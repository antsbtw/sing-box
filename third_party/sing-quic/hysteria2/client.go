package hysteria2

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"
)

const defaultHandshakeTimeout = 15 * time.Second

type ClientOptions struct {
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      M.Socksaddr
	ServerPorts        []string
	HopInterval        time.Duration
	HopIntervalMax     time.Duration
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	Password           string
	TLSConfig          aTLS.Config
	QUICOptions        qtls.QUICOptions
	UDPDisabled        bool
	BBRProfile         string
	RealmOptions       *realm.Options
}

type Client struct {
	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddr         M.Socksaddr
	serverPorts        []uint16
	hopInterval        time.Duration
	hopIntervalMax     time.Duration
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	password           string
	tlsConfig          aTLS.Config
	quicConfig         *quic.Config
	udpDisabled        bool
	bbrProfile         congestion_meta2.Profile
	realmOptions       *realm.Options
	controlClient      *realm.ControlClient

	connAccess sync.Mutex
	conn       *clientQUICConnection
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	if options.RealmOptions != nil && len(options.ServerPorts) > 0 {
		return nil, E.New("realm and port hopping are mutually exclusive")
	}
	var controlClient *realm.ControlClient
	if options.RealmOptions != nil {
		var err error
		controlClient, err = realm.NewControlClient(options.RealmOptions.ServerURL, options.RealmOptions.Token, options.RealmOptions.HTTPClient)
		if err != nil {
			return nil, E.Cause(err, "create control client")
		}
	}
	var serverPorts []uint16
	if len(options.ServerPorts) > 0 {
		var err error
		serverPorts, err = hysteria.ParsePorts(options.ServerPorts)
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddr:         options.ServerAddress,
		serverPorts:        serverPorts,
		hopInterval:        options.HopInterval,
		hopIntervalMax:     options.HopIntervalMax,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
		bbrProfile:         bbrProfile,
		realmOptions:       options.RealmOptions,
		controlClient:      controlClient,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := common.ContextWithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	go c.completeOffer(pending, offerCtx)

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	if c.realmOptions != nil {
		return c.offerNewRealm(ctx)
	}
	dialCtx := ctx
	hopCtx := c.ctx
	if hopCtx == nil {
		hopCtx = context.Background()
	}
	firstDial := true
	dialFunc := func(serverAddr M.Socksaddr) (net.PacketConn, error) {
		currentCtx := hopCtx
		if firstDial {
			// The initial socket open belongs to the shared offer. Later port hops
			// belong to the live client connection and must outlive any one caller.
			currentCtx = dialCtx
			firstDial = false
		}
		udpConn, err := c.dialer.DialContext(currentCtx, "udp", serverAddr)
		if err != nil {
			return nil, err
		}
		var packetConn net.PacketConn
		packetConn = bufio.NewUnbindPacketConn(udpConn)
		if c.salamanderPassword != "" {
			packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
		}
		return packetConn, nil
	}
	var (
		packetConn net.PacketConn
		err        error
	)
	if len(c.serverPorts) == 0 {
		packetConn, err = dialFunc(c.serverAddr)
	} else {
		packetConn, err = hysteria.NewHopPacketConn(dialFunc, c.serverAddr, c.serverPorts, c.hopInterval, c.hopIntervalMax)
	}
	if err != nil {
		return nil, err
	}
	return c.authenticateAndWrap(ctx, packetConn, c.serverAddr)
}

type realmFamilyConn struct {
	family         string
	conn           net.PacketConn
	localAddresses []netip.AddrPort
}

func (c *Client) offerNewRealm(ctx context.Context) (*clientQUICConnection, error) {
	// probe 分支埋点：记录 realm 连接七阶段。退出时统一输出一行结构化 JSON，
	// 供 prober 从 stderr 解析。生产分支无此调用。
	trace := realm.NewTrace(c.realmOptions.RealmID, "hysteria2")
	defer c.emitProbeTrace(trace)

	families, err := c.realmOpenFamilies(ctx)
	if err != nil {
		trace.Fail(realm.FailStageSTUN, err)
		return nil, err
	}
	surviving, localAddresses, stunServers, err := c.realmDiscoverFamilies(ctx, families)
	if err != nil {
		trace.Fail(realm.FailStageSTUN, err)
		return nil, err
	}
	trace.STUNDone(localAddresses, stunServers)
	closeSurviving := func() {
		for _, family := range surviving {
			_ = family.conn.Close()
		}
	}
	localMetadata, err := realm.GeneratePunchMetadata()
	if err != nil {
		closeSurviving()
		trace.Fail(realm.FailStageRendezvous, err)
		return nil, E.Cause(err, "generate punch metadata")
	}
	response, err := c.controlClient.Connect(ctx, c.realmOptions.RealmID, localAddresses, localMetadata)
	if err != nil {
		closeSurviving()
		trace.Fail(realm.FailStageRendezvous, err)
		return nil, E.Cause(err, "realm connect")
	}
	trace.RendezvousDone(response.Addresses)
	winner, result, err := c.realmRacePunch(ctx, surviving, response.Addresses, response.PunchMetadata, trace)
	if err != nil {
		// 候选为空与打洞超时是两类问题，必须分开归因。
		stage := realm.FailStagePunch
		if strings.Contains(err.Error(), "no compatible peer addresses") {
			stage = realm.FailStageCandidate
		}
		trace.Fail(stage, err)
		return nil, err
	}
	trace.PunchDone(result, winner.family, "")
	packetConn := winner.conn
	if c.salamanderPassword != "" {
		packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
	}
	peerAddr := M.SocksaddrFromNetIP(result.PeerAddr)
	conn, err := c.authenticateAndWrap(ctx, packetConn, peerAddr)
	if err != nil {
		trace.Fail(realm.FailStageHandshake, err)
		return nil, err
	}
	trace.HandshakeDone()
	return conn, nil
}

// mode（punch vs direct）是【节点侧】配置（realm.Options.DirectAddresses 只在
// server 端设置），客户端无从直接得知。故 mode 不在内核埋点里编造，
// 由 prober 依据被测节点的已知配置在上报时填入。
// 客户端能提供的对照证据是 peer_addr_matched：direct 模式下它等于节点的固定
// 公网地址，打洞模式下通常是 NAT 映射地址。

// emitProbeTrace 把埋点以单行 JSON 输出，前缀固定便于 prober 精确提取。
//
// 🔴 注意 tunnel_established 不等于 ok。内核只能证明隧道建起来了；
// 是否真的可用由 prober 经隧道做真实往返（HTTP 204）判定。
func (c *Client) emitProbeTrace(trace *realm.Trace) {
	if c.logger == nil || trace == nil {
		return
	}
	encoded, err := json.Marshal(trace)
	if err != nil {
		return
	}
	c.logger.Info(realm.ProbeTraceLogPrefix, string(encoded))
}

func (c *Client) realmOpenFamilies(ctx context.Context) ([]*realmFamilyConn, error) {
	specs := []struct {
		family string
		addr   M.Socksaddr
	}{
		{"v4", M.SocksaddrFrom(netip.IPv4Unspecified(), 0)},
		{"v6", M.SocksaddrFrom(netip.IPv6Unspecified(), 0)},
	}
	conns := make([]*realmFamilyConn, len(specs))
	listenErrs := make([]error, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, listenErr := c.dialer.ListenPacket(ctx, spec.addr)
			if listenErr != nil {
				listenErrs[i] = E.Cause(listenErr, spec.family)
				return
			}
			conns[i] = &realmFamilyConn{family: spec.family, conn: conn}
		}()
	}
	wg.Wait()
	var families []*realmFamilyConn
	var errs []error
	for i, family := range conns {
		if family != nil {
			families = append(families, family)
			continue
		}
		errs = append(errs, listenErrs[i])
	}
	if len(families) == 0 {
		return nil, E.Cause(E.Errors(errs...), "listen UDP for realm")
	}
	return families, nil
}

// realmDiscoverFamilies 额外返回实际响应的 STUN 服务器（埋点用，供 STUN 选点优化）。
func (c *Client) realmDiscoverFamilies(ctx context.Context, families []*realmFamilyConn) ([]*realmFamilyConn, []netip.AddrPort, []string, error) {
	type discoverResult struct {
		addrs   []netip.AddrPort
		servers []string
		err     error
	}
	results := make([]discoverResult, len(families))
	var wg sync.WaitGroup
	for i, family := range families {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, servers, discoverErr := realm.DiscoverTraced(ctx, family.conn, c.realmOptions.STUNServers, c.realmOptions.Resolver)
			results[i] = discoverResult{addrs: addrs, servers: servers, err: discoverErr}
		}()
	}
	wg.Wait()
	var surviving []*realmFamilyConn
	var union []netip.AddrPort
	var stunServers []string
	seenServer := make(map[string]bool)
	var errs []error
	for i, family := range families {
		result := results[i]
		if result.err != nil {
			errs = append(errs, E.Cause(result.err, family.family))
			_ = family.conn.Close()
			continue
		}
		family.localAddresses = result.addrs
		surviving = append(surviving, family)
		union = append(union, result.addrs...)
		for _, server := range result.servers {
			if !seenServer[server] {
				seenServer[server] = true
				stunServers = append(stunServers, server)
			}
		}
	}
	if len(surviving) == 0 {
		return nil, nil, nil, E.Cause(E.Errors(errs...), "realm STUN discovery")
	}
	return surviving, union, stunServers, nil
}

func (c *Client) realmRacePunch(
	ctx context.Context,
	families []*realmFamilyConn,
	peerAddresses []netip.AddrPort,
	metadata realm.PunchMetadata,
	trace *realm.Trace,
) (*realmFamilyConn, realm.PunchResult, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	type outcome struct {
		family *realmFamilyConn
		result realm.PunchResult
		err    error
	}
	out := make(chan outcome, len(families))
	for _, family := range families {
		go func() {
			punchResult, punchErr := realm.PunchTraced(raceCtx, family.conn, family.localAddresses, peerAddresses, metadata, trace)
			out <- outcome{family: family, result: punchResult, err: punchErr}
		}()
	}
	var errs []error
	for pending := len(families); pending > 0; pending-- {
		result := <-out
		if result.err == nil {
			for _, family := range families {
				if family != result.family {
					_ = family.conn.Close()
				}
			}
			return result.family, result.result, nil
		}
		errs = append(errs, E.Cause(result.err, result.family.family))
	}
	for _, family := range families {
		_ = family.conn.Close()
	}
	return nil, realm.PunchResult{}, E.Cause(E.Errors(errs...), "realm punch")
}

func (c *Client) authenticateAndWrap(ctx context.Context, packetConn net.PacketConn, peerAddr M.Socksaddr) (*clientQUICConnection, error) {
	var quicConn *quic.Conn
	http3Transport, err := qtls.CreateTransport(packetConn, &quicConn, peerAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password, Rx: c.receiveBPS})
	handshakeTimeout := c.tlsConfig.HandshakeTimeout()
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	authCtx, authCancel := context.WithTimeout(ctx, handshakeTimeout)
	defer authCancel()
	response, err := http3Transport.RoundTrip(request.WithContext(authCtx))
	if err != nil {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		packetConn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != protocol.StatusAuthOK {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		packetConn.Close()
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, c.brutalDebug, c.logger))
	} else {
		timeFunc := ntp.TimeFuncFromContext(c.ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
			congestion_meta2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(quicConn.Config().InitialPacketSize),
			c.bbrProfile,
		))
	}
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     packetConn,
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
		udpConnMap:  make(map[uint32]*udpPacketConn),
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpDisabled  bool
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, qtls.WrapError(err)
	}
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, qtls.WrapError(err)
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
