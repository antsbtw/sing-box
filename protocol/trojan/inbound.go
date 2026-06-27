package trojan

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TrojanInboundOptions](registry, C.TypeTrojan, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router                   adapter.ConnectionRouterEx
	logger                   log.ContextLogger
	listener                 *listener.Listener
	service                  *trojan.Service[int]
	users                    []option.TrojanUser
	// userNameList is indexed by the int user value the trojan service assigns at
	// auth time (carried through ctx to newConnection). Read on every routed
	// connection and swapped wholesale by UpdateUsers (hot reload), so held in an
	// atomic.Pointer to stay race-free. Index assignments are STABLE across
	// reloads (see updateAccess / nameToIndex) so billing never gets
	// misattributed when the user set changes under a live connection.
	userNameList atomic.Pointer[[]string]
	// updateAccess serialises UpdateUsers and guards nameToIndex. Read path does
	// not take this lock.
	updateAccess             sync.Mutex
	nameToIndex              map[string]int
	tlsConfig                tls.ServerConfig
	fallbackAddr             M.Socksaddr
	fallbackAddrTLSNextProto map[string]M.Socksaddr
	transport                adapter.V2RayServerTransport
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeTrojan, tag),
		router:  router,
		logger:  logger,
		users:   options.Users,
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled,
		})
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	var fallbackHandler N.TCPConnectionHandlerEx
	if options.Fallback != nil && options.Fallback.Server != "" || len(options.FallbackForALPN) > 0 {
		if options.Fallback != nil && options.Fallback.Server != "" {
			inbound.fallbackAddr = options.Fallback.Build()
			if !inbound.fallbackAddr.IsValid() {
				return nil, E.New("invalid fallback address: ", inbound.fallbackAddr)
			}
		}
		if len(options.FallbackForALPN) > 0 {
			if inbound.tlsConfig == nil {
				return nil, E.New("fallback for ALPN is not supported without TLS")
			}
			fallbackAddrNextProto := make(map[string]M.Socksaddr)
			for nextProto, destination := range options.FallbackForALPN {
				fallbackAddr := destination.Build()
				if !fallbackAddr.IsValid() {
					return nil, E.New("invalid fallback address for ALPN ", nextProto, ": ", fallbackAddr)
				}
				fallbackAddrNextProto[nextProto] = fallbackAddr
			}
			inbound.fallbackAddrTLSNextProto = fallbackAddrNextProto
		}
		fallbackHandler = adapter.NewUpstreamContextHandler(inbound.fallbackConnection, nil)
	}
	service := trojan.NewService[int](adapter.NewUpstreamContextHandler(inbound.newConnection, inbound.newPacketConnection), fallbackHandler, logger)
	inbound.service = service
	inbound.nameToIndex = make(map[string]int)
	emptyList := make([]string, 0)
	inbound.userNameList.Store(&emptyList)
	// Initial users go through the same stable-index path as hot reload so the
	// service, nameToIndex and userNameList all stay consistent from the start.
	err := inbound.UpdateUsers(
		common.Map(options.Users, func(it option.TrojanUser) string { return it.Name }),
		common.Map(options.Users, func(it option.TrojanUser) string { return it.Password }),
	)
	if err != nil {
		return nil, err
	}
	if options.Transport != nil {
		inbound.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), inbound.tlsConfig, (*inboundTransportHandler)(inbound))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	if h.transport == nil {
		return h.listener.Start()
	}
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.Serve(tcpListener)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	if common.Contains(h.transport.Network(), N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.ServePacket(udpConn)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	return nil
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		h.transport,
	)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil && h.transport == nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.userNameByIndex(userIndex)
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := h.userNameByIndex(userIndex)
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// userNameByIndex resolves the billing/display name for the int user value the
// trojan service assigned at auth time. Race-free via the atomic snapshot.
func (h *Inbound) userNameByIndex(userIndex int) string {
	nameList := *h.userNameList.Load()
	if userIndex < 0 || userIndex >= len(nameList) {
		return ""
	}
	return nameList[userIndex]
}

// UpdateUsers hot-reloads the full trojan user set (full-set / idempotent) without
// dropping existing connections. names[i] is the user name (billing/display, =UUID
// for otun) and passwords[i] the trojan password. Index assignments stay stable
// across reloads so live connections keep resolving to the right name.
func (h *Inbound) UpdateUsers(names []string, passwords []string) error {
	if len(names) != len(passwords) {
		return E.New("trojan: user name/password count mismatch")
	}
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()

	// trojan auth is by password only; name is for billing/display and may be
	// empty in upstream configs. Use a stable key per user: the name when set,
	// else fall back to the password (always unique within a config).
	keys := make([]string, len(names))
	for i := range names {
		if names[i] != "" {
			keys[i] = names[i]
		} else {
			keys[i] = passwords[i]
		}
	}

	userList, passwordList, nameList := assignStableIndices(h.nameToIndex, keys, passwords, names)
	if err := h.service.UpdateUsers(userList, passwordList); err != nil {
		return err
	}
	h.userNameList.Store(&nameList)
	return nil
}

// assignStableIndices keeps each user's int index stable across hot reloads.
// stableKeys[i] identifies user i (name, or password if name empty); displayNames[i]
// is what ends up in nameList (the billing/display name, may be empty).
func assignStableIndices(nameToIndex map[string]int, stableKeys []string, passwords []string, displayNames []string) (userList []int, passwordList []string, nameList []string) {
	newKeySet := make(map[string]struct{}, len(stableKeys))
	for _, k := range stableKeys {
		newKeySet[k] = struct{}{}
	}
	// Drop stale key->index assignments so slots can be reused; find high-water mark.
	maxIndex := -1
	for key, index := range nameToIndex {
		if _, keep := newKeySet[key]; !keep {
			delete(nameToIndex, key)
			continue
		}
		if index > maxIndex {
			maxIndex = index
		}
	}
	used := make(map[int]struct{}, len(nameToIndex))
	for _, index := range nameToIndex {
		used[index] = struct{}{}
	}
	freeSlots := make([]int, 0)
	for i := 0; i <= maxIndex; i++ {
		if _, taken := used[i]; !taken {
			freeSlots = append(freeSlots, i)
		}
	}
	nextIndex := maxIndex + 1
	passwordByKey := make(map[string]string, len(stableKeys))
	nameByKey := make(map[string]string, len(stableKeys))
	for i, key := range stableKeys {
		passwordByKey[key] = passwords[i]
		nameByKey[key] = displayNames[i]
		if _, ok := nameToIndex[key]; ok {
			continue
		}
		if len(freeSlots) > 0 {
			nameToIndex[key] = freeSlots[0]
			freeSlots = freeSlots[1:]
		} else {
			nameToIndex[key] = nextIndex
			nextIndex++
		}
	}
	size := 0
	for _, index := range nameToIndex {
		if index+1 > size {
			size = index + 1
		}
	}
	userList = make([]int, 0, len(nameToIndex))
	passwordList = make([]string, 0, len(nameToIndex))
	nameList = make([]string, size)
	for key, index := range nameToIndex {
		userList = append(userList, index)
		passwordList = append(passwordList, passwordByKey[key])
		nameList[index] = nameByKey[key]
	}
	return userList, passwordList, nameList
}

func (h *Inbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var fallbackAddr M.Socksaddr
	if len(h.fallbackAddrTLSNextProto) > 0 {
		if tlsConn, loaded := common.Cast[tls.Conn](conn); loaded {
			connectionState := tlsConn.ConnectionState()
			if connectionState.NegotiatedProtocol != "" {
				if fallbackAddr, loaded = h.fallbackAddrTLSNextProto[connectionState.NegotiatedProtocol]; !loaded {
					h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled for ALPN: ", connectionState.NegotiatedProtocol)
					N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
					return
				}
			}
		}
	}
	if !fallbackAddr.IsValid() {
		if !h.fallbackAddr.IsValid() {
			h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled by default")
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		fallbackAddr = h.fallbackAddr
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = fallbackAddr
	h.logger.InfoContext(ctx, "fallback connection to ", fallbackAddr)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

var _ adapter.V2RayServerTransportHandler = (*inboundTransportHandler)(nil)

type inboundTransportHandler Inbound

func (h *inboundTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	(*Inbound)(h).NewConnection(ctx, conn, metadata, onClose)
}
