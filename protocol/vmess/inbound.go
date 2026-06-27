package vmess

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
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.VMessInboundOptions](registry, C.TypeVMess, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	ctx       context.Context
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	service   *vmess.Service[int]
	users     []option.VMessUser
	// userNameList / updateAccess / nameToIndex: same stable-index hot-reload
	// machinery as the trojan/hysteria2 inbounds. userNameList is read on every
	// routed connection (billing/display) and swapped atomically by UpdateUsers;
	// index assignments stay stable across reloads. Read path takes no lock.
	userNameList atomic.Pointer[[]string]
	updateAccess sync.Mutex
	nameToIndex  map[string]int
	tlsConfig    tls.ServerConfig
	transport    adapter.V2RayServerTransport
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VMessInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeVMess, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		users:   options.Users,
	}
	var err error
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	var serviceOptions []vmess.ServiceOption
	if timeFunc := ntp.TimeFuncFromContext(ctx); timeFunc != nil {
		serviceOptions = append(serviceOptions, vmess.ServiceWithTimeFunc(timeFunc))
	}
	if options.Transport != nil && options.Transport.Type != "" {
		serviceOptions = append(serviceOptions, vmess.ServiceWithDisableHeaderProtection())
	}
	service := vmess.NewService[int](adapter.NewUpstreamContextHandler(inbound.newConnectionEx, inbound.newPacketConnectionEx), serviceOptions...)
	inbound.service = service
	inbound.nameToIndex = make(map[string]int)
	emptyList := make([]string, 0)
	inbound.userNameList.Store(&emptyList)
	// Initial users go through the same stable-index path as hot reload
	// (preserve configured alterId for initial construction).
	err = inbound.UpdateUsersWithAlterId(
		common.Map(options.Users, func(it option.VMessUser) string { return it.Name }),
		common.Map(options.Users, func(it option.VMessUser) string { return it.UUID }),
		common.Map(options.Users, func(it option.VMessUser) int { return it.AlterId }),
	)
	if err != nil {
		return nil, err
	}
	if options.TLS != nil {
		inbound.tlsConfig, err = tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		inbound.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), inbound.tlsConfig, (*inboundTransportHandler)(inbound))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
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
	err := h.service.Start()
	if err != nil {
		return err
	}
	if h.tlsConfig != nil {
		err = h.tlsConfig.Start()
		if err != nil {
			return err
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
		h.service,
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

func (h *Inbound) newConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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

func (h *Inbound) newPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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
	if metadata.Destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		metadata.Destination = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), metadata.Destination)
		h.logger.InfoContext(ctx, "[", user, "] inbound packet addr connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

// userNameByIndex resolves the billing/display name for the int user value the
// vmess service assigned at auth time. Race-free via the atomic snapshot.
func (h *Inbound) userNameByIndex(userIndex int) string {
	nameList := *h.userNameList.Load()
	if userIndex < 0 || userIndex >= len(nameList) {
		return ""
	}
	return nameList[userIndex]
}

// UpdateUsers hot-reloads the full vmess user set (full-set / idempotent) without
// UpdateUsers matches the hot-reload endpoint's userUpdater interface
// (UpdateUsers(names, passwords)). For vmess the "password" is the UUID and
// alterId is 0 (modern AEAD / otun). Delegates to UpdateUsersWithAlterId.
func (h *Inbound) UpdateUsers(names []string, uuids []string) error {
	alterIds := make([]int, len(uuids))
	return h.UpdateUsersWithAlterId(names, uuids, alterIds)
}

// UpdateUsersWithAlterId hot-reloads the full vmess user set (full-set /
// idempotent) without dropping existing connections. names[i] = billing/display
// name (=UUID for otun), uuids[i] = vmess UUID, alterIds[i] = alterId.
// Index assignments stay stable across reloads so live connections keep their name.
func (h *Inbound) UpdateUsersWithAlterId(names []string, uuids []string, alterIds []int) error {
	if len(names) != len(uuids) || len(names) != len(alterIds) {
		return E.New("vmess: user name/uuid/alterId count mismatch")
	}
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()

	// vmess auth is by UUID; name is for billing/display and may be empty.
	// Stable key per user: name when set, else the UUID (always unique).
	keys := make([]string, len(names))
	for i := range names {
		if names[i] != "" {
			keys[i] = names[i]
		} else {
			keys[i] = uuids[i]
		}
	}

	userList, uuidList, alterIdList, nameList := assignStableIndices(h.nameToIndex, keys, uuids, alterIds, names)
	if err := h.service.UpdateUsers(userList, uuidList, alterIdList); err != nil {
		return err
	}
	h.userNameList.Store(&nameList)
	return nil
}

// assignStableIndices keeps each user's int index stable across hot reloads.
// stableKeys[i] identifies user i; uuids/alterIds carry the auth material;
// displayNames[i] is what ends up in nameList (billing/display, may be empty).
func assignStableIndices(nameToIndex map[string]int, stableKeys, uuids []string, alterIds []int, displayNames []string) (userList []int, uuidList []string, alterIdList []int, nameList []string) {
	newKeySet := make(map[string]struct{}, len(stableKeys))
	for _, k := range stableKeys {
		newKeySet[k] = struct{}{}
	}
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
	uuidByKey := make(map[string]string, len(stableKeys))
	alterByKey := make(map[string]int, len(stableKeys))
	nameByKey := make(map[string]string, len(stableKeys))
	for i, key := range stableKeys {
		uuidByKey[key] = uuids[i]
		alterByKey[key] = alterIds[i]
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
	uuidList = make([]string, 0, len(nameToIndex))
	alterIdList = make([]int, 0, len(nameToIndex))
	nameList = make([]string, size)
	for key, index := range nameToIndex {
		userList = append(userList, index)
		uuidList = append(uuidList, uuidByKey[key])
		alterIdList = append(alterIdList, alterByKey[key])
		nameList[index] = nameByKey[key]
	}
	return userList, uuidList, alterIdList, nameList
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
