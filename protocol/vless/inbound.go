package vless

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
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.VLESSInboundOptions](registry, C.TypeVLESS, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	// users is the index-keyed user table, read on every routed connection via
	// the int user value the vless service assigns at auth time and carries
	// through to newConnectionEx in the context. It is swapped wholesale by
	// UpdateUsers (runtime hot reload), so it is held in an atomic.Pointer to
	// stay race-free with the read path. Index assignments are STABLE across hot
	// reloads (see assignStableVLESSIndices / userToIndex) so a connection
	// authenticated under an old user set always resolves to the same user ->
	// per-user v2ray_api billing is never misattributed when the set changes
	// under a live connection.
	users atomic.Pointer[[]option.VLESSUser]
	// updateAccess serialises UpdateUsers calls and guards the stable
	// userToIndex bookkeeping below. The read path does not take this lock.
	updateAccess sync.Mutex
	userToIndex  map[string]int
	// flow is the inbound-wide VLESS flow (xtls-rprx-vision or "") captured at
	// construction. The hot-reload endpoint signature is binary (uuids, uuids)
	// and cannot carry per-user flow; flow is uniform per inbound across the
	// fleet (manager hardcodes xtls-rprx-vision), so new hot-added users inherit
	// this flow. See WP-A difficulty 1 route (a).
	flow      string
	service   *vless.Service[int]
	tlsConfig tls.ServerConfig
	transport adapter.V2RayServerTransport
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeVLESS, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}
	// Capture the inbound-wide flow for hot-added users. The fleet uses a uniform
	// flow per VLESS inbound (xtls-rprx-vision everywhere, manager hardcoded), so
	// the first configured user's flow defines it; absent users it stays "".
	if len(options.Users) > 0 {
		inbound.flow = options.Users[0].Flow
	}
	inbound.userToIndex = make(map[string]int)
	emptyUsers := []option.VLESSUser{}
	inbound.users.Store(&emptyUsers)
	var err error
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	service := vless.NewService[int](logger, adapter.NewUpstreamContextHandler(inbound.newConnectionEx, inbound.newPacketConnectionEx))
	inbound.service = service
	// Seed the user table through the same hot-reload path used at runtime, so the
	// stable-index bookkeeping is established identically on first load and on
	// every subsequent update.
	uuids := common.Map(options.Users, func(it option.VLESSUser) string {
		return it.UUID
	})
	if err = inbound.updateUsersWithFlow(uuids, uuids, common.Map(options.Users, func(it option.VLESSUser) string {
		return it.Flow
	})); err != nil {
		return nil, err
	}
	if options.TLS != nil {
		inbound.tlsConfig, err = tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled &&
				common.All(options.Users, func(it option.VLESSUser) bool {
					return it.Flow == ""
				}),
		})
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

// UpdateUsers replaces the full set of VLESS users at runtime without disturbing
// established connections. It is the hot-reload path invoked by the loopback
// hotreload server: pass the COMPLETE list of users that should currently be
// online (full-set / idempotent semantics, not incremental add/remove).
//
// The signature matches the hotreload server's userUpdater interface
// (UpdateUsers(names, passwords []string)); for VLESS, names[i]==passwords[i]==
// the user UUID (the manager writes name=uuid for every VLESS user, and the UUID
// is also used as the v2ray_api billing key via metadata.User). flow is not in
// the signature because it is uniform per inbound across the fleet; hot-added
// users inherit the inbound flow captured at construction (h.flow). len(names)
// must equal len(passwords).
//
// Index assignment is STABLE across calls (see assignStableVLESSIndices): a UUID
// already present keeps its previously assigned int index. The vless service's
// userMap/userFlow are swapped wholesale; live connections cache their
// authenticated int user value and never re-read the map, so they are
// unaffected — only new handshakes see the new set. The index-keyed h.users
// table is swapped via an atomic.Pointer so newConnectionEx never reads a torn
// slice.
func (h *Inbound) UpdateUsers(names []string, passwords []string) error {
	flowList := make([]string, len(names))
	for i := range flowList {
		flowList[i] = h.flow
	}
	return h.updateUsersWithFlow(names, passwords, flowList)
}

// updateUsersWithFlow is the shared implementation behind both the constructor
// seed and the runtime UpdateUsers call. names[i] is the user name (=UUID),
// uuidList[i] the auth UUID, flowList[i] the per-user flow. All three slices
// must be equal length.
func (h *Inbound) updateUsersWithFlow(names []string, uuidList []string, flowList []string) error {
	if len(names) != len(uuidList) || len(names) != len(flowList) {
		return E.New("vless: user name/uuid/flow count mismatch")
	}
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()

	indexList, uuidByIndex, flowByIndex, userTable := assignStableVLESSIndices(h.userToIndex, names, uuidList, flowList)
	// indexList / uuidByIndex / flowByIndex are parallel and indexed the same way
	// as the construction-time call (service.UpdateUsers(indices, uuids, flows)),
	// so the service assigns each connection the int slot we use to key h.users.
	h.service.UpdateUsers(indexList, uuidByIndex, flowByIndex)
	h.users.Store(&userTable)
	return nil
}

// assignStableVLESSIndices mutates userToIndex in place to reflect the full set
// of (names, uuids, flows) while keeping already-present users at their existing
// index, mirroring the hysteria2 stable-index scheme. It returns the parallel
// (indexList, uuidByIndex, flowByIndex) consumed by vless.Service.UpdateUsers
// plus an index-keyed userTable for the read path (newConnectionEx). Keeping
// existing indices stable is what makes per-user billing safe across a hot
// update: a live connection's captured index always maps back to the same user.
// Pulled out as a pure function so the invariant can be unit-tested without a
// live vless service. Users are keyed by UUID (the manager guarantees name==uuid
// and uuids are unique within an inbound).
func assignStableVLESSIndices(userToIndex map[string]int, names []string, uuids []string, flows []string) (indexList []int, uuidByIndex []string, flowByIndex []string, userTable []option.VLESSUser) {
	newKeySet := make(map[string]struct{}, len(uuids))
	for _, uuid := range uuids {
		newKeySet[uuid] = struct{}{}
	}
	// Drop stale uuid->index assignments so their slots can be reused, and find
	// the current high-water mark of live indices.
	maxIndex := -1
	for uuid, index := range userToIndex {
		if _, keep := newKeySet[uuid]; !keep {
			delete(userToIndex, uuid)
			continue
		}
		if index > maxIndex {
			maxIndex = index
		}
	}
	used := make(map[int]struct{}, len(userToIndex))
	for _, index := range userToIndex {
		used[index] = struct{}{}
	}
	freeSlots := make([]int, 0)
	for i := 0; i <= maxIndex; i++ {
		if _, taken := used[i]; !taken {
			freeSlots = append(freeSlots, i)
		}
	}
	// Assign indices: keep existing stable, give new uuids a reused or new slot.
	// On duplicate uuids within one push, only the first occurrence assigns a
	// slot; later duplicates resolve to the same index (full-set is deduplicated
	// upstream, but we stay defensive).
	nextIndex := maxIndex + 1
	type userData struct {
		name string
		flow string
	}
	dataByUUID := make(map[string]userData, len(uuids))
	for i, uuid := range uuids {
		dataByUUID[uuid] = userData{name: names[i], flow: flows[i]}
		if _, ok := userToIndex[uuid]; ok {
			continue
		}
		if len(freeSlots) > 0 {
			userToIndex[uuid] = freeSlots[0]
			freeSlots = freeSlots[1:]
		} else {
			userToIndex[uuid] = nextIndex
			nextIndex++
		}
	}
	// Build dense index-keyed slices sized to the highest assigned index.
	size := 0
	for _, index := range userToIndex {
		if index+1 > size {
			size = index + 1
		}
	}
	indexList = make([]int, 0, len(userToIndex))
	uuidByIndex = make([]string, 0, len(userToIndex))
	flowByIndex = make([]string, 0, len(userToIndex))
	userTable = make([]option.VLESSUser, size)
	for uuid, index := range userToIndex {
		data := dataByUUID[uuid]
		// indexList[i]/uuidByIndex[i]/flowByIndex[i] are appended together so they
		// stay parallel; vless.Service builds userMap[uuid]=index and
		// userFlow[index]=flow from this triple.
		indexList = append(indexList, index)
		uuidByIndex = append(uuidByIndex, uuid)
		flowByIndex = append(flowByIndex, data.flow)
		userTable[index] = option.VLESSUser{Name: data.name, UUID: uuid, Flow: data.flow}
	}
	return indexList, uuidByIndex, flowByIndex, userTable
}

// userByIndex resolves the int user value assigned by the vless service to its
// option.VLESSUser via the current (atomically loaded) index-keyed table. A live
// connection may hold an index whose slot was freed by a concurrent UpdateUsers;
// the bounds/empty check returns ok=false in that case rather than panicking,
// and the caller logs/bills without a user name.
func (h *Inbound) userByIndex(index int) (option.VLESSUser, bool) {
	userTable := *h.users.Load()
	if index < 0 || index >= len(userTable) {
		return option.VLESSUser{}, false
	}
	user := userTable[index]
	if user.UUID == "" {
		return option.VLESSUser{}, false
	}
	return user, true
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
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
	var user string
	if u, ok := h.userByIndex(userIndex); ok && u.Name != "" {
		user = u.Name
		metadata.User = user
	} else {
		user = F.ToString(userIndex)
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
	var user string
	if u, ok := h.userByIndex(userIndex); ok && u.Name != "" {
		user = u.Name
		metadata.User = user
	} else {
		user = F.ToString(userIndex)
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
