package hysteria2

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.Hysteria2InboundOptions](registry, C.TypeHysteria2, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router    adapter.Router
	logger    log.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	service   *hysteria2.Service[int]
	// userNameList is indexed by the int user value (U) that the hysteria2
	// service assigns at auth time and carries through to NewConnectionEx via
	// the context. It is read on every routed connection and swapped wholesale
	// by UpdateUsers (runtime hot reload), so it is held in an atomic.Pointer to
	// stay race-free. Index assignments are STABLE across hot reloads (see
	// updateAccess / nameToIndex) so a connection authenticated under an old
	// user set always resolves to the same name -> billing never gets
	// misattributed when the set changes underneath a live connection.
	userNameList atomic.Pointer[[]string]
	// updateAccess serialises UpdateUsers calls and guards the stable
	// name->index bookkeeping below. The read path does not take this lock.
	updateAccess sync.Mutex
	nameToIndex  map[string]int
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2InboundOptions) (adapter.Inbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	var salamanderPassword string
	if options.Obfs != nil {
		if options.Obfs.Password == "" {
			return nil, E.New("missing obfs password")
		}
		switch options.Obfs.Type {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = options.Obfs.Password
		default:
			return nil, E.New("unknown obfs type: ", options.Obfs.Type)
		}
	}
	var masqueradeHandler http.Handler
	if options.Masquerade != nil && options.Masquerade.Type != "" {
		switch options.Masquerade.Type {
		case C.Hysterai2MasqueradeTypeFile:
			masqueradeHandler = http.FileServer(http.Dir(options.Masquerade.FileOptions.Directory))
		case C.Hysterai2MasqueradeTypeProxy:
			masqueradeURL, err := url.Parse(options.Masquerade.ProxyOptions.URL)
			if err != nil {
				return nil, E.Cause(err, "parse masquerade URL")
			}
			masqueradeHandler = &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(masqueradeURL)
					if !options.Masquerade.ProxyOptions.RewriteHost {
						r.Out.Host = r.In.Host
					}
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusBadGateway)
				},
			}
		case C.Hysterai2MasqueradeTypeString:
			masqueradeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if options.Masquerade.StringOptions.StatusCode != 0 {
					w.WriteHeader(options.Masquerade.StringOptions.StatusCode)
				}
				for key, values := range options.Masquerade.StringOptions.Headers {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.Write([]byte(options.Masquerade.StringOptions.Content))
			})
		default:
			return nil, E.New("unknown masquerade type: ", options.Masquerade.Type)
		}
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeHysteria2, tag),
		router:  router,
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		tlsConfig: tlsConfig,
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	var realmOptions *realm.Options
	if options.Realm != nil {
		queryOptions, err := adapter.DNSQueryOptionsFrom(ctx, options.Realm.STUNDomainResolver)
		if err != nil {
			return nil, err
		}
		httpClientTransport, err := service.FromContext[adapter.HTTPClientManager](ctx).ResolveTransport(ctx, logger, common.PtrValueOrDefault(options.Realm.HTTPClient))
		if err != nil {
			return nil, E.Cause(err, "create realm http client")
		}
		dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
		realmOptions = &realm.Options{
			ServerURL:   options.Realm.ServerURL,
			Token:       options.Realm.Token,
			RealmID:     options.Realm.RealmID,
			STUNServers: options.Realm.STUNServers,
			HTTPClient:  &http.Client{Transport: httpClientTransport},
			Resolver: func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
				dnsOptions := queryOptions
				switch {
				case ipv4 && !ipv6:
					dnsOptions.Strategy = C.DomainStrategyIPv4Only
				case !ipv4 && ipv6:
					dnsOptions.Strategy = C.DomainStrategyIPv6Only
				}
				return dnsRouter.Lookup(ctx, host, dnsOptions)
			},
			Logger: logger,
		}
	}
	hysteriaService, err := hysteria2.NewService[int](hysteria2.ServiceOptions{
		Context:            ctx,
		Logger:             logger,
		BrutalDebug:        options.BrutalDebug,
		SendBPS:            uint64(options.UpMbps * hysteria.MbpsToBps),
		ReceiveBPS:         uint64(options.DownMbps * hysteria.MbpsToBps),
		SalamanderPassword: salamanderPassword,
		TLSConfig:          tlsConfig,
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       options.InitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		IgnoreClientBandwidth: options.IgnoreClientBandwidth,
		UDPTimeout:            udpTimeout,
		Handler:               inbound,
		MasqueradeHandler:     masqueradeHandler,
		BBRProfile:            options.BBRProfile,
		RealmOptions:          realmOptions,
	})
	if err != nil {
		return nil, err
	}
	inbound.service = hysteriaService
	inbound.nameToIndex = make(map[string]int)
	emptyList := []string{}
	inbound.userNameList.Store(&emptyList)
	names := make([]string, 0, len(options.Users))
	passwords := make([]string, 0, len(options.Users))
	for _, user := range options.Users {
		names = append(names, user.Name)
		passwords = append(passwords, user.Password)
	}
	if err := inbound.UpdateUsers(names, passwords); err != nil {
		return nil, err
	}
	return inbound, nil
}

// UpdateUsers replaces the full set of hysteria2 users at runtime without
// disturbing established connections. It is the hot-reload path: pass the
// COMPLETE list of users that should currently be online (full-set / idempotent
// semantics, not an incremental add/remove). names[i] is the user name
// (=UUID, used for per-user v2ray_api billing) and passwords[i] the auth
// password (also the UUID for realm). len(names) must equal len(passwords).
//
// Index assignment is STABLE across calls: a name that was already present
// keeps its previously assigned int index, new names take fresh indices
// (reusing slots freed by removed names, else appending). This guarantees that
// a connection authenticated before the update — whose int user value is
// already captured in its QUIC session — always resolves to the same name in
// NewConnectionEx, so billing is never misattributed when the user set changes
// under a live connection. The underlying sing-quic service swaps its auth map
// atomically (see hysteria2.Service.UpdateUsers), so live sessions, which cache
// their authenticated user and never re-read the map, are unaffected; only new
// handshakes see the new set.
func (h *Inbound) UpdateUsers(names []string, passwords []string) error {
	if len(names) != len(passwords) {
		return E.New("hysteria2: user name/password count mismatch")
	}
	h.updateAccess.Lock()
	defer h.updateAccess.Unlock()

	userList, passwordList, nameList := assignStableIndices(h.nameToIndex, names, passwords)
	h.service.UpdateUsers(userList, passwordList)
	h.userNameList.Store(&nameList)
	return nil
}

// assignStableIndices mutates nameToIndex in place to reflect the full set of
// (names, passwords) while keeping already-present names at their existing
// index, and returns the parallel (userList, passwordList) for the sing-quic
// service plus the index-keyed nameList for the read path. New names reuse
// indices freed by removed names before extending past the high-water mark, so
// indices stay dense and bounded. Keeping existing indices stable is what makes
// per-user billing safe across a hot update: a live connection's captured index
// always maps back to the same name. Pulled out as a pure function so the
// stable-index invariant can be unit-tested without a live QUIC service.
func assignStableIndices(nameToIndex map[string]int, names []string, passwords []string) (userList []int, passwordList []string, nameList []string) {
	newNameSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		newNameSet[name] = struct{}{}
	}
	// Drop stale name->index assignments so their slots can be reused, and find
	// the current high-water mark of live indices.
	maxIndex := -1
	for name, index := range nameToIndex {
		if _, keep := newNameSet[name]; !keep {
			delete(nameToIndex, name)
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
	// Assign indices: keep existing ones stable, give new names a reused or new slot.
	nextIndex := maxIndex + 1
	passwordByName := make(map[string]string, len(names))
	for i, name := range names {
		passwordByName[name] = passwords[i]
		if _, ok := nameToIndex[name]; ok {
			continue
		}
		if len(freeSlots) > 0 {
			nameToIndex[name] = freeSlots[0]
			freeSlots = freeSlots[1:]
		} else {
			nameToIndex[name] = nextIndex
			nextIndex++
		}
	}
	// Build dense index-keyed slices sized to the highest assigned index.
	size := 0
	for _, index := range nameToIndex {
		if index+1 > size {
			size = index + 1
		}
	}
	// userList[i] and passwordList[i] are appended together, so they stay
	// parallel; sing-quic builds its password->user(index) map from this pair.
	// nameList is keyed by index for the read path (NewConnectionEx).
	userList = make([]int, 0, len(nameToIndex))
	passwordList = make([]string, 0, len(nameToIndex))
	nameList = make([]string, size)
	for name, index := range nameToIndex {
		userList = append(userList, index)
		passwordList = append(passwordList, passwordByName[name])
		nameList[index] = name
	}
	return userList, passwordList, nameList
}

// userName resolves a user's int index to its name via the current (atomically
// loaded) name list. A live connection may hold an index whose slot was freed
// by a concurrent UpdateUsers; the bounds check returns "" in that case (the
// caller then logs/bills without a user name) rather than panicking.
func (h *Inbound) userName(index int) string {
	nameList := *h.userNameList.Load()
	if index < 0 || index >= len(nameList) {
		return ""
	}
	return nameList[index]
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[int](ctx)
	if userName := h.userName(userID); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	userID, _ := auth.UserFromContext[int](ctx)
	if userName := h.userName(userID); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
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
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	return h.service.Start(packetConn)
}

func (h *Inbound) InterfaceUpdated() {
	h.service.Reset()
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
		common.PtrOrNil(h.service),
	)
}
