// Package hotreload provides a small loopback HTTP control endpoint that pushes
// the full set of hysteria2 users into a running sing-box instance at runtime,
// without a full configuration reload. A reload rebuilds every inbound and tears
// down all live QUIC sessions (an ~8-9s stall for everyone on a realm egress);
// this endpoint instead swaps the inbound's auth map and the v2ray_api billing
// user set atomically, so existing connections are never disturbed and only new
// handshakes observe the new user set.
//
// The endpoint takes a COMPLETE list of users that should currently be online
// (full-set / idempotent semantics, NOT incremental add/remove). It refreshes
// two things in one call:
//
//   - the hysteria2 inbound's users (so a new UUID can authenticate and route),
//   - the v2ray_api StatsService user set (so the new UUID is actually billed;
//     that set is otherwise fixed at construction and a hot-added user would
//     route but never be counted).
//
// It deliberately depends only on small local interfaces (userUpdater /
// userSetUpdater) rather than the protocol/hysteria2 or experimental/v2rayapi
// packages, so it carries no build-tag constraints of its own.
package hotreload

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// userUpdater is implemented by the hysteria2 inbound. names[i] is the user
// name (=UUID, used for v2ray_api billing) and passwords[i] the auth password
// (also the UUID for realm); both slices must be equal length. Full-set.
type userUpdater interface {
	UpdateUsers(names []string, passwords []string) error
}

// userSetUpdater is implemented by the v2ray_api StatsService: it refreshes the
// set of user names eligible for per-user traffic accounting. Full-set.
type userSetUpdater interface {
	UpdateUsers(users []string)
}

// Server is the loopback hot-reload control service. It implements
// adapter.LifecycleService and is wired into the box like the other
// experimental servers.
type Server struct {
	logger         log.ContextLogger
	listen         string
	inboundTags    []string
	inboundManager adapter.InboundManager
	v2rayServer    adapter.V2RayServer // may be nil if v2ray_api is not enabled
	httpServer     *http.Server
	listener       net.Listener
}

// NewServer builds a hot-reload control server bound to options.Listen, targeting
// the inbound(s) identified by options.InboundTag and/or options.InboundTags. The
// inbound manager is required; v2rayServer may be nil (billing sync is then
// skipped). All target inbounds receive the same full user set per call.
func NewServer(logger log.ContextLogger, options option.HotReloadOptions, inboundManager adapter.InboundManager, v2rayServer adapter.V2RayServer) (*Server, error) {
	if options.Listen == "" {
		return nil, E.New("hot_reload: missing listen address")
	}
	// Merge single InboundTag (backward compat) + InboundTags, deduplicated.
	seen := make(map[string]struct{})
	var tags []string
	for _, t := range append([]string{options.InboundTag}, options.InboundTags...) {
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		tags = append(tags, t)
	}
	if len(tags) == 0 {
		return nil, E.New("hot_reload: missing inbound_tag / inbound_tags")
	}
	if inboundManager == nil {
		return nil, E.New("hot_reload: nil inbound manager")
	}
	return &Server{
		logger:         logger,
		listen:         options.Listen,
		inboundTags:    tags,
		inboundManager: inboundManager,
		v2rayServer:    v2rayServer,
	}, nil
}

func (s *Server) Name() string {
	return "hot-reload control"
}

func (s *Server) Start(stage adapter.StartStage) error {
	// PostStart: inbounds and the v2ray server are already constructed and
	// registered in the service context by this point.
	if stage != adapter.StartStatePostStart {
		return nil
	}
	listener, err := net.Listen("tcp", s.listen)
	if err != nil {
		return E.Cause(err, "hot_reload: listen ", s.listen)
	}
	s.listener = listener
	mux := http.NewServeMux()
	mux.HandleFunc("/hotreload/users", s.handleUpdateUsers)
	s.httpServer = &http.Server{Handler: mux}
	s.logger.Info("hot-reload control endpoint started at ", listener.Addr(), " (inbounds ", strings.Join(s.inboundTags, ","), ")")
	go func() {
		err := s.httpServer.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error(E.Cause(err, "hot_reload: serve"))
		}
	}()
	return nil
}

func (s *Server) Close() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

type updateUsersRequest struct {
	Users []struct {
		UUID string `json:"uuid"`
	} `json:"users"`
}

type updateUsersResponse struct {
	OK          bool   `json:"ok"`
	UserCount   int    `json:"user_count"`
	BillingSync bool   `json:"billing_sync"`
	Error       string `json:"error,omitempty"`
}

func (s *Server) handleUpdateUsers(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Error("hot_reload: panic in handler: ", rec, "\n", string(debug.Stack()))
			s.writeError(w, http.StatusInternalServerError, F.ToString("panic: ", rec))
		}
	}()
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req updateUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, E.Cause(err, "decode request").Error())
		return
	}
	// Full-set: name == password == UUID, matching the realm hysteria2 inbound
	// config (and the realm dual-UUID contract). Deduplicate defensively.
	seen := make(map[string]struct{}, len(req.Users))
	uuids := make([]string, 0, len(req.Users))
	for _, u := range req.Users {
		if u.UUID == "" {
			s.writeError(w, http.StatusBadRequest, "empty uuid in users list")
			return
		}
		if _, dup := seen[u.UUID]; dup {
			continue
		}
		seen[u.UUID] = struct{}{}
		uuids = append(uuids, u.UUID)
	}

	// Update every configured inbound with the same full user set. All target
	// inbounds use name==password==UUID semantics (vless / hysteria2). A single
	// inbound failing (not found / wrong type / update error) fails the whole
	// call so the agent falls back to reload — we do not want partial state where
	// one protocol has the new user set and another does not.
	for _, tag := range s.inboundTags {
		inbound, found := s.inboundManager.Get(tag)
		if !found {
			known := make([]string, 0)
			for _, in := range s.inboundManager.Inbounds() {
				known = append(known, in.Tag())
			}
			s.logger.Warn("hot_reload: inbound ", tag, " not found; known tags: ", strings.Join(known, ","))
			s.writeError(w, http.StatusNotFound, "inbound not found: "+tag)
			return
		}
		updater, ok := inbound.(userUpdater)
		if !ok {
			s.writeError(w, http.StatusBadRequest, "inbound "+tag+" (type "+inbound.Type()+") does not support hot user update")
			return
		}
		if err := updater.UpdateUsers(uuids, uuids); err != nil {
			s.writeError(w, http.StatusInternalServerError, E.Cause(err, "update inbound users ("+tag+")").Error())
			return
		}
	}

	// Keep billing in sync: refresh the v2ray_api stats user set so hot-added
	// users are actually counted. If v2ray_api is not configured this is simply
	// skipped (billing_sync=false in the response) — not an error.
	billingSync := false
	if s.v2rayServer != nil {
		if stats := s.v2rayServer.StatsService(); stats != nil {
			if statsUpdater, ok := stats.(userSetUpdater); ok {
				statsUpdater.UpdateUsers(uuids)
				billingSync = true
			}
		}
	}

	s.logger.Info("hot-reloaded ", len(uuids), " users (billing_sync=", billingSync, ")")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(updateUsersResponse{
		OK:          true,
		UserCount:   len(uuids),
		BillingSync: billingSync,
	})
}

func (s *Server) writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(updateUsersResponse{OK: false, Error: message})
}
