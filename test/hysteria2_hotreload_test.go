package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	hotReloadAddr  = "127.0.0.1:18099"
	v2rayStatsAddr = "127.0.0.1:18098"
	userA          = "11111111-1111-1111-1111-111111111111"
	userB          = "22222222-2222-2222-2222-222222222222"
	hy2InboundTag  = "hy2-in"
)

// hy2HotReloadServerOptions builds a server-side box: a hysteria2 inbound that
// starts with a single user (userA), a v2ray_api StatsService counting that
// user, and the hot-reload control endpoint. The outbound is direct so the
// inbound's decrypted traffic reaches the local echo server.
func hy2HotReloadServerOptions(t *testing.T, certPem, keyPem string, statsUsers []string) option.Options {
	return option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeHysteria2,
				Tag:  hy2InboundTag,
				Options: &option.Hysteria2InboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					UpMbps:   100,
					DownMbps: 100,
					Users: []option.Hysteria2User{{
						Name:     userA,
						Password: userA,
					}},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
		Experimental: &option.ExperimentalOptions{
			V2RayAPI: &option.V2RayAPIOptions{
				Listen: v2rayStatsAddr,
				Stats: &option.V2RayStatsServiceOptions{
					Enabled: true,
					Users:   statsUsers,
				},
			},
			HotReload: &option.HotReloadOptions{
				Listen:     hotReloadAddr,
				InboundTag: hy2InboundTag,
			},
		},
	}
}

// hy2ClientOptions builds a client-side box: a socks mixed inbound that routes
// out through a hysteria2 outbound authenticating as `password`.
func hy2ClientOptions(certPem string, listenPort uint16, password string) option.Options {
	return option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: listenPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect},
			{
				Type: C.TypeHysteria2,
				Tag:  "hy2-out",
				Options: &option.Hysteria2OutboundOptions{
					ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: serverPort},
					UpMbps:        100,
					DownMbps:      100,
					Password:      password,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{Inbound: []string{"mixed-in"}},
					RuleAction: option.RuleAction{
						Action:       C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{Outbound: "hy2-out"},
					},
				},
			}},
		},
	}
}

func pushHotReloadUsers(t *testing.T, uuids ...string) {
	type user struct {
		UUID string `json:"uuid"`
	}
	body := map[string]any{"users": common.Map(uuids, func(u string) user { return user{UUID: u} })}
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post("http://"+hotReloadAddr+"/hotreload/users", "application/json", bytes.NewReader(buf))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "hot reload failed: %s", string(respBody))
	var parsed struct {
		OK          bool `json:"ok"`
		UserCount   int  `json:"user_count"`
		BillingSync bool `json:"billing_sync"`
	}
	require.NoError(t, json.Unmarshal(respBody, &parsed))
	require.True(t, parsed.OK)
	require.True(t, parsed.BillingSync, "billing user set must be refreshed alongside auth users")
	require.Equal(t, len(uuids), parsed.UserCount)
}

// queryUserTraffic reads the per-user uplink+downlink byte counters from the
// v2ray_api StatsService over gRPC.
func queryUserTraffic(t *testing.T, uuid string) int64 {
	conn, err := grpc.NewClient(v2rayStatsAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The server registers the StatsService under the v2ray-core service name
	// (overridden in experimental/v2rayapi stats.go init), not the generated
	// proto package name, so invoke the method path the server actually serves.
	req := &v2rayapi.QueryStatsRequest{Patterns: []string{"user>>>" + uuid}}
	resp := &v2rayapi.QueryStatsResponse{}
	err = conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", req, resp)
	require.NoError(t, err)
	var total int64
	for _, s := range resp.GetStat() {
		total += s.GetValue()
	}
	return total
}

// TestHysteria2HotReloadNoDrop is the headline WP-1 guarantee. With a live,
// continuously-streaming hysteria2 connection on the egress, hot-adding a user
// must NOT disturb that connection (no drop, no error), the new user must then
// be able to authenticate and pass traffic, and the new user's traffic must be
// billed (proving the v2ray_api stats user set was refreshed too).
func TestHysteria2HotReloadNoDrop(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")

	// Server starts knowing only userA (auth + billing).
	startInstance(t, hy2HotReloadServerOptions(t, certPem, keyPem, []string{userA}))

	// Client A connects as userA.
	startInstance(t, hy2ClientOptions(certPem, clientPort, userA))

	// Start a local TCP echo server at testPort that the tunneled traffic targets.
	echoListener, err := listen("tcp", ":"+F.ToString(testPort))
	require.NoError(t, err)
	defer echoListener.Close()
	go func() {
		for {
			c, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	// Open a long-lived tunneled connection and stream data continuously.
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	liveConn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	require.NoError(t, err)
	defer liveConn.Close()

	var streamErr atomic.Pointer[error]
	var roundtrips atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload := bytes.Repeat([]byte("X"), 1024)
		readBuf := make([]byte, len(payload))
		for {
			select {
			case <-stop:
				return
			default:
			}
			liveConn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := liveConn.Write(payload); err != nil {
				streamErr.Store(&err)
				return
			}
			if _, err := io.ReadFull(liveConn, readBuf); err != nil {
				streamErr.Store(&err)
				return
			}
			roundtrips.Add(1)
		}
	}()

	// Let the stream establish and run.
	time.Sleep(300 * time.Millisecond)
	rtBefore := roundtrips.Load()
	require.Greater(t, rtBefore, int64(0), "live stream should be flowing before hot reload")

	// Hot-add userB (full set {A,B}) repeatedly while the stream is live — this
	// also stresses the concurrent auth-read vs map-swap path for -race.
	for i := 0; i < 5; i++ {
		pushHotReloadUsers(t, userA, userB)
		time.Sleep(50 * time.Millisecond)
	}

	// The live connection must have survived and kept making progress.
	require.Nil(t, streamErr.Load(), "live connection dropped during hot reload: %v", deref(streamErr.Load()))
	time.Sleep(200 * time.Millisecond)
	require.Greater(t, roundtrips.Load(), rtBefore, "live stream stalled across hot reload")

	close(stop)
	<-done
	require.Nil(t, streamErr.Load(), "live connection errored after hot reload")

	// New user B must now be able to connect and pass traffic.
	startInstance(t, hy2ClientOptions(certPem, otherPort, userB))
	dialerB := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", otherPort), socks.Version5, "", "")
	connB, err := dialerB.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("127.0.0.1", testPort))
	require.NoError(t, err, "new hot-added user B failed to connect")
	defer connB.Close()
	msg := []byte("hello-from-B")
	connB.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = connB.Write(msg)
	require.NoError(t, err)
	echo := make([]byte, len(msg))
	_, err = io.ReadFull(connB, echo)
	require.NoError(t, err)
	require.Equal(t, msg, echo, "new user B traffic did not round-trip")

	// Billing: user B's traffic must be counted (proves stats user set refreshed).
	time.Sleep(200 * time.Millisecond)
	require.Greater(t, queryUserTraffic(t, userB), int64(0), "new user B traffic was not billed")
	require.Greater(t, queryUserTraffic(t, userA), int64(0), "user A traffic was not billed")
}

func deref(p *error) error {
	if p == nil {
		return nil
	}
	return *p
}
