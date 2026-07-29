package realm

// probe_stun.go —— 带埋点的 STUN 发现（仅 probe 分支）。
//
// 与 Discover 的唯一区别：记录「哪台 STUN 实际回了包」。
// 这是 STUN 选点优化的直接依据 —— 现网 stun_servers 是硬编码列表，
// 哪台真正有效、哪台常年不回，此前无数据。
//
// 刻意不改 Discover 本身的签名：生产路径调用点保持零改动。

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-quic/hysteria2/internal/stun"
	E "github.com/sagernet/sing/common/exceptions"
)

// DiscoverTraced 行为与 Discover 一致，额外返回实际响应的 STUN 服务器地址列表。
func DiscoverTraced(
	ctx context.Context,
	conn net.PacketConn,
	servers []string,
	resolver Resolver,
) ([]netip.AddrPort, []string, error) {
	resolved, err := resolveForConn(ctx, conn, servers, resolver)
	if err != nil {
		return nil, nil, err
	}
	requests, err := buildSTUNRequests(resolved)
	if err != nil {
		return nil, nil, err
	}
	// 事务 ID → 服务器地址，用于把响应归因到具体 STUN。
	serverByTxn := make(map[stun.TransactionID]netip.AddrPort, len(requests))
	for _, request := range requests {
		serverByTxn[request.transactionID] = request.server
	}
	var responded []string
	seenServer := make(map[netip.AddrPort]bool)

	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()
	buffer := make([]byte, 1500)
	runAttempt := func(deadline time.Time, pending map[stun.TransactionID]struct{}) ([]netip.AddrPort, error) {
		err := conn.SetReadDeadline(deadline)
		if err != nil {
			return nil, E.Cause(err, "set read deadline")
		}
		var addresses []netip.AddrPort
		for time.Now().Before(deadline) && len(pending) > 0 {
			n, _, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				if E.IsTimeout(readErr) {
					return addresses, nil
				}
				return nil, E.Cause(readErr, "read STUN response")
			}
			message, parseErr := stun.Decode(buffer[:n])
			if parseErr != nil {
				continue
			}
			_, isPending := pending[message.TransactionID]
			if !isPending {
				continue
			}
			delete(pending, message.TransactionID)
			address, parseErr := message.XORMappedAddress()
			if parseErr != nil {
				continue
			}
			if server, found := serverByTxn[message.TransactionID]; found && !seenServer[server] {
				seenServer[server] = true
				responded = append(responded, server.String())
			}
			addresses = append(addresses, address)
		}
		return addresses, nil
	}
	addresses, err := runDiscoveryAttempts(ctx, conn, requests, runAttempt)
	return addresses, responded, err
}
