package realm

import (
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
)

func decodeTrace(t *testing.T, trace *Trace) map[string]any {
	t.Helper()
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal trace: %v", err)
	}
	return out
}

// nil Trace 必须是完全的 no-op —— 生产路径靠这条保证行为不变。
func TestNilTraceIsNoOp(t *testing.T) {
	var trace *Trace
	trace.STUNDone(nil, nil)
	trace.RendezvousDone(nil)
	trace.CandidatesComputed(nil)
	trace.HelloSent()
	trace.PunchDone(PunchResult{}, "v4", "")
	trace.HandshakeDone()
	trace.Fail(FailStagePunch, errors.New("boom"))
}

// 成功路径：各阶段耗时必须都存在，且 tunnel_established=true、无 fail_stage。
func TestTraceSuccessPathPopulatesAllStages(t *testing.T) {
	trace := NewTrace("egress-sg-02", "hysteria2")
	srflx := []netip.AddrPort{
		netip.MustParseAddrPort("117.181.51.12:54321"),
		netip.MustParseAddrPort("117.181.51.12:54321"),
	}
	trace.STUNDone(srflx, []string{"stun.l.google.com:19302"})
	trace.RendezvousDone([]netip.AddrPort{netip.MustParseAddrPort("13.214.21.114:51820")})
	trace.CandidatesComputed([]netip.AddrPort{netip.MustParseAddrPort("13.214.21.114:51820")})
	trace.HelloSent()
	trace.HelloSent()
	trace.PunchDone(PunchResult{
		PeerAddr: netip.MustParseAddrPort("13.214.21.114:51820"),
		Type:     PunchAck,
	}, "v4", "")
	trace.HandshakeDone()

	out := decodeTrace(t, trace)
	if out["tunnel_established"] != true {
		t.Errorf("tunnel_established = %v, want true", out["tunnel_established"])
	}
	if _, present := out["fail_stage"]; present {
		t.Errorf("fail_stage should be absent on success, got %v", out["fail_stage"])
	}

	stages, _ := out["stages"].(map[string]any)
	for _, key := range []string{"stun_ms", "rendezvous_ms", "punch_ms", "handshake_ms", "total_ms"} {
		if _, ok := stages[key]; !ok {
			t.Errorf("stages.%s missing on success path", key)
		}
	}

	detail, _ := out["punch_detail"].(map[string]any)
	if detail["peer_addr_matched"] != "13.214.21.114:51820" {
		t.Errorf("peer_addr_matched = %v", detail["peer_addr_matched"])
	}
	if detail["first_recv_type"] != "ack" {
		t.Errorf("first_recv_type = %v, want ack", detail["first_recv_type"])
	}
	if detail["hello_sent_count"].(float64) != 2 {
		t.Errorf("hello_sent_count = %v, want 2", detail["hello_sent_count"])
	}
	if detail["nat_type_guess"] != string(NATTypeCone) {
		t.Errorf("nat_type_guess = %v, want cone", detail["nat_type_guess"])
	}
}

// 失败路径：fail_stage 必须非空 —— 验收清单「fail_stage 全空说明埋点没生效」。
func TestTraceFailStageIsRecorded(t *testing.T) {
	trace := NewTrace("egress-nj-01", "hysteria2")
	trace.STUNDone([]netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:1000")}, []string{"stun.miwifi.com:3478"})
	trace.Fail(FailStagePunch, errors.New("punch timeout: context deadline exceeded"))

	out := decodeTrace(t, trace)
	if out["fail_stage"] != string(FailStagePunch) {
		t.Errorf("fail_stage = %v, want punch", out["fail_stage"])
	}
	if out["error_code"] != ErrCodeTimeout {
		t.Errorf("error_code = %v, want %s", out["error_code"], ErrCodeTimeout)
	}
	if out["tunnel_established"] != false {
		t.Errorf("tunnel_established = %v, want false", out["tunnel_established"])
	}
}

// 首次失败阶段生效，避免上层包装错误覆盖真实卡点。
func TestTraceFailKeepsFirstStage(t *testing.T) {
	trace := NewTrace("x", "hysteria2")
	trace.Fail(FailStageCandidate, errors.New("no compatible peer addresses"))
	trace.Fail(FailStagePunch, errors.New("realm punch"))

	out := decodeTrace(t, trace)
	if out["fail_stage"] != string(FailStageCandidate) {
		t.Errorf("fail_stage = %v, want candidate (first wins)", out["fail_stage"])
	}
	if out["error_code"] != ErrCodeNoCandidates {
		t.Errorf("error_code = %v, want %s", out["error_code"], ErrCodeNoCandidates)
	}
}

// 多个 STUN 反射地址不一致 → 对称 NAT 特征（移动 CGNAT 的典型表现）。
func TestGuessNATType(t *testing.T) {
	testCases := []struct {
		name  string
		addrs []string
		want  NATTypeGuess
	}{
		{"single address is undecidable", []string{"1.2.3.4:100"}, NATTypeUnknown},
		{"none is undecidable", nil, NATTypeUnknown},
		{"same mapping is cone", []string{"1.2.3.4:100", "1.2.3.4:100"}, NATTypeCone},
		{"differing port is symmetric", []string{"1.2.3.4:100", "1.2.3.4:200"}, NATTypeSymmetric},
		{"differing ip is symmetric", []string{"1.2.3.4:100", "5.6.7.8:100"}, NATTypeSymmetric},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var addrs []netip.AddrPort
			for _, raw := range testCase.addrs {
				addrs = append(addrs, netip.MustParseAddrPort(raw))
			}
			if got := guessNATType(addrs); got != testCase.want {
				t.Errorf("guessNATType(%v) = %v, want %v", testCase.addrs, got, testCase.want)
			}
		})
	}
}

// error_code 是聚合键，具体成因必须优先于宽泛的 timeout 匹配。
func TestClassifyErrorPrefersSpecificCause(t *testing.T) {
	testCases := []struct {
		msg  string
		want string
	}{
		{"no compatible peer addresses", ErrCodeNoCandidates},
		{"no STUN responses received", ErrCodeNoSTUNResponse},
		{"punch timeout: context deadline exceeded", ErrCodeTimeout},
		{"lookup stun.l.google.com: no such host", ErrCodeDNSFailure},
		{"x509: certificate signed by unknown authority", ErrCodeTLSFailure},
		{"dial udp: connection refused", ErrCodeConnectionRefused},
		{"something nobody predicted", ErrCodeUnknown},
	}
	for _, testCase := range testCases {
		if got := classifyError(errors.New(testCase.msg)); got != testCase.want {
			t.Errorf("classifyError(%q) = %s, want %s", testCase.msg, got, testCase.want)
		}
	}
	if got := classifyError(nil); got != "" {
		t.Errorf("classifyError(nil) = %q, want empty", got)
	}
}
