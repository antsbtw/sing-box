package realm

// probe_errcode.go —— 把错误原文映射为稳定枚举，便于聚合。
// 仅 probe 分支使用。原文仍完整保留在 error_msg，枚举只是聚合键。

import "strings"

const (
	ErrCodeUnknown           = "unknown"
	ErrCodeTimeout           = "timeout"
	ErrCodeCanceled          = "canceled"
	ErrCodeNoCandidates      = "no_candidates"
	ErrCodeNoSTUNResponse    = "no_stun_response"
	ErrCodeDNSFailure        = "dns_failure"
	ErrCodeConnectionRefused = "connection_refused"
	ErrCodeNetworkUnreach    = "network_unreachable"
	ErrCodeTLSFailure        = "tls_failure"
	ErrCodeAuthFailure       = "auth_failure"
	ErrCodeHTTPStatus        = "http_status"
)

// classifyError 按最具体优先匹配。顺序有意义：先匹配具体成因，
// 再落到 timeout 这类宽泛特征，避免「DNS 超时」被粗分成 timeout。
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no compatible peer addresses"):
		return ErrCodeNoCandidates
	case strings.Contains(msg, "no stun responses"):
		return ErrCodeNoSTUNResponse
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "dns"):
		return ErrCodeDNSFailure
	case strings.Contains(msg, "connection refused"):
		return ErrCodeConnectionRefused
	case strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "no route to host"):
		return ErrCodeNetworkUnreach
	case strings.Contains(msg, "x509"), strings.Contains(msg, "tls"), strings.Contains(msg, "certificate"):
		return ErrCodeTLSFailure
	case strings.Contains(msg, "unauthorized"), strings.Contains(msg, "forbidden"), strings.Contains(msg, "auth"):
		return ErrCodeAuthFailure
	case strings.Contains(msg, "unexpected status"), strings.Contains(msg, "status code"):
		return ErrCodeHTTPStatus
	case strings.Contains(msg, "context canceled"):
		return ErrCodeCanceled
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return ErrCodeTimeout
	default:
		return ErrCodeUnknown
	}
}
