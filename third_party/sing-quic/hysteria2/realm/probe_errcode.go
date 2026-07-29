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
	// ErrCodeNotAssigned：节点不认识这个用户（鉴权返 404）。
	//
	// 这**不是节点故障**，而是该账号没被分配到这个节点
	// （residential 是按需分配主/备，不是全节点可用）。
	// 与 auth_failure（凭证错/被拒）必须分开：前者说明"没分配"，
	// 后者说明"分配了但凭证不对"，指向完全不同的处理。
	// 混在一起会让未分配的健康节点在面板上显示成不可达。
	ErrCodeNotAssigned = "not_assigned"
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
	// 404 必须先于通用 auth 匹配 —— 原文是
	// "authentication failed, status code: 404"，同时含 "auth" 与 "404"。
	// 顺序反了就会被归成 auth_failure，"没分配"和"凭证错"混为一谈。
	case strings.Contains(msg, "status code: 404"), strings.Contains(msg, "status code 404"):
		return ErrCodeNotAssigned
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
