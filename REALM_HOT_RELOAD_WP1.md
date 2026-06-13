# WP-1 交付物 — sing-box fork：hy2 inbound 运行时热更用户（加用户不断连接）

> 对应 `REALM_HOT_RELOAD_IMPLEMENTATION_HANDOFF.md` §2 的 WP-1。
> 基线：`SagerNet/sing-box` tag `v1.14.0-alpha.25`（commit `812a8fd`），fork `github.com/antsbtw/sing-box` 分支 `realm-hot-reload`。
> **单仓**：hy2 底层（sing-quic）的改动**内联**在本仓 `third_party/sing-quic/`，`go.mod` 用相对路径 `replace` 指过去。CI 只 clone 这一个仓即可 build，无需第二个 fork 仓。

---

## 1. 做了什么

让运行中的 sing-box 在**不 reload、不断现有连接**的前提下，被外部 agent 一次 HTTP 调用推入“当前应在线的全量 hy2 用户集”。同时把 v2ray_api 计费用户集一并热更，保证新加用户**仍被计费**。

三层改动（自底向上）：

1. **sing-quic fork**（`hysteria2/service.go`）：`Service.userMap` 由 `map[string]U` 改为 `atomic.Pointer[map[string]U]`。`UpdateUsers` 原子换 map，认证读路径原子 Load。已建 QUIC session 缓存了 `authUser`、不回查 map → 换 map 对在连接零影响，只有新握手用新集合。`go test -race` 通过。
2. **sing-box hy2 inbound**（`protocol/hysteria2/inbound.go`）：
   - 新增导出方法 `func (h *Inbound) UpdateUsers(names, passwords []string) error`（全量 set 语义，幂等）。
   - `userNameList` 改为 `atomic.Pointer[[]string]`，读路径（`NewConnectionEx` / `NewPacketConnectionEx`）走 `userName(index)` 原子 Load + 越界保护。
   - **稳定索引**：已存在的用户名保持其原 int 索引不变，新用户复用被删用户腾出的槽位、否则追加。这保证一个在更新前已认证的连接（其 int 索引已被 QUIC session 捕获）始终解析到同一个用户名 → **计费不会在用户集变化时错配**。
3. **v2ray_api StatsService**（`experimental/v2rayapi/stats.go`）：新增并发安全的 `UpdateUsers([]string)` 热更 `s.users` 计费白名单。`s.users` 原本只在构造期填一次、运行时不更新——只热加 hy2 user 而不刷这里，新用户会出网但**不计费**。本改动堵上这个缺口。
4. **热更端点**（新包 `experimental/hotreload/`）：一个绑 loopback 的 HTTP 控制服务，收到全量用户集后**同时**刷 hy2 inbound（认证）和 v2ray_api（计费）。通过新增实验选项 `experimental.hot_reload` 启用，由 `box.go` 像其它实验服务一样在 PostStart 阶段拉起；直接持有 inbound manager / v2ray server 实例（不靠 context registry 懒查，避免多实例共享 registry 时拿错）。

reload 路径**完全没动**——realm 参数变更仍走 reload（WP-3 负责区分）。编译 tag 不变。

## 2. 改了哪些文件

sing-box fork（`antsbtw/sing-box` @ `realm-hot-reload`）：
- `protocol/hysteria2/inbound.go` — `UpdateUsers` + 稳定索引 `assignStableIndices` + 原子 `userNameList`。
- `experimental/v2rayapi/stats.go` — 并发安全 `UpdateUsers` + `isCountedUser`。
- `experimental/hotreload/server.go` — **新增**，热更控制服务。
- `option/experimental.go` — 新增 `HotReloadOptions` + 挂到 `ExperimentalOptions.hot_reload`。
- `box.go` — `needHotReload` 判定 + 构造热更服务（把 inboundManager / v2rayServer 直接传入）。
- `protocol/hysteria2/inbound_hotreload_test.go` — **新增**，稳定索引单测。
- `test/hysteria2_hotreload_test.go` — **新增**，端到端不断连 + 计费验证。
- `go.mod` / `test/go.mod` — `replace sing-quic` 指向 fork（见 §5）。

内联的 sing-quic（本仓 `third_party/sing-quic/`，基线 commit `c865574`）：
- `hysteria2/service.go` — `userMap` 原子化。
- `hysteria2/service_hotreload_test.go` — **新增**，并发换 map race 测 + 全量 set 语义测。

## 3. 热更端点契约（WP-3 照此调用）

| 项 | 值 |
|---|---|
| 绑定 | `experimental.hot_reload.listen`（建议 `127.0.0.1:<port>`，仅本机 agent 调，**无鉴权**） |
| 目标 inbound | `experimental.hot_reload.inbound_tag`（指向那个 hy2 inbound 的 tag） |
| 路径 | `POST /hotreload/users` |
| 请求体 | `{"users":[{"uuid":"<uuid>"}, ...]}` —— **全量集**（当前应在线的所有用户），非增量。空 uuid 报 400。重复 uuid 自动去重。 |
| 语义 | name = password = uuid（贴 realm hy2 inbound 配置 + realm 双 UUID 契约）。幂等：重复推同一集合无副作用、不增长。 |
| 成功响应 | `200` `{"ok":true,"user_count":N,"billing_sync":true}`。`billing_sync=true` 表示 v2ray_api 计费集已同步；若未配 v2ray_api 则为 `false`（不算错）。 |
| 错误响应 | `400`（请求体坏 / 空 uuid）、`404`（inbound_tag 找不到）、`405`（非 POST）、`500`（内部错/inbound 不支持热更/panic）。统一 `{"ok":false,"error":"..."}`。 |

配置片段示例（agent 生成 sing-box 配置时加）：
```json
"experimental": {
  "v2ray_api": { "listen": "127.0.0.1:10085", "stats": { "enabled": true, "users": ["<uuid>", ...] } },
  "hot_reload": { "listen": "127.0.0.1:10086", "inbound_tag": "hy2-in" }
}
```
> 注意 hy2 inbound 必须有 `tag` 且与 `hot_reload.inbound_tag` 一致。

调用示例：
```bash
curl -s -XPOST http://127.0.0.1:10086/hotreload/users \
  -H 'Content-Type: application/json' \
  -d '{"users":[{"uuid":"<uuidA>"},{"uuid":"<uuidB>"}]}'
# -> {"ok":true,"user_count":2,"billing_sync":true}
```

**WP-3 兜底建议**：调用失败（连接拒绝/非 200）时降级回 reload，保证最终一致。

## 4. 构建命令

Go 1.25（基线用 go1.24.7，1.25 兼容）。编译 tag 与现状一致：
```bash
go build -tags "with_v2ray_api,with_clash_api,with_quic,with_utls" -o sing-box ./cmd/sing-box
# 并发验证（开发期）：
go build -race -tags "with_v2ray_api,with_clash_api,with_quic,with_utls" ./cmd/sing-box
```
产物 `version` 输出确认 tag：`Tags: with_v2ray_api,with_clash_api,with_quic,with_utls`。

## 5. go.mod replace（单仓，CI 直接可用）

`go.mod` 与 `test/go.mod` 都用**相对路径** replace 指向内联的 sing-quic：
```
# go.mod
replace github.com/sagernet/sing-quic => ./third_party/sing-quic
# test/go.mod
replace github.com/sagernet/sing-quic => ../third_party/sing-quic
```
因为 `third_party/sing-quic` 就在本仓里，CI clone `antsbtw/sing-box` 后 `go build` 直接命中，**无需第二个仓、无需 pseudo-version**。WP-3 的 `build-singbox.yml` 只要把 clone 源从 `SagerNet/sing-box` 改成本 fork 分支即可。

> 升级上游 sing-quic 时：用新的上游 sing-quic 源码覆盖 `third_party/sing-quic/`，重打 `hysteria2/service.go` 那 16 行 patch（见 §2）即可。

## 6. 验证（已实际跑过，均 -race）

- `sing-quic` `TestServiceUpdateUsersConcurrent` / `TestServiceUpdateUsersReplacesMap` — 并发换 map race-free + 全量 set 语义。**PASS**。
- `sing-box` `protocol/hysteria2` `TestAssignStableIndices_*` — 加/删/复用/幂等下索引稳定、计费不错配。**PASS**。
- `sing-box` `test` `TestHysteria2HotReloadNoDrop` — **端到端**：一条持续流式 hy2 连接在被热更 5 次（加 userB）期间**不断、不卡**；userB 随后能认证出网；userA/userB 经 v2ray_api gRPC 查出**都计费**（非零）；全程 `-race` 无竞争。**PASS**。

复现：
```bash
# sing-quic fork
cd sing-quic && go test -race -run TestServiceUpdateUsers ./hysteria2/
# sing-box fork（带 tags）
cd sing-box && go test -race -tags "with_quic,with_v2ray_api" -run TestAssignStableIndices ./protocol/hysteria2/
cd sing-box/test && go test -race -tags "with_quic,with_v2ray_api,with_clash_api,with_utls" -run TestHysteria2HotReloadNoDrop .
```

## 7. 对照 §0.6 验收标准

| 标准 | 结论 | 证据 |
|---|---|---|
| 不断连 | ✅ | e2e：5 次热更期间 live 连接 roundtrips 持续增长、无 error、journctl 无 reload |
| 新用户可用 | ✅ | e2e：userB 热加后握手认证成功并 echo 出网 |
| 计费仍准 | ✅ | e2e：userA/userB 经 v2ray gRPC QueryStats 均非零；`billing_sync=true` |
| realm 变更仍 reload | ✅ | 未触碰 reload 路径；热更是新增旁路，realm/dns 变更由 WP-3 走 reload |
| 并发安全 | ✅ | 全部测试 `-race` 通过；userMap/userNameList 均原子；stats.users 加锁 |

## 8. 待用户做（需凭据/不可逆）

1. push `antsbtw/sing-box` 的 `realm-hot-reload` 分支（含内联的 `third_party/sing-quic`）。**只此一个仓**。
2. 交 WP-3：把 `build-singbox.yml` 的 clone 源从 `SagerNet/sing-box` 切到 `antsbtw/sing-box@realm-hot-reload`；按 §3 契约接热更端点。

> §5 的 replace 已是相对路径，随仓走，push 后 CI 直接可 build，无需任何额外改动。
