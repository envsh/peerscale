# update-new-libp2p.md

## 目标
把 myvendor 精简版 go-libp2p 从 v0.36.2 升级到 **v0.49.0**（Go 1.25.9 支持的最后版本），沿用现状精简策略，控制体积与行为影响并验证。

## 已核对结论（均为实测/静态分析）

### 版本天花板
- go-libp2p **v0.49 系列只有 v0.49.0**，无小版本；go.mod `go 1.25.7`。
- v0.50.0 起要求 go 1.26 → 被 1.25.9 排除，因此 v0.49.0 即上限。
- 依赖对齐：
  - `go-libp2p-kad-dht v0.42.2`：go 1.25.7，**精确依赖 go-libp2p v0.49.0**。
  - `go-libp2p-pubsub v0.18.0`：go 1.25，依赖 go-libp2p v0.47.0，靠 replace 编译对 fork，风险中低需实证。
- 两包子依赖 import 的 go-libp2p 包（`core/*`、`p2p/host/{basic,eventbus,peerstore,pstoremem}`、`p2p/net/{mock,swarm,connmgr}`、`p2p/discovery/backoff`、`p2p/protocol/identify`）全部在保留清单内；它们引用的 `p2p/net/swarm/testing`、`x/simlibp2p` **仅出现在各自测试文件**，删除安全。

### `go get -u` 陷阱（本次事故根因）
- 错误 `requires go >= 1.26.0` 是 `-u` 把传递依赖顶到 latest 造成：
  x/crypto v0.58.0、x/net v0.61.0、x/sys v0.49.0、x/tools v0.52.0、x/mod v0.42.0、
  x/sync v0.24.0、x/exp 2026-10、prometheus/client_golang v1.25.0、prometheus/common v0.72.1 ——均已要求 go 1.26。
- v0.49.0 / kad-dht v0.42.2 实际钉的都是 pre-1.26：
  x/crypto v0.54.0、x/net v0.57.0、x/sync v0.22.0、x/sys v0.47.0、x/mod v0.38.0、
  x/tools v0.48.0、prometheus/client_golang v1.24.1、prometheus/common v0.70.1。
- **规则：一律不加 `-u`**，逐模块精确 `@version`；`go mod tidy` 遵循 MVS 不会主动升级到 1.26。

### 已决策
1. asn-util 维持精简 stub（`AsnForIPv6` 返回 0）→ relay `MaxReservationsPerASN` 限额保持失效（与现状一致）。
2. `p2p/security/insecure` 保留不动（含 config.go 引用）。

## 精简保留/删除清单（v0.49）

保留：
- `p2p/transport/tcpreuse`（tcp/websocket/config 依赖）
- `x/rate`（identify/rcmgr 依赖）
- `noise` / `tls` / `yamux`
- `p2p/security/insecure`
- `p2p/http`、`docs`、`scripts`

删除：
- `p2p/transport/{quic, quicreuse, webrtc, webtransport}`
- `x/simlibp2p`
- `p2p/net/swarm/testing`
- `p2p/transport/testsuite`、`p2p/muxer/testsuite`
- `p2p/test/`
- `examples/`、`test-plans/`、`leaky_tests/`、`.github/`、`.githooks/`

## Phase A — 重建精简 fork
1. v0.49.0 源码全量替换 `myvendor/go-libp2p/`（纯重建，不增量 patch）。
2. 删除上表"删除"列所有目录。
3. `config/defaults.go`：删 quic/webrtc/webtransport 的 3 个 import + 3 行 `Transport(...)` + 6 条 `/udp/0/...` 默认监听地址。
4. `config/options.go`：删公开函数 `QUICReuse()` + `quicreuse` import。
5. `config/config.go`：
   - 删 import：`quicreuse`、`libp2pwebrtc`（以及残留的 quic-go import）
   - 删 `fx.Provide(PrivKeyToStatelessResetKey)` / `fx.Provide(PrivKeyToTokenGeneratorKey)`
   - 删默认 `*quicreuse.ConnManager` provider（`cfg.QUICReuse` if/else 分支中的 else 块）
   - 删 webrtc `ListenUDPFn` provider
   - 删 swarm 构造器入参 `_ *quicreuse.ConnManager`
   - 整删 `config/quic.go`
   - `insecure` 相关代码原样保留
6. go.mod 保持 `go 1.25.7`；`version.json` → `v0.49.0`。
7. fork 内 `go mod tidy`（Go 1.25.9）：清掉 quic-go/qpack/webtransport-go/pion 全系；确认 `go-libp2p-asn-util v0.4.1` 仍为 direct require（relay 用）。
8. 残留扫描：全树 grep `quic|quicreuse|webrtc|webtransport|quic-go` 清零后 `go build ./...` 通过。

## Phase B — 父工程迁移
```bash
# 先 git status 确认上次 -u 未污染 go.mod/go.sum，有残留则 git checkout -- go.mod go.sum
# 按顺序、不带 -u
go get github.com/libp2p/go-libp2p@v0.49.0
go get github.com/libp2p/go-libp2p-kad-dht@v0.42.2
go get github.com/libp2p/go-libp2p-pubsub@v0.18.0
go mod tidy
# 兜底：若 tidy 后间接依赖出现 go 1.26，显式钉回（如 go get golang.org/x/crypto@v0.54.0）
```
- go.mod 指令：`go 1.21.0` → `go 1.25.7`；require 对齐三个目标版本；replace 两处（go-libp2p、asn-util）不变。
- 间接依赖 kbucket/record/routing-helpers 等由 tidy 解析。
- API 走查：`libp2p_bs.go`（`EnableAutoRelayWithStaticRelays`、事件订阅、`*swarm.Swarm` 断言）、`relaypool.go`（circuitv2 client 签名、relay backoff 修复影响）、`user_protocols.go`、`stable_peers.go`。
- `go build ./...` + `go vet` + p2put/softun/iptunnel 测试（含 `-race`）。

## Phase C — 体积与行为验证
| 组合 | 预期 |
|---|---|
| 1.22.3 / 精简0.36（基准） | 31M |
| 1.25.9 / 精简0.36（现状） | 33M |
| **1.25.9 / 精简0.49** | 删 quic/pion 净收益 ≥ stdlib fips140 增长 → ≤33M，可能回 31M 以下 |

运行时冒烟：RelayPool 选路 / managed / event suber / DHT / TCP+WS 互通。

## 风险
- pubsub v0.18.0 按 v0.47 API 写，对 fork v0.49 需 `go build` 实证（中低）；失败则退 v0.17.0。
- ASN 限额保持失效（已决策接受）。
- 工具链需 Go 1.25.9（联网 `GOTOOLCHAIN=auto` 或已装）。
- 纯替换式重建 fork，原 git 历史不保留（无功能意义）。