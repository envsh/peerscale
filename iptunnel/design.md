
# iptunnel 设计文档

ip packet level tunnel over libp2p network (should fix libp2p relayed connection bwlimit)

## 架构

每个对端一个 `tunnelHub`，每个 hub 维护 `carriers` 列表（libp2p stream）。

```go
type tunnelCarrier struct {
    s         network.Stream
    w         msgio.WriteCloser
    dead      atomic.Bool
    direction network.Direction  // DirOutbound / DirInbound
    created   time.Time
}

type tunnelHub struct {
    peerID   string
    mu       sync.Mutex
    carriers []*tunnelCarrier
    opening  bool          // 防止并发重连
    lastUse  time.Time
}
```

### 数据流

```
写出：softun → routeToPeer → WriteToPeer → hub.write → carrier.w.WriteMsg
读入：carrier.s → pump → r.ReadMsg → Sink.Inbound → softun
```

### 方向规则

- `write()` 只使用 `DirOutbound` carrier（本端发起的 stream）
- `pump()` 读取所有 carrier 的数据交给 Sink
- `attach()` 收到新 stream 时，同方向旧 carrier 被标记 dead 并从列表移除

## 断流切换机制

### 触发条件

| 触发点 | 位置 | 行为 |
|--------|------|------|
| pump 读到 error | pump:127 | defer detach(c) |
| write 失败 | write:161 | 标记 dead + go s.Close() |
| write 无 live carrier | write:153 | maybeOpenLocked |
| write 全失败 | write:169 | maybeOpenLocked |

### detach 逻辑

```go
func (h *tunnelHub) detach(c *tunnelCarrier) {
    c.dead.Store(true)
    h.mu.Lock()
    found := false
    for i, x := range h.carriers {
        if x == c {
            h.carriers = append(h.carriers[:i], h.carriers[i+1:]...)
            found = true
            break
        }
    }
    if found {
        h.maybeOpenLocked("detach: stream lost")  // 只在确实移除成功时才触发重连
    }
    h.mu.Unlock()
    c.s.Close()
}
```

**关键设计**：只有 carrier 确实在列表中移除成功时才触发重连。防止已被 `attach()` 摘除的旧 carrier 误触发重连导致级联。

### attach 逻辑（同向覆盖）

```go
func (h *tunnelHub) attach(s network.Stream) {
    c := &tunnelCarrier{direction: s.Stat().Direction, ...}
    h.mu.Lock()
    var live []*tunnelCarrier
    for _, old := range h.carriers {
        if old.direction == c.direction && !old.dead.Load() {
            old.dead.Store(true)       // 标记 dead
            continue                   // 从列表移除（不关闭 stream）
        }
        live = append(live, old)
    }
    live = append(live, c)
    h.carriers = live
    h.mu.Unlock()
    go h.pump(c)
}
```

**关键设计**：
- 新 stream 到来时，同方向旧 carrier 从列表移除（不关闭 stream）
- 旧 carrier 的 pump 退出时 detach 找不到它 → 不触发重连
- 旧 stream 由旧 pump 退出时的 `detach → c.s.Close()` 关闭
- 确保每个方向只有一个活跃 carrier

### 重连流程

```
maybeOpenLocked(reason)
  → opening=true（防止并发）
  → openPeerStreamAsync()
    → p2put.OpenStream(peerID, tunnelProto)
    → attach(s)  // 新 carrier 替换同方向旧 carrier
    → defer opening=false
```

## 已修复的问题

### 级联误触发（3-4 秒断流）

**根因**：`detach()` 对已被 `attach()` 摘除的 carrier 仍调用 `maybeOpenLocked()`，触发新 stream 打开，新 stream 的 `attach()` 又替换掉当前正在工作的 carrier，形成无限循环。

**修复**：`detach()` 中增加 `found` 标记，只在 carrier 确实在列表中移除成功时才触发重连。

### 级联时序

```
T=3s   网络抖动 → 双向 pump 报错 → detach → 重连
T=3.5s 新 stream 建立 → attach 替换旧 carrier
T=4.5s 旧 pump 退出 → detach → [修复前] 误触发重连 → 级联
                        → [修复后] found=false → 不触发 → 稳定
```

## 日志

| 日志 | 含义 |
|------|------|
| `handleStream: incoming stream from <peer>` | 收到对端发起的 stream |
| `attach: carrier added (<direction>, total=N)` | 新 carrier 加入 |
| `attach: remove old <direction> carrier` | 同方向旧 carrier 被替换 |
| `detach: carrier detached (<direction>, alive=Xs)` | carrier 退出（含存活时间） |
| `pump: read error` | stream 读取错误 |
| `write: no live carrier` | 无可写 carrier，触发重连 |
| `write: failed (<direction>)` | 写入失败 |
| `write: packet dropped len=N` | 包被丢弃 |
| `opening stream (reason)` | 正在重连 |
| `stream to <peer> opened` | 重连成功 |
