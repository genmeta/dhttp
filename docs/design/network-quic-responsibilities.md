# Network 与 QUIC 接入：职责划分和实施清单

日期：2026-10-03。本文以当前相邻 dquic 工作区的接口为准；结构、生命周期及调用顺序见 [Network 详细设计](network-detailed-design.md)。

## 1. 职责边界

**dhttp 负责网卡维护、地址发布生命周期和 HTTP 接入；dquic 提供 socket、地址簿及 QUIC/TLS 能力；h3x 负责 HTTP/3 和连接池机制。**

| 工作 | 下层职责 | dhttp 职责 |
| --- | --- | --- |
| 网卡与绑定 | qudp 按具体 IP、scope 和 BoundDevice 绑定 | 监听网卡变化，保存自己创建的实际 bound，决定增删和重建 |
| socket 收包 | Dock 保存登记、接收任务和协议 topology | 使用实际 bound 查询，检查任务存活，不接管临时或其他所有者的绑定 |
| 协议地址 | Dock 自动登记 direct QUIC 地址，移除时清理全部协议别名 | 仅在需要时登记额外别名 |
| 地址簿 | AddressBook 提供 inner/outer、NAT、网卡元数据和订阅 | 选择发布范围，显式发布、撤回并回滚局部失败 |
| 接收失败 | Dock 清除本次 socket、STUN 和 QUIC 登记 | 即使没有网卡事件，也检查失效绑定并撤回地址；必要时重建 |
| STUN/NAT | 提供协议探测、映射和打洞能力 | 决定何时启用；负责停止本绑定的探测及发布任务后再撤回 |
| 名称解析 | qresolve 提供全局 resolver；qconnection 消费地址流 | 保留应用注册的解析源，规范化请求名称和 authority |
| 名称发布 | AddressBook 提供准确的地址集合与变化订阅 | 将 DHTTP 名称与地址关联；装配实际 DDNS/mDNS 发布服务 |
| 具名端点 | QuicEndpoint 持有必填身份，提供 listen/connect | 加载身份材料，保存和复用内存凭据 |
| 匿名请求 | connect_anonymously 独立发起连接，与具名 connect 共用内部流程，仍验证服务器身份 | 调用匿名入口、配置 h3 和传输参数、隔离连接池条目 |
| TLS 与来源 | qtls 验证身份；qconn 处理逐名称 scopes、QUIC 路径与流 | 传入 scopes、核对实际 h3 ALPN、检查 HTTP authority |
| HTTP/3 | h3x 负责协议、QPACK、Body、流和通用 Pool | 名称到 Service 映射、池键、双向请求驱动及可信 extensions |

全部适用网卡在 init 时准备，纯客户端也有发送和接收资源。listener 的 scopes 只约束该名称的来源，不决定进程 socket 集合。停止 listener 撤销名称和 Service，保留共享网络资源。

## 2. 当前下层接口

```rust
// qconnection
QuicEndpoint::new(identity: Arc<qbase::endpoint::Endpoint>)
quic.identity.name()
quic.connect(server_name: String)

// qprotocol
Dock::new(topology: Arc<Topology>)
Dock::add(socket: Arc<UdpSocket>) -> io::Result<Option<AbortHandle>>
Dock::find_socket(bound: SocketAddr) -> Option<Arc<UdpSocket>>
Dock::remove(socket: &UdpSocket) -> bool
QuicProtocol::unregister(bound: SocketAddr)
AddressBook::insert_inner(socket: &UdpSocket, endpoint: EndpointAddr)
AddressBook::insert_outer(socket: &UdpSocket, endpoint: EndpointAddr)
AddressBook::remove_bound(bound: SocketAddr)
```

Dock 管理接收与协议登记；AddressBook 由发布它的上层管理。两者没有隐式生命周期关联，Network 必须组合调用。

`Some(handle)` 才表示本次新登记成功。`None` 表示已有登记，不授予 Network 发布或撤销该登记的所有权。Dock 已完成 direct QUIC 登记，上层只登记额外映射或中继别名。

## 3. Network 的绑定所有权

维护任务保存：

```text
网卡名称 + 索引 + 硬件地址 + IP/scope
  → 实际 bound + 原 socket 引用 + 接收任务 AbortHandle
```

每次扫描只核对这张所有权表。键仍在目标快照中，接收任务未结束，且 `Dock::find_socket(bound)` 返回原 socket 时，保留实际端口。网卡、地址或身份变化则撤回旧绑定，再创建新绑定。

临时打洞 socket 由 EphemeralSocket 的所有者管理。其他组件创建的 socket 即使绑定了同一张网卡，也不属于 Network；扫描和维护任务退出都不会移除它们。

IPv6 link-local 的 scope 使用接口索引。无效接口和局部绑定错误不阻断其他接口；空快照允许启动，后续恢复时补建。

## 4. 地址生命周期

### 登记与发布

```text
bind_to_device
  → Dock::add
  → Some(handle)
  → 按上层策略 insert_inner / insert_outer
  → 写入 Network 的绑定表
```

当前直接地址策略为 Loopback/Internal 写入 inner，External 写入 outer，无可发布 scope 的地址只保留 socket 登记。listener 的 External 不自动触发 STUN、NAT 或名称发布。

AddressBook 单次插入失败没有部分写入。失败后仅回滚本次新建的 Dock 登记，保留已有地址记录；重复 Dock 登记不进入发布步骤。

### 主动撤回

```text
停止并等待本绑定的探测、刷新和发布任务
  → AddressBook::remove_bound(bound)
  → Dock::remove(&socket)
```

当前发布操作都在维护任务内同步完成，没有额外探测或发布任务需要等待。未来引入这些任务时，必须先结束它们，避免撤回后重新发布旧地址。

AddressBook 清理地址、NAT、网卡记录和订阅状态。Dock 调用 `QuicProtocol::unregister(bound)` 清理全部别名，并停止接收及移除 STUN 登记。dhttp 不根据 AddressBook 返回的 direct 列表逐个撤销协议别名。

### 接收任务退出

Dock 的接收任务可能在没有网卡事件时退出。此时协议登记已清理，但地址簿记录仍需上层撤回。

watch 在系统事件之外，每秒检查一次自己的绑定，复用最近网卡快照。检查 `AbortHandle::is_finished()` 和按 bound 的 Dock 查询结果；失效时撤回地址，仍需该接口则重建。对任务被取消但 socket 引用仍存活的情况也适用。

系统接口只由 netwatcher 监测，定时器不枚举网卡。该机制允许最多一个正常检查间隔的地址滞后；运行时被阻塞时可能更久。所有写入与撤回由一个维护任务串行执行。

## 5. 具名端点和匿名请求

`Endpoint::new(identity)` 必须提供身份，构造具名 QuicEndpoint。`Endpoint::load` 读取 DHTTP home 的证书、私钥和 OCSP，之后连接与监听直接使用已加载材料。dhttp 的 Endpoint 始终持有 `Arc<QuicEndpoint>`，不能构造无身份 Endpoint，name() 返回 &str。

`Anonymous.get(uri)` 等方法创建未绑定 Endpoint 的匿名出站请求，与 Endpoint 的请求方法对称；`Anonymous.from_request` 和 `Request::new(http_request)` 用于标准请求。不创建 QuicEndpoint，也没有可供裸 `~` 展开的本端名称。Anonymous 和 Request 不提供监听能力；Request 的可选 Endpoint 只表达出站身份。dquic 的 QuicEndpoint 保持必填身份，匿名函数只有出站建连能力。

具名请求调用 QuicEndpoint::connect，匿名请求调用 qconn::connect_anonymously；两者共用 dquic 的内部建连流程。dhttp 显式配置 h3 ALPN 和 transport parameters。CID、初始密钥、TLS、路径、解析及后台任务全部由 dquic 创建和管理；dhttp 不再保留匿名建连模块。匿名请求仍验证服务器身份，握手失败不降级为匿名。

取消尚未交付的 connect future 时，dquic 发出连接关闭信号；客户端生命周期停止解析，并按既有 Closing/Draining 流程清理路径和 CID。已经排队但尚未被调用方取得的连接同样受此取消保护；成功交付后由连接句柄管理生命周期。

池键沿用名称值和远端端口。同目标的匿名请求可复用连接；具名请求与匿名请求隔离。匿名入站不会被当作某个具名远端复用。

## 6. 保留的连接与服务语义

- 应用可以在 Network 初始化前后注册全局 resolver，init 不替换它。
- 入站和出站共用 QuicTransport 的实际 ALPN 校验和 H3 构造；握手结果直接提供可信身份。
- 每条 H3 连接只有一个双向请求接入循环。无 Service 时停止和取消本次流。
- listen 取消后撤销名称和 Service；已有出站连接继续，同名重新监听后可沿用原连接。
- 按具体连接移出 Pool，防止旧驱动退出时删掉替换连接。
- 旧路径沿用发包失败退出机制；新本地地址经现有地址订阅、打洞及 QUIC 验证接入。
- 本轮不承诺恢复已经终止的连接，也不自动重放已发送的 HTTP 请求。

## 7. 验证范围

| 文件 | 主要验证 |
| --- | --- |
| `dhttp/src/network.rs` 单元测试 | 端口复用、IPv6 scope、网卡身份变化、空快照恢复、其他所有者 socket 保留、发布失败回滚、协议全别名撤回、接收任务实际失败和取消 |
| `dhttp/tests/network_lifecycle.rs` | 初始化幂等、地址显式发布、全局 resolver 保留、无网卡事件的失效撤回和重建、真实 EphemeralSocket 保留 |
| `dhttp/tests/quic_roundtrip.rs` | 单参数 Dock.add、具名和匿名实际 UDP/TLS/H3 请求、两个匿名构造入口、连接复用、双向请求和监听生命周期 |
| `dhttp/tests/dns_bootstrap.rs` | 单参数 Dock.add、H3 引导解析、authority 端口保留 |
| `dhttp/tests/listener_lifecycle.rs` | 具名身份、匿名监听拒绝、Service 撤销及共享 socket 保留 |

测试及实际执行结果见详细设计。系统网卡 down/up 的跨平台行为、NAT 映射和跨进程名称发布仍需独立验收。

## 8. 代码入口

- [Network](../../dhttp/src/network.rs)：初始化、绑定维护、地址生命周期、Pool 与请求驱动。
- [Endpoint](../../dhttp/src/endpoint.rs)：HTTP/3 配置与具名端点构造；匿名启动由 qconnection 的 connect_anonymously 提供。
- [QuicTransport](../../dhttp/src/transport.rs)：h3 校验、握手摘要和流适配。
- [qconnection endpoint](../../../dquic/qconnection/src/endpoint.rs)：具名 listen/connect。
- [Dock](../../../dquic/qprotocol/src/dock.rs)、[AddressBook](../../../dquic/qprotocol/src/addr_book.rs)、[QuicProtocol](../../../dquic/qprotocol/src/protocol/quic.rs)：各自登记和清理契约。
- [EphemeralSocket](../../../dquic/qprotocol/src/socket/ephemeral.rs)：临时 socket 所有权。

相邻仓库链接按当前 `genmeta/{dhttp,dquic,h3x}` 目录布局解析。
