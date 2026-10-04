# Network 详细设计

日期：2026-10-03。本文描述 dhttp 对当前 dquic 接口的适配，与[职责划分](network-quic-responsibilities.md)配套。

## 1. 资源归属

`DhttpNetwork::init` 为全部适用网卡准备 socket。网卡维护任务保存自己创建的绑定，负责地址发布、撤回和重建；Dock 负责收包任务及协议登记。停止 listener 只撤销名称和 Service，共享 socket 继续供出站和其他服务使用。

```text
DhttpNetwork（进程单例）
  listeners → 本端名称 → Tower Service
  pool      → ConnectionKey → h3x Pool

网卡维护任务
  watcher   → netwatcher 系统事件
  snapshot  → 最近一次完整网卡快照
  bindings  → 网卡身份 + IP/scope → 实际 bound、socket、接收任务句柄
  dock      → Dock
  addresses → AddressBook

Dock
  实际 bound → socket 登记、接收任务
  topology   → QUIC / STUN / forward 协议

AddressBook
  inner / outer 地址、网卡元数据、NAT 记录及订阅

qconn ServerRegistry
  本端名称 → TLS 材料、监听 scopes、接入回调
```

Dock 不持有 AddressBook。维护任务中的绑定表只记录 Network 的资源所有权和实际端口，不复制协议地址簿，也不接管其他所有者或打洞流程创建的 socket。

## 2. 结构和入口

实现按职责拆分，子模块均为私有，公开入口仍是 `network::DhttpNetwork`：

| 文件 | 职责 |
| --- | --- |
| `dhttp/src/network.rs` | 进程单例、初始化装配、连接池访问及名称到 Service 的登记 |
| `dhttp/src/network/connection.rs` | 连接池键、具名和匿名建连、双向 HTTP/3 请求驱动 |
| `dhttp/src/network/interfaces.rs` | 首次网卡扫描、绑定所有权、事件与存活检查、串行 NAT future 轮询及撤回 |
| `dhttp/src/network/interfaces/nat.rs` | 一次性 NAT 分类、STUN 心跳、QUIC 端点地址和外部映射同步 |

各模块的回归测试统一放在 `dhttp/tests/unit/network/`，共享绑定测试夹具放在 `dhttp/tests/support/interface_bindings.rs`；源模块通过 `#[cfg(test)]` 和 `#[path]` 接入，以保留对私有实现的单元测试。NAT 模块属于网卡绑定维护，其 future 由绑定持有并由唯一维护任务轮询；拆分不增加后台任务，也不改变发布与撤回顺序。

### 2.1 Network 与连接池

```rust
pub struct DhttpNetwork {
    listeners: Mutex<HashMap<Arc<str>, BoxService>>,
    pool: h3x::Pool<ConnectionKey, QuicTransport, Error>,
}

enum ConnectionKey {
    Incoming { local: Arc<str>, remote: Option<Arc<str>> },
    Outgoing { local: Option<Endpoint>, remote: Arc<str> },
}
```

`ConnectionKey` 的 Eq/Hash 比较本端、远端名称值。双方具名时，同名 Incoming 与 Outgoing 共享池条目；匿名本端和匿名对端分别保留 `None`，不会匹配具名连接。远端 authority 的端口参与出站键，避免不同服务端口共用连接。

`NETWORK` 使用 `tokio::sync::OnceCell::get_or_try_init`。重复和并发 init 返回同一实例。取得连接的等待期限保持 30 秒。Network 沿用进程生命周期，Tokio runtime 必须持续存活。

### 2.2 网卡维护的私有状态

```rust
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct InterfaceAddress {
    name: String,
    index: u32,
    hw_addr: String,
    addr: SocketAddr, // 端口为 0，保留 IPv6 scope
}

struct Binding {
    bound: SocketAddr, // local_addr 返回的实际端口
    socket: Arc<UdpSocket>,
    receiver: tokio::task::AbortHandle,
    nat_probe: futures::future::BoxFuture<'static, ()>,
}

struct InterfaceBindings {
    dock: Arc<Dock>,
    addresses: Arc<AddressBook>,
    bindings: HashMap<InterfaceAddress, Binding>,
}
```

名称、索引和硬件地址共同描述快照中的网卡身份；硬件地址变化也会触发替换。不同 IP 或 IPv6 scope 是不同绑定。socket 引用供按实例撤销，并让旧绑定在地址撤回完成前继续占用自己的端口。AbortHandle 用于识别接收任务已经结束的情况。nat_probe 直接持有该绑定的一次性 NAT 分类及后续 STUN 绑定心跳 future，由唯一维护任务轮询，不 spawn 独立发布任务。NAT 分类只在新 socket 创建时执行一次；之后每20秒向同地址族的 STUN 节点发送绑定心跳并读取各节点的映射，失败的映射撤回，下次心跳重试。NAT 分类失败不重新分类，也不阻止心跳继续保活；映射仍可更新 DDNS，但不伪造 NAT 类型，外部打洞广告等待有效分类。Loopback 和 IPv6 link-local 不探测。

### 2.3 函数职责

| 入口 | 职责 |
| --- | --- |
| `DhttpNetwork::init/global` | 初始化信任、路由、首次扫描和维护任务；读取单例 |
| `interfaces::init` | 装配网卡监听器和路由，完成首次扫描后启动唯一维护任务 |
| `interfaces(snapshot)` | 生成以网卡身份和 IP/scope 为键的目标绑定集合 |
| `InterfaceBindings::register(socket)` | Dock 登记成功后显式发布地址；发布失败时回滚本次登记 |
| `InterfaceBindings::scan(snapshot)` | 保留存活绑定，撤回失效或过期绑定，补齐缺少的绑定 |
| `InterfaceBindings::withdraw(binding)` | 先撤回 AddressBook，再按 socket 移除 Dock 登记 |
| `InterfaceBindings::drop` | 维护任务退出时撤回它仍拥有的绑定 |
| `watch(watcher, snapshot, bindings)` | 优先处理网卡事件和每秒一次的存活检查，串行扫描并轮询各绑定的 NAT/心跳 future |
| `nat::probe_nat/sync_nat_mappings` | 一次性分类和持续心跳，无返回结果，内部记录日志，先更新 QUIC 端点地址再同步地址簿，局部失败回滚 |
| `DhttpNetwork::listen` | 登记具名 QUIC 服务及 Tower Service，取消时撤销名称 |
| `get_connection/connect` | 查 H3 Pool；分别启动具名或匿名连接，装配 H3 并启动请求驱动 |
| `serve_connection` | 接收双向请求流，读取当前 Service，退出时按连接实例移出池 |

## 3. 初始化与扫描

### 3.1 初始化

1. 初始化信任，建立 netwatcher 监听器和全局 QuicRouter。
2. 消费监听器立即交付的初始快照。
3. 创建 `InterfaceBindings`，扫描全部适用网卡。
4. 将监听器、快照和绑定表交给唯一的维护任务。
5. 发布 Network 单例。

信任或监听器创建失败时，OnceCell 仍可重试。单个绑定失败只记录错误，其他绑定继续；空快照也允许初始化成功。首次扫描结束到启动维护任务之间没有 await。初始化不读取身份目录，也不等待 NAT 探测。

### 3.2 目标地址

使用 netwatcher 提供的启用接口及 IP 列表。忽略 unspecified 和 multicast 地址；IPv4 直接绑定具体 IP，IPv6 link-local 使用该接口索引作为 scope ID，其他 IPv6 地址使用 scope 0。端口请求值为 0，实际端口由操作系统分配。

`BoundDevice::new` 和 `bind_to_device` 的实际返回值决定能否使用该接口。重复地址记录在目标表中合并，不产生重复绑定。

### 3.3 扫描算法

```text
根据当前快照生成目标集合
  → 遍历 Network 自己的绑定
      key 仍存在
      且接收任务尚未结束
      且 Dock::find_socket(bound) 返回原 socket
        → 保留原绑定和原端口
      否则
        → 撤回地址并移除原登记
  → 遍历缺少绑定的目标
      bind_to_device(IP:0, device)
        → register(socket)
        → 只有新登记和发布成功才写入绑定表
```

查询始终是 `Dock::find_socket(bound: SocketAddr)`。Network 不枚举 Dock，也不根据“是否绑定网卡”推断资源所有权。其他所有者的网卡 socket 和临时打洞 socket 都留给其所有者处理。

名称、索引、硬件地址、IP 或 scope 变化时，旧键被撤回。未变化且仍存活的绑定不会重复发布，也不会重新分配端口。

## 4. 登记、发布与撤回

### 4.1 新建绑定

当前下层入口为：

```rust
Dock::add(Arc<UdpSocket>) -> io::Result<Option<AbortHandle>>
Dock::find_socket(SocketAddr) -> Option<Arc<UdpSocket>>
Dock::remove(&UdpSocket) -> bool
QuicProtocol::unregister(SocketAddr)
```

`Dock::add` 登记 STUN socket、直接 QUIC 地址并安装接收任务。返回值含义：

| 返回值 | Network 的处理 |
| --- | --- |
| `Ok(Some(handle))` | 本次新登记成功，可以开始本次地址发布 |
| `Ok(None)` | 已有登记；不发布、不加入自己的绑定表、不撤销已有登记 |
| `Err(error)` | 下层登记失败，记录错误并等待下一轮重试 |

Dock 已登记 `EndpointAddr::direct(bound)`，Network 不重复登记它。需要额外映射或中继端点地址时，由相应所有者向 QuicProtocol 登记额外端点地址。

当前 Network 对直接地址采用以下发布策略：

| `EndpointAddr::scope()` | 操作 |
| --- | --- |
| Loopback / Internal | `AddressBook::insert_inner(&socket, direct)` |
| External | `AddressBook::insert_outer(&socket, direct)` |
| 无可用 scope | 保留 socket 登记，不发布地址 |

AddressBook 从 socket 读取实际 bound 和网卡元数据。是否发布及 inner/outer 的选择属于上层策略，不由 listener 的 scopes 决定。写入 AddressBook 也不等于已经向 DDNS 或 mDNS 服务发布名称。

AddressBook 的单次插入是原子的。插入失败时，Network 调用 `Dock::remove(&socket)` 回滚本次新登记；不能调用 `remove_bound` 删除导致本次插入失败的既有地址记录。

### 4.2 主动撤回

```text
停止轮询并丢弃该绑定的 nat_probe future
  → AddressBook::remove_bound(bound)
  → Dock::remove(&socket)
  → 释放 Network 的 socket 引用
```

NAT future 只由维护任务轮询，分类、心跳及同步地址更新均不另起任务。扫描与 future 轮询串行，绑定移除时丢弃 nat_probe，立即取消尚未完成的 STUN transaction；不存在后台写入或需要等待的独立探测任务。映射变化时先更新 QUIC 直接/中介端点地址，再更新 AddressBook；端点地址冲突保留原发布，失效映射的端点地址及发布一起撤回。

`AddressBook::remove_bound` 清除 inner/outer 地址、NAT 和网卡记录，并发出撤回通知。Dock 移除接收任务和 STUN 登记，内部调用 `QuicProtocol::unregister(bound)` 清理全部协议端点地址；Network 不遍历或逐个撤销端点地址。

### 4.3 接收任务自行结束

Dock 的接收任务结束时会清除自己的登记和 QUIC 端点地址，AddressBook 保持原状。因此 watch 同时等待两种触发：

- netwatcher 交付新的完整快照；
- 每秒一次的绑定检查，使用最近快照。

检查同时读取 `AbortHandle::is_finished()` 和 `Dock::find_socket(bound)`。即使外部取消任务后 Dock 仍能升级 socket 引用，也能识别该绑定已失效。随后执行相同撤回流程；网卡仍适用时，在同轮扫描中重建并发布。

这项定时检查不轮询操作系统网卡。间隔采用 Skip 策略，运行时阻塞后的过期 tick 不连续补跑。正常调度下，失效地址在下一次检查时撤回；不承诺故障和撤回原子发生。绑定失败也会在后续检查重试。

维护任务退出时，其私有绑定表的 Drop 执行同样的撤回流程，不影响其他所有者的 socket。

## 5. 具名端点与匿名请求

### 5.1 具名端点

```rust
pub struct Endpoint {
    pub(crate) quic: Arc<qconn::QuicEndpoint>,
}
```

`Endpoint::new(identity)` 把必填身份传给 `QuicEndpoint::new`，显式配置 h3 ALPN 和现有 client/server transport parameters。Endpoint 始终持有 `Arc<QuicEndpoint>`，不能构造无身份端点；name() 返回 &str，读取 `quic.identity.name()`。

`Endpoint::load` 规范化 DHTTP 名称，并一次性读取证书链、私钥和 OCSP。克隆共享内存中的 QUIC endpoint；新连接和 listen 不重新读取身份文件。凭据加载或验证失败返回错误。

### 5.2 匿名出站

`Anonymous` 是无状态的匿名出站入口，提供与 Endpoint 对称的 get/head/post/put/patch/delete/options/request/from_request 方法。GET/HEAD/DELETE/OPTIONS 返回 Request<Empty>，POST/PUT/PATCH/request 返回 Request<WndBuf>，上传和响应接口与具名请求相同。

`Anonymous.from_request` 和 `Request::new(http::Request<B>)` 不绑定 Endpoint；Anonymous 与 Request 都不提供 listen，也不能使用需要本端名称的裸 `~` URI。Endpoint.from_request 绑定具名 Endpoint；可选状态只存在于出站 Request 和连接池键中，不存在于任何监听端点中。

连接池 factory 选择 dquic 的两种入口，两者共用内部建连实现：

```text
Some(endpoint) → endpoint.quic.connect(server_name)
None           → qconn::connect_anonymously(server_name, client_parameters, alpn)
```

qconn 的具名 connect 提供本端 LocalAuthority，匿名函数传入 None；共有的内部流程统一创建初始 CID、密钥、TLS context 和 Paths，并启动 `client_growing` 与 `recv::tick`。dhttp 只装配 HTTP/3 所需配置，不实现匿名 QUIC 启动。

解析源、地址流、路径发现和 QUIC/TLS 生命周期由下层客户端流程处理。TLS 验证目标服务器身份；匿名只表示不提交本端身份。握手名称去掉 authority 的端口，解析和连接池键保留端口。取消尚未交付的 connect future 会发出关闭信号，停止解析并按现有关闭流程清理路径及 CID；回调无法交付已经建立的连接时同样关闭该连接。

匿名请求可复用同目标的匿名连接，并与具名请求隔离。dhttp Endpoint 和 qconn QuicEndpoint.identity 都保持必填；实际认证身份来自握手结果，错误不表示匿名。

## 6. H3 接入与服务生命周期

- 具名出站继续调用 `connect(server_name)`；Network 初始化不覆盖全局 resolver 注册。
- 入站回调和出站 factory 都通过 `QuicTransport::new` 核对实际 h3 ALPN，保存实际握手摘要和 Client/Server 角色，再创建 H3Connection。
- 每条 H3 连接启动一个 `serve_connection`。控制及 QPACK 单向流由 h3x 驱动。
- 每次请求读取当前名称对应的 Service；没有 Service 时停止接收方向并取消发送方向。
- HTTP authority 必须匹配握手本端身份，可信身份放入请求或响应 extensions。
- 取消 listen 在服务表锁内移除 Service 和 ServerRegistry 名称。已取得 Service 的请求继续，同名服务重新监听后原连接可交付给新 Service。
- 请求驱动退出时按具体连接移出池，保留同键的替换连接。h3x 负责建连去重和复用。

旧 path 沿用下层发送错误退出机制；新的本地地址通过现有 AddressBook 订阅、puncher 和路径验证接入。已因最后一条路径失败而结束的连接不会被恢复；网络恢复后新请求可重新建连。

## 7. 验收与边界

| 测试 | 覆盖内容 |
| --- | --- |
| Network 单元测试 | IPv6 scope、无效地址过滤、端口复用、网卡身份变化、空快照恢复、其他所有者 socket 保留 |
| Network 登记测试 | 已有 Dock 登记不被认领或发布；发布失败回滚且保留既有地址 |
| Network 撤回测试 | inner/outer、NAT、全部 QUIC 端点地址撤销；任务退出清理 |
| Network 接收任务测试 | 实际接收循环错误及任务取消后的撤回和重建 |
| `network_lifecycle` | 并发/重复初始化、显式发布、接口元数据、全局 resolver 保留、无网卡事件时的周期撤回与重建、临时 socket 保留 |
| `listener_lifecycle` | 具名服务登记、重复监听、匿名 listen 拒绝、取消后 socket 保留 |
| `quic_roundtrip` | 真实 UDP/TLS/H3、具名复用、两个匿名入口、服务器证书名称不匹配时拒绝、身份摘要、反向请求、停止和恢复监听 |
| `dns_bootstrap` | 全局 resolver 通过 H3 引导解析、不同 origin 端口隔离 |

本机验证（2026-10-02）：`cargo test -p dhttp --lib --tests --offline -- --include-ignored` 全部 43 项通过，其中 33 项单元测试、6 项 bootstrap 配置测试、4 项集成测试，包含真实 UDP/TLS/HTTP/3。测试在允许本机 UDP socket 的环境执行。

网卡测试使用受控快照，不修改宿主系统网卡；Linux/Windows 的真实 down/up、地址增删仍需实机验证。普通 Network 初始化自动装配一次性 NAT 分类及持续 STUN 心跳；不启动独立 DDNS/mDNS 名称发布任务。NAT/心跳回归使用本地脚本化 STUN 响应，不访问线上节点。

2026-10-04 中转上报修正：NAT 心跳得到的 agent/outer 对在外部地址簿中保留为 Mediate，不能仅公布 Direct(outer)。FullCone 映射可以直达；受限/未知分类使用中转。QUIC 仍登记 Direct 与 Mediate 端点地址，DNS 的 E-record 使用现有编码器输出 outer-agent；内部 EndpointAddr Display 保持 agent-outer。AddressBook 内部范围仍仅接受 Direct，外部范围接受有效 Mediate，已有成员/签名/错误变体均不变。
