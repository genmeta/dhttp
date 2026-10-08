# Node.js / Python SDK 恢复接口草案

日期：2026-10-08。

用户要求将 Node.js / Python SDK 恢复纳入本次发布准备。本文梳理实现需要的接口，
描述完整恢复目标；公共绑定层和 Node/Python 高层包装已恢复首版，本机安装及跨进程收发已验收。
默认 H3 DNS/mDNS、名称发布和多平台发行仍待实现。
实施状态见 [api/README.md](../../api/README.md)，本文不替代当前 Rust 核心的接口契约。
以现有 Endpoint、Anonymous、共享 Network、标准 HTTP Body / Tower Service 为基础。

## 1. 分层和发布范围

| 层 | 责任 |
| --- | --- |
| `dhttp` Rust 核心 | 身份请求、匿名请求、共享 QUIC/H3 网络、连接复用、服务接入、流读写和错误 |
| `dhttp-home` / qtls | 名称和 profile、凭据读取、证书字段、已验证身份与签名能力 |
| `dyns` | H3 DNS 和 mDNS 协议、查询和名称发布 |
| `dhttp-api` 公共绑定层 | 默认发现装配、名称发布维护、有限缓冲的流桥接、任务所有权和语言中立错误映射 |
| N-API / PyO3 | Node / Python 事件循环与 Rust 异步任务、回调和字节数据的转换 |
| JS / Python 包装 | fetch / request、Response、headers、json/text、语言原生取消和上下文管理 |

当前 dyns 的 H3 feature 已依赖 dhttp。因此默认 DNS 装配放在绑定层，
由它依赖 dyns 和 dhttp；不在 dhttp 核心反向依赖 dyns 的 H3 feature。
Node 与 Python 共享装配与生命周期语义，不分别实现发现和发布算法。

本次恢复的目标是高层客户端、流式请求与响应、handler 服务端、可信身份和
默认名称发现/发布。旧 raw Connection / MessageReader / MessageWriter 不作为首版稳定接口。
HTTP 路由、默认身份设置、证书签发、WebTransport 和 1xx 中间响应另行扩展。

## 2. Rust 核心需要提供的能力

| 能力 | 当前接口 | 状态 / 处理 |
| --- | --- | --- |
| 网络初始化 | `DhttpNetwork::init/global` | 已有；保持进程共享、初始化幂等 |
| 解析器注入 | `resolve::Resolver::add` | 已有；SDK 默认装配只执行一次，普通域名与 DHTTP 名称正确分流 |
| 地址事件 | `AddressBook` 快照和 DDNS/mDNS 订阅、`inner_bindings` | 已有；供 SDK 发布维护使用，语言用户不必管理 socket |
| 具名端点 | `Endpoint::load/name` | 已有；显式名称，不隐式降级为匿名 |
| 指定 profile 加载 | `Endpoint::load_from(path)` | 已实现；沿用 home profile 校验与相同凭据加载流程 |
| OCSP 更新 | `Endpoint::reload() -> Result<Endpoint>` | 已有；返回新端点，证书链变化仍需重启 |
| 本端身份 | `Endpoint::local_authority` | 已有；共享已加载签名能力，不向语言导出私钥 |
| 匿名出站 | `Anonymous`、`Request::new` | 已有；无需 home，无监听能力，仍验证远端 |
| 标准请求接入 | `Endpoint::from_request` / `Anonymous::from_request` | 已有；绑定层先组装 `http::Request`，保留多值 headers 和扩展 |
| 对端固定 | `Request::expect_remote_owner_hash` | 已有；发送前检查真实连接，池复用也检查 |
| 空请求 | `Request<Empty>` await | 已有；返回 `http::Response<Body>` |
| 上传 | `Request<WndBuf>` await | 已有；返回 writer 和独立 response future |
| 上传流控制 | `RequestWriter: AsyncWrite + CancelStream` | 已有；shutdown 完成上传，Drop 取消未完成上传 |
| 请求 trailers | builder / writer 的 trailer、append_trailer | 已有；shutdown 时冻结和发送 |
| 接收流 | `Body: http_body::Body` | 已有；DATA、trailers、错误、EOF，通过丢弃取消未完成接收 |
| 服务接入 | `Endpoint::listen(scopes, Tower Service)` | 已有；接收标准请求，返回标准响应 Body |
| 监听撤销 | 已登记的 `ListenFuture` Drop | 已有；撤销新请求服务接入，保留已有请求和共享连接 |
| 握手身份 | 入站 `HandshakeSummary`、出站响应 `RemoteAuthority` | 已有；绑定层复制可信元数据，不能从 header 推断 |
| 错误 | `Error` / 原始 source | 已有；绑定层映射稳定语言错误，不从错误字符串猜类型 |

`Endpoint::load_from(path)` 与配套的 `reload_from(path)` 已实现，共用凭据装配与重载校验。
不要在多身份 SDK 运行期间修改进程环境变量，也不要在 N-API 和 PyO3 各复制凭据装配。

SDK 恢复不需要新增 Rust Network shutdown、Exchange 注册表、逐身份连接关闭、
原生流公开接口或 `Request<Body>` await。上传桥接使用现有 WndBuf/RequestWriter。
Node/Python 的 endpoint close 只关闭其 SDK 所有的请求、监听和发布任务，不关闭共享 Network。

## 3. 语言高层接口

以下是建议接口形状。命名在实际绑定实现时统一，不声称兼容旧 SDK 全部签名。

| 能力 | Node.js | Python |
| --- | --- | --- |
| 可选显式初始化 | `await init(options)` | `await init(options)` |
| 具名端点 | `await Endpoint.load(name, options)` | `await Endpoint.load(name, **options)` |
| profile 加载 | `await Endpoint.loadFrom(path, options)` | `await Endpoint.load_from(path, **options)` |
| 本端身份 | `endpoint.name`, `endpoint.localAuthority()` | `endpoint.name`, `endpoint.local_authority()` |
| OCSP 更新 | `await endpoint.reload()` | `await endpoint.reload()` |
| 具名请求 | `endpoint.fetch(input, init)` | `endpoint.request(method, url, **options)` |
| 便捷方法 | fetch 指定 method | `get/head/post/put/patch/delete/options` |
| 匿名请求 | `Anonymous.fetch(input, init)` | `Anonymous.request/get/...` |
| 服务接入 | `await endpoint.listen(scopes, handler)` | `await endpoint.listen(scopes, handler)` |
| 停止服务 | `await listener.close()` | `await listener.close()` / async context manager |
| SDK 端点关闭 | `await endpoint.close()` | `await endpoint.close()` / async context manager |

`init` 可显式调用；首次 fetch/listen 可以按默认配置幂等初始化。
初始化配置作用于进程，不伪装为每个 Endpoint 私有网络配置。
端点加载本身不发布名称；仅提供服务时启动所需名称发布。

Node 对齐 Web Request / Response / Headers / ReadableStream，附加可信 authority 和 trailers。
Python 保留 `dhttpy` 包名，提供 ClientResponse、ServerRequest、Response 和多值 Headers；
请求可 await，也可通过 async with 管理响应释放。
Node 的 ESM/CommonJS 和 TypeScript 声明、Python 的类型标注均属于恢复交付内容。

## 4. 请求、响应与流

请求输入至少支持 method、URL、重复 headers、字节/文本请求体、异步字节流、
请求 trailers、对端 ownerHash 约束、取消以及可选总期限。
Node 的 AbortSignal 和 Python 的任务取消/timeout 由绑定层转换为同一清理行为。
json 编码与 Content-Type 便捷设置属于语言包装，不进入 Rust 核心。

| 消息对象 | 必须提供 |
| --- | --- |
| 客户端响应 | status、headers、流式 body、trailers、已验证 remote authority、释放接口 |
| 入站请求 | method、URL、headers、流式 body、trailers、已验证本端/对端身份 |
| 服务响应 | status、重复 headers、有限内容或流式 body、trailers |
| 身份能力 | name、证书链、公钥、SKI/ownerHash；本端 sign、证书规则 verify |
| 错误 | 稳定 code、message、cause；存在时保留协议错误码 |

字节流以消费速度驱动生产者，使用有限缓冲；不得通过无限队列或完整读取来桥接。
大请求先启动上传，再消费语言流；不能在有界 WndBuf 里预填整个 body 后才开始发送。
响应头可先于完整上传返回。读取异常必须作为流错误传播，不能转换为正常 EOF。
trailers 必须来自 EOF 前的 trailer frame，取消/失败不能伪造成功 trailers。
多值 header/trailer 不按普通字典覆盖，headers 与 trailers 分开表示。

Node 高层响应的 `trailers` 可为 Promise，Python 可为 `await response.trailers()`。
读取同一 body 不允许并发消费；read/text/json 是同一 body 的便捷消费方式。
stream cancel/release 必须清理 native 接收句柄，不能只关闭语言侧队列。

动态上传 trailers 可以在 SDK 的显式流式上传入口暴露 writer 的对应操作；
fetch / request 支持静态值或上传结束时获得 trailers 的约定，最终再执行 shutdown。
服务响应 Body 由适配器生成 DATA/trailers 帧，复用 h3x 的标准 Body 发送路径。

## 5. 取消与生命周期契约

绑定层持有其上传 pump、响应 future、响应 Body 和监听/发布任务，负责语言侧取消。

| 时机 | 必须执行的清理 |
| --- | --- |
| 响应头前 AbortSignal / task cancel / deadline | 丢弃请求/响应 future，取消上传 pump 和 writer，清理已取得的接收方向 |
| 响应头后用户取消 | 停止本次响应消费与未完成的 SDK 上传，保持其他请求可用 |
| 正常 body EOF | 交付 trailers，释放接收资源；不将成功读取自动解释为上传失败 |
| 上传 producer 抛错 | 取消 native 上传，让 SDK 请求或后续流操作观察失败，清理 producer |
| handler 抛错且尚未返回响应 | 适配器生成 500；诊断留在日志，不把异常细节写进响应 |
| 服务 body 抛错 | 终止当前流，不另发 500，也不关闭其他交换 |
| listener close | 先停止新接入，停止名称续期并清理自有 mDNS 名称，再按 SDK 约定排空/取消自有 handler 任务 |
| endpoint close | 拒绝该 SDK 句柄新操作，回收它拥有的请求、listener、发布维护；不影响别的端点 |

close 幂等。finalizer / GC 只能作为补充，不能作为资源正确回收的唯一方式。
监听登记错误直接返回，不能返回一个实际上没有监听的成功句柄。
listener close 不能承诺清空共享连接；已有交换按其任务所有权处理。
如提供排空，deadline 到期后取消本 listener 的剩余 handler，避免永久等待。
公共层已确定默认无总期限、close 立即取消不隐式排空；Clone 共享所有权，独立加载各自管理任务，同名仅允许一个 listener。详见 SDK 文档。

`reload` 在 SDK 中应用返回的新 Rust Endpoint，并更新自有名称发布的签名能力；
Rust core 不会自动修改其他已克隆句柄。失败保留原端点；证书/私钥轮换仍需重启。
自动 OCSP 获取/续期不是当前 reload 自带行为。

## 6. 默认发现与发布

默认装配 System DNS、DHTTP H3 查询和 mDNS，处理 bootstrap origin 的普通域名解析，
避免 H3 DNS 请求再次递归进入 DHTTP 查询。解析源在共享进程内安装一次。
监听 scopes 决定 SDK 发布到哪些名称发现范围，实际端口来自 AddressBook。

SDK 持有真实监听成功后的发布维护，订阅地址变化并更新内网 mDNS/外网 DDNS。
没有可发布地址时停止续期；有地址后恢复维护。关闭时 DDNS 记录自然过期，
自有 mDNS 名称停止应答；不取消其他 Endpoint 的发现资源。
复用协议客户端与现有发布行为，发布失败要可观察并重试。
listen 返回表示服务登记成功，不能把它解释为公网名称已经发布成功。
SDK 应提供发布状态或事件，使调用方能区分 listening 与 discoverable。

SDK 默认装配依赖共享 Network 的 NAT 维护。发布前需补齐首次 STUN 节点发现失败后的重试：
当前发现失败会结束 nat_probe，绑定仍存活时没有恢复入口。

## 7. 交付验收

两种语言分别覆盖：具名/匿名 GET，超过窗口容量的上传，早响应，双向请求，
重复 headers/trailers，可信对端和 ownerHash 不匹配，上传/响应 producer 错误，
各阶段取消，handler 异常，重复监听和 close，OCSP reload，以及两身份隔离。

在独立进程验证默认发现、mDNS、名称发布的地址更新及关闭收尾；
跨设备公网/NAT/relay 验收单独执行，不能用回环连接替代。
验证 Node 进程正常退出、Python asyncio 循环关闭和清理后无遗留任务。
安装后分别跑实际客户端/服务端 smoke，覆盖发布的 Node 平台包和 Python wheel。

实施顺序：修复当前 Rust 测试/依赖基线 → 公共绑定与流桥接 → Node/Python 高层接口 →
默认发现和监听发布 → 取消/reload/错误回归 → 打包与跨进程验收。
