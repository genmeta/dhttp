# DHTTP

带身份的 HTTP/3 通信库。当前工作区已实现 Network 初始化时的地址绑定和服务监听接入；出站 HTTP 请求尚未实现，入站 HTTP/3 端到端互通仍需验证。

当前工作区已把出站请求的公开类型和 Endpoint 方法签名同步到[顶层接口审查稿](docs/api/top-level-review.md)：`dhttp::Request<()>`、`dhttp::Request<ArcWndBuf>` 和等待响应头的 `dhttp::Response` 已声明。请求构造与网络执行仍为 `todo!()` 占位；编译通过不表示 HTTP 请求已经可用。其他顶层接口仍在审查中。

## 当前接口

- `Endpoint` 只持有自己的名称 `Arc<str>`。池未命中或登记监听时，Network 按名称取得凭据并创建底层 QUIC endpoint；逻辑 Endpoint 不持有连接或底层端点，也不导出状态快照或订阅类型。
- `get/head/delete/options/post/put/patch/request` 接受已解析的 `Uri`，使用调用端点的身份。`Request<()>` 的首次 await 得到带流式 body 的原生响应；`Request<ArcWndBuf>` 的首次 await 得到可写的 `h3x::Request<W>` 和等待响应头的 `dhttp::Response`。泛型参数是预备请求的 body 类型；两者共享请求头编辑方法，具体执行绑定仍待审查。
- `listen(scopes, app)` 为每个 Endpoint 指定来源范围，并接受标准 `tower_service::Service<http::Request<Body>>`，通过 Network 的接收回调驱动入站 HTTP/3 请求；取消 listen future 会撤销登记。`stop_listening` 和端点级 `close` 尚未实现。
- `DhttpNetwork::init(NetworkConfig)` 显式初始化进程唯一网络；`global` 获取它，`shutdown` 关闭共享 socket 和连接池。`NetworkConfig.listen` 在初始化时选择适用网卡并绑定地址；持续监听网卡变化、完整的监听撤销和交换任务清理仍待实现。
- `Error/Result/ShutdownReport` 保留底层错误来源及关闭结果，错误格式化与转换尚未实现。

不公开 Endpoint.connect、quic()、h3x 连接别名或自建 Router。应用自行选择路由框架和执行环境。字符串 URL 由调用方用 `.parse()?` 转为 `Uri`；自定义 headers、请求 body 和 trailers 的具体操作仍待审查。

## 消息、身份与服务边界

设计目标是复用 h3x 的 `Request<R/W>`、`Response<R/W>`、`ArcWndBuf` 和 `Trailers`；body 读写沿用 h3x 的 Tokio AsyncRead / AsyncWrite。顶层 `dhttp::Request<B>` 绑定 Endpoint 的身份与执行能力，`dhttp::Response` 只等待响应头并在 await 后交出 `h3x::Response<R>`；不重做 HTTP 消息或 body 状态机。

服务接入使用标准 HTTP Request/Response 与 http-body；`Body` 是现有 UnsyncBoxBody 容器的别名。服务响应 body 保持泛型，服务边界不要求 body 为 Sync。

连接与握手元数据直接使用 `qconn::ArcConnection`、`qtls::LocalAuthority/RemoteAuthority/HandshakeSummary`。入站 Service 可从 request.extensions 读取连接和同一次握手的结果。

## 身份和 home

核心 crate 不再依赖旧 `dhttp-identity`，而是复用独立 `dhttp-home` 的名称规范化和目录定位。`dhttp::home` 按 `DHTTP_HOME` 或 `~/.dhttp` 读取身份目录中的 `ssl/fullchain.crt`、`ssl/privkey.pem` 和 `ssl/ocsp.der`，返回已有的 qbase 身份材料。`dhttp-home` 负责扫描 `DHTTP_HOME/<身份名>/ssl` 下的身份；`certificate` 规则模块仍待完善。

workspace 中的旧 identity/home crate 仍被 access/log 等组件使用，其迁移未在本轮展开。`access`、`log` 默认不启用。旧 trust verifier 不再作为新顶层接口导出；全局信任注入等待 qconn 契约确定。

当前直接使用相邻 `../dquic` 的 qconn/qtls/qprotocol 等 crate 和相邻 `../h3x` 的消息类型。发布前需要固定可复现的版本或 revision。

## 应用接入边界

Pishoo 组装好 Router 后调用 `endpoint.listen(scopes, router)`。DHTTP 只约束标准 Tower Service，处理 HTTP/3、可信握手信息、流式 body、取消和连接生命周期。

WASM 加载与执行、WASI HTTP 适配、配套 OpenAPI、逐 API 授权和身份级沙盒均由 Pishoo 负责。Pishoo 的同一身份下多个应用共享沙盒能力、数据和总预算，每请求独立创建执行实例；这些安排通过 Router 和标准 HTTP 接口与 DHTTP 组合。

DHTTP 不依赖 Wasmtime，不提供 wasm feature、WasmApp、apis() 或私有 WIT 清单，也不解析应用 OpenAPI。业务请求与响应结构由应用和调用方约定，DHTTP 只传递标准 HTTP 消息。职责与生命周期衔接见 [Pishoo 服务接入边界](docs/api/pishoo-service-boundary.md)。

## 全局网络

Network 保存共享 HTTP/3 连接池、AddressBook 和网卡选择规则；它持有已绑定 socket 的生存引用，由 qprotocol 的全局 Dock 负责收包。出站连接按目标复用，入站 Server 角色连接在同一个 h3x 池中登记，供关闭时统一清理。它不扫描身份目录，也不提供 network.endpoint。

`listen external` 表示监听所有适合 External 的网卡，对应 `ListenConfig::Scope(Scope::External.into())`。按范围监听已经表示全部适用网卡，无需另设 All 选择器。Network 保存原始规则，随系统快照选择具体网卡并绑定地址；端口由内部策略决定，不向调用方开放配置。规则不限制为默认出口网卡；当前没有匹配网卡时仍等待新增或恢复，需要网络路径的请求返回 NetworkUnavailable。

Network 订阅系统网卡变化并重读快照：网卡删除或 down 时撤销对应地址与协议登记并释放 socket；新增或 up 时重新评估和绑定。地址或索引变化同样触发更新，未受影响的绑定保留。External 仅允许所选绑定接收外网来源的包，不触发 STUN 探测或外部地址发布。

Network 在实际接收 socket 上检查来源范围，qconn 再检查该 Endpoint 的监听范围；qconn 的 `listen` 回调提供已接受连接，Network 将它构造成 Server 角色的 H3 connection，并在 TLS 握手中配置 `h3` ALPN。出站连接池工厂尚未接线，网络初始化成功不表示出站 HTTP 请求可用。入站 HTTP/3 互通仍需端到端验证。

Endpoint.close 只清理自身资源；network.shutdown 使用同一个绝对 deadline 关闭全进程网络。

## 检查

```sh
cargo fmt --all -- --check
cargo check -p dhttp --no-default-features --all-targets
cargo check --workspace --all-targets --all-features
```

## SDK

旧 Node.js/Python 包装与发布工作流已在重构中移除。新的语言绑定等待 Rust 接口稳定后重建。
