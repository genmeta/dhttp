# DHTTP

带身份的 HTTP/3 通信库。当前工作区处于**成员和接口声明阶段**，尚不能运行 HTTP 请求或监听服务。

当前工作区已把出站请求的公开类型和 Endpoint 方法签名同步到[顶层接口审查稿](docs/api/top-level-review.md)：`dhttp::Request<()>`、`dhttp::Request<ArcWndBuf>` 和等待响应头的 `dhttp::Response` 已声明。请求构造与网络执行仍为 `todo!()` 占位；编译通过不表示 HTTP 请求已经可用。其他顶层接口仍在审查中。

## 当前接口

- `Endpoint` 只持有自己的名称 `Arc<str>`。池未命中或登记监听时，Network 按名称取得凭据并创建底层 QUIC endpoint；逻辑 Endpoint 不持有连接或底层端点，也不导出状态快照或订阅类型。
- `get/head/delete/options/post/put/patch/request` 接受已解析的 `Uri`，使用调用端点的身份。`Request<()>` 的首次 await 得到带流式 body 的原生响应；`Request<ArcWndBuf>` 的首次 await 得到可写的 `h3x::Request<W>` 和等待响应头的 `dhttp::Response`。泛型参数是预备请求的 body 类型；两者共享请求头编辑方法，具体执行绑定仍待审查。
- `listen` 接受标准 `tower_service::Service<http::Request<Body>>`；`stop_listening` 停止接入，`close` 按绝对 deadline 关闭该端点。
- `DhttpNetwork::init(NetworkConfig)` 显式初始化进程唯一网络；`global` 获取它，`shutdown` 关闭共享资源。`NetworkConfig.listen` 保存监听规则：`ListenConfig::Scope` 按通信范围持续选择全部适用网卡，`ListenConfig::Interface` 指定具体网卡配置。
- `Error/Result/ShutdownReport` 保留底层错误来源及关闭结果，错误格式化与转换尚未实现。

不公开 Endpoint.connect、quic()、h3x 连接别名或自建 Router。应用自行选择路由框架和执行环境。字符串 URL 由调用方用 `.parse()?` 转为 `Uri`；自定义 headers、请求 body 和 trailers 的具体操作仍待审查。

## 消息、身份与服务边界

设计目标是复用 h3x 的 `Request<R/W>`、`Response<R/W>`、`ArcWndBuf` 和 `Trailers`；body 读写沿用 h3x 的 Tokio AsyncRead / AsyncWrite。顶层 `dhttp::Request<B>` 绑定 Endpoint 的身份与执行能力，`dhttp::Response` 只等待响应头并在 await 后交出 `h3x::Response<R>`；不重做 HTTP 消息或 body 状态机。

服务接入使用标准 HTTP Request/Response 与 http-body；`Body` 是现有 UnsyncBoxBody 容器的别名。服务响应 body 保持泛型，服务边界不要求 body 为 Sync。

连接与握手元数据直接使用 `qconn::ArcConnection`、`qtls::LocalAuthority/RemoteAuthority/HandshakeSummary`。按契约，入站 Service 从 request.extensions 读取连接和同一次握手的结果；该适配尚未实现。

## 身份和 home

核心 crate 已移除旧 identity/home 的兼容重导出和直接依赖。`dhttp::home` 只声明内部凭据读取边界，返回已有的 qbase 身份材料。`name`、`certificate` 预留 DHTTP 规则模块，具体函数签名待定，不重新导出旧名称和身份包装。

workspace 中的旧 identity/home crate 仍被 access/log 等组件使用，其迁移未在本轮展开。`access`、`log` 默认不启用。旧 trust verifier 不再作为新顶层接口导出；全局信任注入等待 qconn 契约确定。

当前直接使用相邻 `../dquic` 的 qconn/qtls/qprotocol 等 crate 和相邻 `../h3x` 的消息类型。发布前需要固定可复现的版本或 revision。

## 应用接入边界

Pishoo 组装好 Router 后调用 `endpoint.listen(router)`。DHTTP 只约束标准 Tower Service，处理 HTTP/3、可信握手信息、流式 body、取消和连接生命周期。

WASM 加载与执行、WASI HTTP 适配、配套 OpenAPI、逐 API 授权和身份级沙盒均由 Pishoo 负责。Pishoo 的同一身份下多个应用共享沙盒能力、数据和总预算，每请求独立创建执行实例；这些安排通过 Router 和标准 HTTP 接口与 DHTTP 组合。

DHTTP 不依赖 Wasmtime，不提供 wasm feature、WasmApp、apis() 或私有 WIT 清单，也不解析应用 OpenAPI。业务请求与响应结构由应用和调用方约定，DHTTP 只传递标准 HTTP 消息。职责与生命周期衔接见 [Pishoo 服务接入边界](docs/api/pishoo-service-boundary.md)。

## 全局网络

Network 保存共享连接池、AddressBook 和网卡选择规则，使用 qprotocol 的全局 Dock 登记 socket 并收包；不重复持有 socket 或维护第二套网络状态快照。它不扫描身份目录，也不提供 network.endpoint。

`listen external` 表示监听所有适合 External 的网卡，对应 `ListenConfig::Scope(Scope::External.into())`。按范围监听已经表示全部适用网卡，无需另设 All 选择器。Network 保存原始规则，随系统快照选择具体网卡并绑定地址；端口由内部策略决定，不向调用方开放配置。规则不限制为默认出口网卡；当前没有匹配网卡时仍等待新增或恢复，需要网络路径的请求返回 NetworkUnavailable。

网卡删除或 down 时，Network 撤销对应地址与协议登记、取消 STUN 并释放 socket；新增或 up 时重新评估、绑定并探测。地址或索引变化同样触发更新，未受影响的网卡和 Endpoint/app 登记继续保留。变化处理仍只有接口契约，尚无实现。

按契约，Network 按实际接收网卡/socket 检查来源范围，监听网络变化并恢复资源；仅 External socket 使用现有 bootstrap 域名常量探测 STUN。网络启动、变化监听、重绑、准入和清理均待实现。

Endpoint.close 只清理自身资源；network.shutdown 使用同一个绝对 deadline 关闭全进程网络。

## 检查

```sh
cargo fmt --all -- --check
cargo check -p dhttp --no-default-features --all-targets
cargo check --workspace --all-targets --all-features
```

## SDK

旧 Node.js/Python 包装与发布工作流已在重构中移除。新的语言绑定等待 Rust 接口稳定后重建。
