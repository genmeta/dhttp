# DHTTP 顶层接口审查稿

> 历史设计：本轮 h3x/dhttp/Pishoo 对接及结构成员以 [三仓接口冻结 v1](../../../pishoo/design/README.md) 和 [dhttp 结构清单](../../../pishoo/design/dhttp-interfaces.md) 为准。本文保留历史讨论，不作为本轮实现依据。

状态：接口审查与实现同步中。出站类型 `dhttp::Request<()>`、`dhttp::Request<ArcWndBuf>`、`dhttp::Response` 和 Endpoint 请求方法的签名已写入代码；Network 的配置校验、绑定监测与关闭已开始实现，Endpoint.listen 已接入 qconn 回调和入站 H3 服务驱动。出站请求构造仍为 `todo!()`，入站互通尚未端到端验证，不表示可实际收发。本文按当前讨论收敛；与早期架构提案冲突时，以本稿列出的约束为准。下方省略方法体的 Rust 是接口记法。WASM、OpenAPI 和身份沙盒归 Pishoo，DHTTP 只接收标准应用服务。证书辅助函数继续留待审查。本稿按最简单的目标模型设计，不以旧 identity/home API 或 gmutils 兼容为约束；gmutils 可后续适配。home 不在本轮展开设计。

## 1. 已确定的边界

- Endpoint 只持有自己的 `Arc<str>` 名称；连接池保存已建立的 h3x 连接，Network 在未命中时按名称取得凭据并构造底层建连能力。
- DhttpNetwork 通过配置显式初始化，是进程全局对象；所有身份共享 interface 和一个 h3x 连接池。Network 负责监听网络变化并维护这些共享资源。
- home 本轮只作为目录定位和凭据读取的辅助模块，不展开配置、缓存、扫描注册表或生命周期设计；不为保留旧调用方而维持重复身份模型。
- Endpoint 保留 load(servername) 简单入口，只保留规范化名称；不接受 home 或底层材料参数，不暴露 quic()。Network 在发起新连接或登记监听时获取本端凭据，不持有身份目录，也不提供 network.endpoint。
- 网络配置保存按通信范围监听或指定具体网卡的规则，并规定允许的来源范围；`listen external` 持续覆盖所有适合 External 的网卡，Network 处理网卡新增、删除和 up/down。Network 按实际 socket 统一检查入口，Endpoint.listen(scopes, app) 再指定该身份允许的来源范围。External 仅允许对应绑定接收外网来源的包，不触发 STUN 探测或外部地址发布。
- Pishoo 自己发现 Server、解释应用目录和策略；若需显式凭据路径，由 Pishoo 确定凭据来源并在接入阶段交给 Network，不把路径或凭据放进逻辑 Endpoint。
- 不在 Endpoint 里保存身份材料、QUIC endpoint、连接、state、profile 或 network。
- HTTP 消息、body、trailers、异步读写优先复用 h3x，不重做一套 dhttp 消息。get 等方法同步返回绑定当前 Endpoint 的 `Request<B>`；POST 等请求还返回等待响应头的 `dhttp::Response` future，await 后交付原生 `h3x::Response<R>`。底层两个方向始终按流式读写处理；执行对象如何持有 h3x 请求并绑定连接尚待审查。
- “交换”只表示一次请求及响应的完整生命周期；不公开 `dhttp::Exchange`、`ExchangeOutcome` 或独立取消订阅接口。h3x 提供流方向的显式取消，dhttp 在内部协调任务与关闭。
- 本端、对端身份直接使用 qtls 类型；不定义 PreparedIdentity、RequestContext 或 PeerIdentity。
- 服务接入只约束 tower_service::Service 和标准 HTTP body；不依赖、重导出或指定 Axum，也不自建 Router。Pishoo 负责 WASM 运行、WASI HTTP 适配、OpenAPI、授权与身份沙盒，组装好 Router 后交给 Endpoint.listen(scopes, router)。
- 本稿只覆盖 Rust 核心公共面。SDK、WebTransport 和身份轮换暂不扩展；匿名客户端复用情况单列核对，不新建身份包装。

## 2. 顶层导出

```rust
pub use endpoint::Endpoint;
pub use network::{DhttpNetwork, NetworkConfig, ListenConfig};
pub use qconn::{Scope, Scopes};
// 服务边界使用现有 body 容器的别名，不定义新的消息或 body 状态机。
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BoxError>;
pub use error::{Error, Result, ShutdownReport};

// dhttp::Request<B> 是出站执行对象；dhttp::Response 等待响应头。
// 已收到的原生消息写作 h3x::Request<W> / h3x::Response<R>。
pub use client::{Request, Response};
pub use h3x::{R, W, ArcWndBuf, Trailers};
pub use qconn::ArcConnection;
pub use qtls::{LocalAuthority, RemoteAuthority, HandshakeSummary};
pub use http::{Method, Uri, StatusCode, HeaderMap, HeaderName, HeaderValue};

// 只保留必要的本地加载与 DHTTP 规则，不重导出旧 identity 模型。
pub mod home;
pub mod name;
pub mod certificate;
#[cfg(feature = "access")]
pub use dhttp_access as access;
#[cfg(feature = "log")]
pub use dhttp_log as log;
```

`qconn` 是当前本地 dquic 新实现所在的 crate，尚未通过 `dquic` 门面导出。底层 TLS 类型统一使用 qtls 的导出，避免混用它使用的 rustls fork 与 crates.io rustls 类型。旧 `trust` 模块的 rustls verifier 暂不纳入这份新顶层契约；全局信任配置需等 qconn 明确注入接口后再定。

## 3. Endpoint

```rust
#[derive(Clone)]
pub struct Endpoint {
    name: Arc<str>,
}

impl Endpoint {
    // 解析并验证名称；仅保留名称，不保留凭据或传输对象。
    pub async fn load(servername: impl AsRef<str>) -> Result<Self>;
    pub fn name(&self) -> &str;

    // 出站请求同步构造；B 是请求 body 的类型，R/W 只用于 h3x 原生消息。
    // Uri 由调用方先解析，例如 endpoint.get("https://example.com/".parse()?)。
    pub fn get(&self, uri: Uri) -> Request<()>;
    pub fn head(&self, uri: Uri) -> Request<()>;
    pub fn delete(&self, uri: Uri) -> Request<()>;
    pub fn options(&self, uri: Uri) -> Request<()>;
    pub fn post(&self, uri: Uri) -> Request<ArcWndBuf>;
    pub fn put(&self, uri: Uri) -> Request<ArcWndBuf>;
    pub fn patch(&self, uri: Uri) -> Request<ArcWndBuf>;
    pub fn request(&self, method: Method, uri: Uri) -> Request<ArcWndBuf>;

    // 只约束标准 Service，不依赖任何具体 HTTP 路由框架。
    pub async fn listen<S, B>(&self, scopes: impl Into<Scopes>, app: S) -> Result<()>
    where
        S: tower_service::Service<http::Request<Body>, Response = http::Response<B>>
            + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
        B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<BoxError>;
    pub async fn stop_listening(&self) -> Result<()>;

    // 关闭这个逻辑 Endpoint 对应的 HTTP 接入、请求和池条目。
    pub async fn close(&self, deadline: Instant) -> Result<ShutdownReport>;
}
```

Endpoint 只提供 `load(servername)` 作为命名入口，实例只保存自己的名称，不经过旧 Identity、DhttpName 或 authority traits 的转换链，也不保留 gmutils 兼容构造接口。池命中时复用已有 h3x 连接；未命中时 Network 用名称调用轻量 home 凭据读取，构造 qconn::QuicEndpoint 并建连。监听登记时同样由 Network 准备底层身份及服务器参数。仅凭远端 URL 不足以建连，池工厂还必须取得本端名称。

独立 `dhttp-home` 负责名称规范化、`DHTTP_HOME/<身份名>` 身份目录扫描和定位，并统一定义 `ssl/`、`db/`、`apps/`、`public/`、`logs/` 与 `config.db` 的路径。它读取身份凭据；核心 `dhttp::home` 使用这些接口装配底层端点。Pishoo 从统一路径读取自己的配置和应用，daccess 从统一路径管理权限库；各组件负责自己文件的内容和生命周期。`load` 保持简单形状；get/post 等同步返回可配置、可 await 的请求。

listen 登记该 Endpoint 的应用和允许的来源范围。Network 按实际接收 interface/socket 的配置检查入口，qconn 再按该 Endpoint 的 scopes 检查来源；两层检查均通过才交付连接和请求。不因读取凭据自动监听，Endpoint 对象本身不保存 scopes。

`stop_listening` 只停止新请求接入并撤销服务发布；已接入交换继续，端点仍能主动发起请求，也可再次 listen。取消 listen future 同样需要停止准入，并交由全局网络清理登记。

`close` 是最终关闭，影响共享同一个名称 Arc 的 Endpoint 克隆；后续请求返回 EndpointClosed。关闭登记和任务跟踪在全局网络内部维护，不增加 Endpoint.state。独立加载的同名 Endpoint 具有不同 Arc 实例，不因关闭其中一个而误关另一个的资源。

## 4. 请求消息与执行绑定：待审查

目标调用形状（`body` 是请求体写入端；第二例的 `response` 是 `dhttp::Response`）：

```rust
let response: h3x::Response<R> = endpoint.get("https://example.com/".parse()?).header(...).await?;
// response 的 body 仍可逐块读取。

let (mut body, response) = endpoint.post("https://example.com/upload".parse()?).header(...).await?;
body.write_all(chunk).await?;
body.shutdown().await?;
let response: h3x::Response<R> = response.await?;
```

GET、HEAD、DELETE、OPTIONS 的便捷调用按无请求体处理：首次 await 发送请求头、结束请求写入方向并等待响应头。POST、PUT、PATCH 的便捷调用按调用方写请求体处理：首次 await 在建连、发送请求头后返回请求 body 写入端和响应等待端，不等待响应头。需要给其他方法写请求体时使用显式 `request(method, url)`，其首次 await 也返回这一对结果。两类调用都不区分“普通”与“流式”底层消息；响应 body 始终可流式读取。空请求体也要显式结束其写入方向，否则等待请求结束的服务端可能一直不返回响应。

### 4.1 `Request<B>` 的类型设计

`B` 是预备请求的 body 类型，而不是 h3x 的读写方向。`()` 表示空 body；`ArcWndBuf` 是可写的有界流式 body。`Request<()>` 首次 await 结束空请求方向并等待响应；`Request<ArcWndBuf>` 首次 await 返回可写的原生 `h3x::Request<W>` 和独立响应 future。不定义额外的 `RequestBody`。`dhttp::Request<B>` 负责发送前的请求编辑与 Endpoint 执行绑定；发送时把标准 `http::Request<ArcWndBuf>` 转为原生 `h3x::Request<W>`。`R/W` 只用于 h3x 的消息方向。

```rust
pub struct Request<B> {
    endpoint: Endpoint,
    message: http::Request<B>,
}

impl<B> Request<B> {
    // header、append_header、method、uri 等请求头编辑方法共用同一实现。
    // 编辑方法保留 B；修改 HTTP method 不会偷偷改变 await 的输出类型。
}

impl Request<()> {
    pub fn with_body(self) -> Request<ArcWndBuf>;
}

impl Request<ArcWndBuf> {
    pub fn without_body(self) -> Request<()>;
}

impl IntoFuture for Request<()> {
    type Output = Result<h3x::Response<R>>;
    // IntoFuture 的具体类型待执行接缝确定。
}

impl IntoFuture for Request<ArcWndBuf> {
    type Output = Result<(h3x::Request<W>, Response)>;
    // IntoFuture 的具体类型待执行接缝确定。
}
```

上面是接口记法，并非当前可编译实现。`h3x::Request<W>` 已实现 Tokio `AsyncWrite`，写入受其 `ArcWndBuf` 的有界缓冲背压约束；`shutdown()` 结束请求方向，trailer 必须在此之前设置。`with_body()` 允许带 body 的 GET 等请求，`without_body()` 明确发送空 body 的 POST；`request(method, uri)` 默认返回可写 body 的形状。URI 类型由调用方提供；字符串应使用 `.parse()?` 转为 `Uri`，不在请求对象里延迟保存解析错误。

### 4.2 `Response` 的类型设计

`dhttp::Response` 是一次性交付响应头的 future，不是另一套 HTTP 响应消息。它只持有一个已经启动的异步任务，该任务驱动 `read_response`，await 后交出原生 `h3x::Response<R>`；后续通过原生消息流式读取 body。它不实现 `AsyncRead`，不提供 status/header 的预读取接口，也不允许 Clone。

```rust
#[must_use = "await the response or cancel the exchange"]
pub struct Response {
    task: tokio::task::JoinHandle<Result<h3x::Response<R>>>,
}

impl Future for Response {
    type Output = Result<h3x::Response<R>>;
    // poll task；JoinError 转成 dhttp 错误。
}

impl Drop for Response {
    // task.abort()；任务内部的取消守卫负责通知交换并停止响应读取。
}
```

任务须在首次 `Request<ArcWndBuf>.await` 返回前启动；`Response.await` 只等待任务结果，不能负责启动读取。否则调用方先写 body、稍后才 await 响应时，响应读取不会推进。`read_response` 读到最终响应头后返回 `h3x::Response<R>`，并继续用 h3x 的后台任务读取响应 body。

取消契约分两段：响应头交付前，`Response::drop` 调用 `task.abort()`；被取消的读取任务对该 QUIC 接收方向发送 STOP_SENDING，并把本次交换标记为取消。响应头交付后，`Response` 已完成，取消责任转给原生响应 body；最后一个读取所有者未读到 EOF 就丢弃时，也要停止接收方向并回收交换。当前 h3x 的 `H3ReadStream::drop` 只调用 `finish()`，底层 Reader 的 Drop 也不会代替显式 `stop()`，因此不能只给 `Response` 增加 `task.abort()`。所需内部接缝见第 4.6 节。

`Request<()>` 立即结束空请求方向，再等待同一响应结果，直接返回 `h3x::Response<R>`。`Request<ArcWndBuf>` 在请求头已交给底层写入后返回 `(h3x::Request<W>, dhttp::Response)`，不等待上传完成或响应头；body 与响应继续并发推进。若首次 await 等待响应头，服务端先等待完整上传时就会卡住。当前 h3x 的 `write_request` 只在整个请求发送完后完成，尚不能报告“请求头已发送”，因此实现这条返回时机需要明确的写入接缝。

返回原生 `h3x::Request<W>` 有两个需要解决的行为：它的 header/URI setter 在请求头发送后仍可调用，但修改已不能影响线上请求；它的 Clone 和 Drop 也没有“最后一个调用方写入句柄消失就取消上传”的语义。若坚持直接返回该类型，必须明确禁止或调整发送后修改头部的接口，并为未 `shutdown` 就丢弃请求体提供受控取消接缝；不能把这种修改静默当成成功。具体 h3x 接缝一起审查。当前 dhttp 代码只同步了请求类型签名，网络执行仍是占位。顶层调用不增加 `open()`、`send()`。

### 4.3 当前 h3x Request 不能独立完成交换

本地 h3x::Request<W> 持有 HTTP 消息头、ArcWndBuf、Trailers 和读写方向标记。它没有绑定连接或请求流，也没有取得这些资源的执行入口。W 表示消息可写方向，并不表示它已经持有 QUIC 发送流。

write_request 消费请求消息；read_response 则需要同一交换的接收流、请求方法及连接的 QPACK。请求 body 缓冲无法提供这些资源。因此，仅增加 `impl IntoFuture for h3x::Request<W>` 无法让 await 自动取得对应响应。

### 4.4 需要明确的执行接缝

无论执行对象放在 dhttp 还是 h3x，它都必须绑定当前 Endpoint 的执行能力：执行时取得连接、打开双向流，并配对发送请求和读取响应。它不必在同步构造时已经持有真实流，但必须知道如何取得并驱动这一对流。需要调用方写 body 时，首次 await 还必须交出可继续写入的请求方向，并独立驱动响应方向。

dhttp 提供使用当前 Endpoint 身份及全局连接池的逻辑；h3x 不反向依赖 dhttp，也不接管 home、DHTTP 名称或网络策略。绑定方式、绑定后的类型表达、错误传递、消费及 Clone 语义仍需审查，本文暂不增加回调 trait、泛型参数或新的公共包装类型。h3x 当前的协议错误也不能直接当作能够保留所有 dhttp 建连错误的执行错误。

若 h3x 保持纯消息类型，dhttp 的请求执行对象可承载 Endpoint 上下文并驱动原生 h3x 消息；若执行对象放进 h3x，也需表达上述两种 IntoFuture 输出及 dhttp 建连错误。具体放置仍需审查，但不能改变上面的直接 await 调用形状。不能同时假定请求保持完全未绑定、没有其他执行入口，却能独立 await 完成收发。

### 4.5 执行与流式约束

无论最终采用哪种绑定方式，执行方都必须完成：

1. 校验请求，使用调用 Endpoint 的身份从全局池取得 h3x 连接。
2. open_bi 获得同一交换的配对读写流。
3. 通过 write_request 发送消息，通过 read_response 读取响应；上传与响应接收能够并发推进。返回请求 body 写入端前，不等待响应头或完整上传。
4. 无请求体的便捷调用返回 h3x::Response<R>；需调用方写请求体的调用先返回写入端与响应 future，后者 await 返回 h3x::Response<R>。网络层继续管理未完成上传、响应 body、取消和任务回收。

请求头、body 和 trailers 复用 h3x 的消息操作与有界缓冲。请求 body 写入端遵守异步写入和背压，结束写入只关闭请求方向，不关闭响应方向；不能要求调用方在发送开始前把整个 body 写入有界缓冲。返回响应头不代表整个交换已经结束。

### 4.6 h3x 必需的启动与取消接缝

先区分当前已有能力：`read_response` 读到最终响应 HEADERS 后已经 `tokio::spawn` 后台 body 读取任务并返回 `h3x::Response<R>`；h3x 的流也已有显式 `StopSending` / `CancelStream` 操作。以下需要补的是请求写入的返回时机，以及在调用方丢弃 body 或任务时自动调用这些取消操作的所有权接缝，不增加 dhttp 顶层公开类型。dhttp 负责任务启动、错误映射和交换登记。

1. **请求头发送完成信号**：当前 `write_request` 在写完 HEADERS 后仍在同一个 future 中循环读取有界请求 body、发送 DATA/trailers，直到发送 FIN 才返回；它没有在内部 spawn body 发送任务。dhttp 可以在外部 spawn 这个完整 future，但还需要 h3x 在 HEADERS 写入底层流后通知执行方。`Request<ArcWndBuf>.await` 收到信号即可返回 `(h3x::Request<W>, dhttp::Response)`；上传任务不能因首次 await 返回而停止。HEADERS 写入失败时首次 await 返回错误，并取消配对的响应读取任务。
2. **响应头前取消**：`read_response` 的 future 在读到最终响应头之前拥有接收方向的取消守卫。future 被 abort/drop 时，守卫调用该 `H3ReadStream` 的 `StopSending` 能力，使用请求取消错误码，唤醒等待者并撤销本次流登记；正常交付响应头后转移所有权，不发送 STOP_SENDING。仅调用当前 `H3ReadStream::drop` 的 `finish()` 不满足此要求。
3. **响应 body 所有权**：`read_response` 把接收方向的取消能力交给返回的 `h3x::Response<R>` 所持有的 body 消费端。消费端及其克隆共享一个内部读取所有权；生产端的后台读任务不计入该所有权。最后一个消费端在 EOF 前被丢弃时，触发 STOP_SENDING、终止后台读任务并释放有界缓冲上的等待；读到 EOF 或已经失败时解除取消动作。所有权随现有 `into_body` / `into_parts` 一起转移，不能只绑定在 `Response<R>` 外壳上，否则提取 body 后会误取消。可在 `ArcWndBuf` 内部增加方向明确的消费端租约，不要求新增公开 body 类型。
4. **请求 body 所有权**：返回给调用方的 `h3x::Request<W>` 及其克隆共享一个内部写入所有权；后台 `write_request` 消费的缓冲读取端不计入该所有权。最后一个调用方写入端在 `shutdown()` 前被丢弃时，使缓冲读取结束并对 QUIC 发送方向调用 `CancelStream`，不能把未结束上传当作空 body 或永远等待。正常 `shutdown()` 后，驱动任务继续发送剩余 DATA、trailers 和 FIN；写入失败传回交换结果。可用 `ArcWndBuf` 的写入端租约实现，不要求新增 `RequestBody`。
5. **发送后头部不可再编辑**：首次 await 返回给调用方的 `h3x::Request<W>` 只用于写 body 和 trailers。当前类型仍公开 `set_method`、`set_uri`、`set_header` 等方法；调用后只会修改本地副本，不能改变已发送的 HEADERS。h3x 需要提供发送后的类型状态或等价的冻结机制，使这些操作在类型层面不可用，或明确返回错误；不允许静默成功。该机制不能妨碍 `AsyncWrite`、`shutdown` 与发送前已设置的 trailers。
6. **交换终态**：同一次取消至多记录一个终态；只停止本次请求的读写方向，不关闭可复用的连接。Endpoint 的任务登记在取消后等待写入任务、响应头任务和响应 body 任务退出；连接级错误仍按 h3x 的分类传播。`Response::drop` 只需 abort 它持有的一个响应头任务，取消守卫和 body 租约负责底层流动作。

落地时至少验证：服务端等完整上传才发响应、服务端提前发送大响应、响应头前丢弃 `dhttp::Response`、响应头后丢弃未读完的 body、未 shutdown 就丢弃最后一个请求写入端、克隆或提取 body 后的最后所有者判定、发送后修改请求头会被拒绝，以及取消后同一连接仍能处理下一次请求。当前 h3x 尚无上述租约、HEADERS 完成通知和发送后头部冻结能力，代码实施前须补齐。

### 4.7 dhttp 的请求执行分工

dhttp 不让 h3x 查找身份、建立连接或管理全局池。`Request<B>::into_future` 被轮询后，使用当前 Endpoint 的身份与全局 Network 取得或建立 h3x 连接，调用 `open_bi` 得到配对的发送/接收方向，并在 Network 的交换登记中记录这次请求。连接与开流失败在首次 await 返回，不启动遗留任务。

发送方向由 dhttp 启动 `write_request` 任务，接收方向由 `dhttp::Response` 持有的任务驱动 `read_response`；二者使用同一 stream 对和连接的 QPACK，同时推进，不用一个方向等待另一个方向结束。h3x 当前的 `write_request` 本身不 spawn，dhttp 必须显式启动并跟踪它；h3x 当前的 `read_response` 在返回响应头后已经自行 spawn body 读取，不需要 dhttp 再启动第二个 body 读取任务。后台写入任务由 Network 跟踪，即使 `dhttp::Response` 先返回也继续发送未完成的请求 body。

`Request<()>` 在启动前关闭空请求 body，随后等待 `dhttp::Response` 得到原生 `h3x::Response<R>`。`Request<ArcWndBuf>` 保留一个供调用方写入的 h3x 请求句柄，把共享 body 的另一个句柄交给写入任务；首次 await 等待 HEADERS 发送完成信号后返回 `(h3x::Request<W>, dhttp::Response)`。返回时不等待响应头，避免服务端等上传结束时死锁。

写入任务把成功/失败送给交换登记。HEADERS 之前的失败使首次 await 报错；HEADERS 之后的失败传给请求 body 写入端和交换结果，并在响应尚未交付时唤醒 `dhttp::Response` 返回错误。若响应头先到，`dhttp::Response` 可以返回，写入任务仍由 Network 持有；后续写入错误不能追溯修改已交付的响应，只能由写入端和交换结果报告。读取失败取消本次写入方向；正常提前响应不自动取消仍在进行的上传。

这套 dhttp 分工可直接使用 h3x 已有的 `open_bi`、`write_request`、`read_response`、有界 `ArcWndBuf` 和显式流取消能力。第 4.6 节列出的 HEADERS 完成通知、发送后头部冻结及自动丢弃取消仍是保留当前顶层语义时的 h3x 接缝；若放弃这些保证，必须先修改这里的 await 和取消契约，不能把 dhttp 外部 `spawn(write_request(...))` 当作 HEADERS 已发送的证明。

本轮已同步 dhttp 的请求接口声明。待执行接缝审查通过后，再实现 dhttp 的网络收发及必要的 h3x 接缝；当前声明中的 `todo!()` 不是可调用的请求行为。

### 返回类型与客户端身份无关

`IntoFuture` 只表示请求可直接 await，不表示两种调用返回相同结果，也不表示调用方必须知道具体 future 类型。本文不再把它称为“匿名异步操作”。通过 Endpoint.load(servername) 创建的端点及其请求都使用该名称对应的身份；以下单列的不提供本端证书的客户端能力，是另一项底层能力，不是 Endpoint.get 的默认行为。

本地 dquic `dev@bc039623` 的现有能力：

| 路径 | 已有匿名能力 | 当前限制 |
|---|---|---|
| dquic 门面的 QuicClient | `QuicClientBuilder::without_cert()` 使用无客户端证书配置 | 属于旧 qconnection 路径，不是当前草案选用的 qconn 端点 |
| 新 qtls | `ClientTlsConfig { local: None, .. }`，已有匿名握手测试 | 这是 TLS 配置，不是一个完整的匿名 Endpoint |
| 新 qconn::QuicEndpoint | 连接结果允许可选本端 authority | identity 成员仍必填，connect 固定传 local: Some(...)，尚无匿名构造入口 |

因此不另造 AnonymousIdentity 或 PreparedIdentity。后续匿名请求应复用底层无本端凭据能力，并继续验证服务端身份、使用全局网络及连接池；不要求初始化 home，也不能借匿名请求发起 servername 监听。连接池必须区分匿名与有身份的连接，不能互相复用。

当前没有发现独立的 AnonymousEndpoint 结构。若沿用 qconn，则需先把 qtls 已有的匿名配置接到 qconn 的端点/客户端入口；不在 dhttp 偷混旧 QuicClient 和新 qconn 两套连接类型。匿名构造 API 待这一步确认后再定；Endpoint.load(servername) 仍表示从 home 选择命名身份，空字符串不表示匿名。

核对入口：[旧 QuicClient 无证书配置](/Users/lixiaofeng/code/genmeta/dquic/dquic/src/client.rs)、[qtls 客户端身份选项](/Users/lixiaofeng/code/genmeta/dquic/qtls/src/config.rs)、[qconn 端点](/Users/lixiaofeng/code/genmeta/dquic/qconn/src/endpoint.rs)。

## 5. Tower Service 与应用边界

### 5.1 使用已有服务边界

dhttp 只依赖最小的 `tower-service` 契约，接受调用方提供的 Service。HTTP 路由器和 middleware 由应用自行选择；dhttp 不依赖或重导出 Axum，不定义 dhttp::Router，也不实现路径匹配、404/405 或 fallback 规则。[tower-service](https://docs.rs/tower-service/latest/tower_service/trait.Service.html)。

listen 的服务边界为：

```rust
S: tower_service::Service<http::Request<Body>, Response = http::Response<B>>
B: http_body::Body<Data = bytes::Bytes>
```

Body 是 http_body_util::UnsyncBoxBody 的别名，只统一入站流的类型，要求 Send、不要求 Sync；响应 body 保持泛型，接受满足 http_body::Body 的响应类型。`dhttp::Request<B>` 是出站执行对象，不是第二套 HTTP 消息；客户端响应与内部消息使用 h3x::Response/Request，服务适配使用标准 http::Request/Response。[UnsyncBoxBody](https://docs.rs/http-body-util/latest/http_body_util/combinators/struct.UnsyncBoxBody.html)。

```text
h3x Request<R>
  → dhttp 流式 http-body 桥接
  → http::Request<Body>
  → 应用提供的 tower_service::Service
  → http::Response<B>
  → dhttp 流式发送桥接
  → h3x Response<W>
```

dhttp 从 h3x 消息的 parts 复用方法、URI、headers 和 extensions，把有界 body 与 trailers 映射为 DATA/trailers frames；响应方向反向桥接。不先 read_to_end，也不额外引入无界队列。

Service::poll_ready 必须被正确驱动，在得到 Ready 的同一个 service 实例上 call；不能在一个实例 ready 后对未经 ready 的 clone 调用。应用可以自行组合 Tower middleware；dhttp 只正确驱动 readiness 和服务调用，不要求特定 middleware 实现。即使 Service 已返回响应头，完整交换的生命周期仍持续到实际发送完成或取消。

### 5.2 连接与身份作为现有类型的 extensions

不再定义接收 `(Request, connection, handshake)` 的 dhttp 专用 handler 签名。dhttp 在交给 Service 前，把同一次成功握手对应的下列对象写入标准 request.extensions：

- `qconn::ArcConnection`：已有连接句柄。
- `qtls::HandshakeSummary`：已有 local/remote authority 结果。

Service 直接读取标准 request.extensions，不使用特定框架的 extractor。它们来自底层握手，不从请求头或 URI 推断。remote 为 None 表示匿名，握手失败不会当成匿名请求分发。后续 dquic 若把身份查询并入连接，可以简化这些元数据；当前不新增 Context 包装。

Service 的错误由应用 middleware 优先转换为 HTTP 响应；未处理错误由接入层记录并在响应头发送前生成 500。响应头之后的 body 错误终止当前流，不再发送另一份响应头。路由语法错误属于所选 Router 的 API，不进入 dhttp::Error。

### 5.3 调用方组装 Router

Pishoo 负责组装应用服务，DHTTP 只接收这个服务：

```rust
let endpoint = Endpoint::load(servername).await?;
// router 由 Pishoo 完成路由、授权和执行环境装配。
endpoint.listen(scopes, router).await?;
```

Router 内可以包含静态文件、代理、原生 handler 和 WASM，均通过同一个标准 HTTP Service 边界交给 DHTTP。DHTTP 不识别 handler 的执行技术，不负责 WASM 加载、WASI HTTP 转换、OpenAPI 解析或沙盒设置。

调用方可以使用 Axum，也可以使用其他实现 Tower Service 的应用。DHTTP 不依赖或重导出 Axum，响应 body 继续保持泛型。Server 目录、路由匹配、方法分发和内容更新均由调用方处理。

### 5.4 HTTP 交换与应用生命周期

DHTTP 负责 h3x 与标准 HTTP/body 的流式桥接、背压、trailers、连接/流取消及实际网络输出完成。正确驱动同一个 Service 的 readiness 和 call；返回响应头不表示 Exchange 已经结束。

调用方持有其应用任务、执行预算和业务状态。应用服务需要把取消与 body 终止衔接到自己的后台任务，并完成回收；DHTTP 不直接持有或控制 Wasmtime Store、guest 实例或应用沙盒。

Service 返回响应、body EOF 和网络输出完成属于不同阶段。通用的交换完成/取消通知及应用任务衔接仍需在实现时核对；不能靠一次 Service::call 返回或简单 timeout 认定所有应用任务已完成。这是标准 HTTP 应用生命周期要求，不引入 WASM 专属接口。

应用可在响应头前将错误转换为 HTTP 响应；未处理的 Service 错误按通用契约生成 500。响应头后的 body 错误只终止当前流，不再发送另一份响应头，也不关闭仍被其他交换使用的连接。HEAD/204/304 或应用替换 body 时，调用方负责原应用执行的清理，DHTTP 按 HTTP 语义完成最终输出。

### 5.5 Pishoo 的 OpenAPI 与身份沙盒

以下是 Pishoo 提供应用服务时的约定，不进入 DHTTP 公共类型或依赖。完整边界见 [Pishoo 服务接入说明](pishoo-service-boundary.md)。

- 一个 `.wasm` 包含多个业务 handler，配套同名 OpenAPI 3.1.x JSON；Pishoo 静态解析文档，以 method/path 注册入口，operationId 可选。不执行 guest 获取私有清单。
- Pishoo 按声明的 API 逐条注册和授权。首版使用显式方法及字面量路径，未声明业务入口不进入 guest；OpenAPI schema 可服务于文档和 SDK，不要求 DHTTP 理解业务数据。
- 一个规范化 Server 身份对应一个 WASM 沙盒。同身份 App 共享数据、能力上限和聚合资源账户，每请求独立创建 Store/Instance/ResourceTable；不可变编译代码可共享。
- Pishoo 管理 WASM 编译、imports 校验、WASI HTTP 适配、文件/出站能力、guest 和 host I/O 任务，以及组件与 OpenAPI 的成对更新。
- Server 执行边界覆盖所有路由的身份、总预算与生命周期；WASM 身份沙盒覆盖该身份的 WASM 分支，普通原生 handler 不因 middleware 获得 WASM 或操作系统隔离。

```text
DHTTP HTTP/3 → http::Request<Body> + 可信握手 extensions
  → Pishoo ServerGuard + Router
      ├─ 静态 / 代理 / 原生 handler
      └─ OpenAPI 路由 + daccess 准入
          → 身份沙盒 → Pishoo WASI HTTP 适配 → guest
  → http::Response<B> → DHTTP HTTP/3 输出
```

Pishoo 根据可信握手信息核对 Server 身份和 authority，再执行自己的逐 API 授权。身份向 guest 的投影和出站授权由 Pishoo 处理，普通请求 header 不产生可信身份。共享网络、QUIC/TLS 与 HTTP/3 运行层仍由 DHTTP 提供。

### 5.6 当前声明状态

DHTTP 已移除 WASM 专属模块、feature、Wasmtime 依赖、错误分支及私有 WIT 清单，不再定义 WasmApp 或 apis()。标准 Service、Body、Endpoint 与 Network 仍处于成员和接口占位阶段。

Pishoo 文档中的组件执行、OpenAPI 和身份沙盒方案属于应用层设计，尚不代表相应实现或集成测试完成。h3x 的 WASI HTTP 测试可作为 Pishoo 适配参考，不形成 DHTTP 内置 WASM 能力。

## 6. 身份与 home：最小模型

目标删除独立的 dhttp-identity crate 及其重复身份模型，不再为了 gmutils 兼容保留旧 Identity、LocalAuthority/RemoteAuthority traits 或多层名称存储包装。gmutils、access/log 等调用方可以随实现迁移，不在本次顶层接口设计里补兼容层。

| 能力 | 归属与最小表达 |
|---|---|
| 名称输入与存储 | &str / String / Arc<str> |
| DHTTP 名称规范化、简写展开 | 独立 `dhttp-home` 的名称能力 |
| 证书链、私钥加载后的签名能力 | 直接复用 dquic/qtls 的已有类型 |
| QUIC endpoint 使用的本地材料 | qbase::endpoint::Endpoint（当前 qconn 的既有输入） |
| 握手中的本端/对端身份 | qtls::LocalAuthority / RemoteAuthority |
| DHTTP 证书字段解析与校验 | dhttp::certificate 中必要的规则与函数，不为每个字段机械增加 newtype |
| 定位身份目录、读取默认凭据文件和身份级通信日志路径 | dhttp-home；dhttp::home 使用它装配端点 |

home 与 Endpoint 之间只需要一个内部读取边界：

```rust
// 内部示意，不增加调用方需要理解的身份包装或构造步骤。
pub(crate) async fn load_identity(
    servername: &str,
) -> Result<Arc<qbase::endpoint::Endpoint>>;
```

本轮不定义 HomeConfig、HomeSettings、身份注册表、全局初始化、重扫快照、热替换、默认身份管理或保存事务等新 API，也不要求保留它们的旧签名。已有可用的文件读写代码可以按实现需要复用；具体如何组织不是这份顶层接口稿的前置条件。

名称和证书的 DHTTP 规则不能随结构一起丢掉。必要的签名算法选择、SKI 编解码等保留为具体协议逻辑；通用密钥与握手能力交给 dquic/qtls，不把整个旧 identity 原样搬入 home。

这里是重构目标，不代表当前目录和 Cargo 依赖已经删除。实际删除 identity crate 时同步迁移所有依赖它的代码，不保留两套长期身份模型，也不引入反向依赖 dhttp 的 home crate 造成依赖环。本轮仍只收敛顶层接口，不展开 home 实现设计。

## 7. Network：配置驱动的全局网络

```rust
#[derive(Clone)]
pub struct NetworkConfig {
    /// 持续生效的选择规则，随系统网卡变化重新求值。
    pub listen: Vec<ListenConfig>,
}

#[derive(Clone)]
pub enum ListenConfig {
    /// 持续监听所选通信范围内的全部适用网卡，包括以后新增的网卡。
    Scope(Scopes),
    /// 指定一张网卡及其允许的来源范围。
    Interface { device: String, scopes: Scopes },
}

pub struct DhttpNetwork {
    config: NetworkConfig,
    outbound_pool: h3x::Pool<ConnectionKey, DquicTransport, Error>,
    addresses: Arc<qprotocol::AddressBook>,
}

static NETWORK: OnceLock<DhttpNetwork> = OnceLock::new();

impl DhttpNetwork {
    pub async fn init(config: NetworkConfig) -> Result<&'static Self>;
    pub fn global() -> Result<&'static Self>;
    pub async fn shutdown(&self, deadline: Instant) -> Result<ShutdownReport>;
}
```

NetworkConfig 保存持续生效的 ListenConfig 规则。Scope 分支表达通信范围，Network 将它展开到当前和将来的适用网卡；Interface 分支允许调用方直接指定一张网卡及其用途，不再公开单独的 InterfaceConfig。索引、地址和实际绑定端口属于随系统变化的运行时资源，不由调用方配置。Network 既不扫描身份目录，也不持有 endpoints 身份索引。配置由调用方以类型化值提供，不依赖 home 的配置模型。

### 7.1 当前 qprotocol 的资源边界

以当前 qprotocol / qudp 为依据；已废弃的 qinterface 不进入设计或依赖。qprotocol 没有网卡配置类型，也不负责枚举网卡：

- `qprotocol::UdpSocket` 直接重导出 `qudp::UdpSocket`。qudp 提供 `bind(SocketAddr)` 和 `bind_to_device(SocketAddr, BoundDevice)`；`BoundDevice::new(name, index)` 接收已解析的名称及非零网卡索引。
- `Dock::add(Arc<UdpSocket>)` 接管 socket 的接收分发，按实际 `local_addr()` 管理；DHTTP 使用它接收 QUIC。
- `AddressBook` 将具体绑定地址关联到 inner / outer / agent 协议地址，不以网卡名作为地址键。

`Dock::global()` 已提供进程级 Dock，按绑定地址保存 socket 登记并持有收包任务；DhttpNetwork 持有已绑定 socket 的生存引用及规则对应关系，供撤销和重绑使用，不另建收包任务。`AddressBook` 已维护地址快照与订阅，DhttpNetwork 不复制 `NetworkState`、`SocketStatus`、`NetworkStatus` 或 watch 发布器。qprotocol 不枚举网卡，也不解释 Loopback / Internal / External 选择规则。

因此 `ListenConfig` 只表示监听意图，一条范围规则可匹配多张网卡，一张网卡又可产生多个 IPv4 / IPv6 socket。最终绑定的 socket 交给 Dock；调用方不提供易变化的索引、地址快照、端口或已打开的 socket。

核对入口：[qprotocol socket 重导出](/Users/lixiaofeng/code/genmeta/dquic/qprotocol/src/socket.rs)、[qudp 网卡绑定](/Users/lixiaofeng/code/genmeta/dquic/qudp/src/lib.rs)、[Dock](/Users/lixiaofeng/code/genmeta/dquic/qprotocol/src/dock.rs)、[AddressBook](/Users/lixiaofeng/code/genmeta/dquic/qprotocol/src/addr_book.rs)。

### 7.2 网卡选择与范围

`listen external` 的确定语义是 **listen all external device**：Network 持续监听所有适合 External 通信的网卡，包含以后新增或恢复的网卡。按通信范围监听已经包含“该范围内全部适用网卡”的含义，无需另加 All。命令直接产生范围规则，Network 根据系统变化持续展开。下面以系统分配端口为例：

```rust
let network_config = NetworkConfig {
    listen: vec![ListenConfig::Scope(Scope::External.into())],
};
```

若当前有 en0、en1 两张适用网卡，Network 为两张网卡都建立符合 External 规则的绑定；以后 en2 新增时再加入。原始 Scope 规则持续保留，不能用初始化时的展开结果替换。

需要限定网卡时使用 `ListenConfig::Interface { device: "en0".into(), scopes: Scope::External.into() }`。这里名称指定资源，scopes 指定这个资源的通信用途和允许的来源；同一张网卡可以用于 Internal、External 或两者，无法单凭网卡名确定用途。两种规则可共同使用，由 Network 按实际网卡合并。

范围规则在展开时将适用 scopes 关联到具体网卡及绑定地址；它在实际入口上约束允许的来源，不再反过来筛选另一份 All 选择器。沿用 qconn 的独立位语义，不默认累加。Endpoint.listen(scopes, app) 明确指定逐身份的来源范围；每个服务同时受 Network 的实际 socket 策略限制。启用 External 不会自动启动服务，也不会扩大其他 Endpoint 的允许范围。同一张网卡可通过一组 socket 同时承担 Internal 和 External。

| 范围 | 网卡及 socket 用途 |
|---|---|
| Loopback（localhost） | 回环网卡上的具体回环地址 |
| Internal | 所选网卡上用于内网通信的地址 |
| External | 所选网卡上允许接收外网来源包的地址 |

初始化及每次系统变化时，Network 枚举网卡，按 Scope 规则展开全部适用网卡，并合入直接指定的 Interface 配置，解析当前索引与符合所选范围的可用单播地址，分别构造具体 SocketAddr。IPv4 / IPv6 均可使用，不绑定通配地址；IPv6 链路本地地址保留系统 scope ID，只用于适合的局部通信。Loopback 必须使用回环资源；External 可以绑定 NAT 后的私网地址，也不要求网卡承担默认路由。绑定成功不表示公网路由或 NAT 转发已配置。具体可用性随地址和链路变化。

Scope 规则当前没有匹配或可用网卡时，Network 仍保留规则和系统监听，等待网卡新增或恢复；没有可用路径的操作返回 NetworkUnavailable。空配置列表仍为配置错误，不隐式选择网卡。显式 Interface 配置的名称不存在或范围与指定网卡不兼容，在初始化时返回配置错误；成功初始化后设备的暂时不可用按恢复流程处理。

规则展开到具体网卡后，先合并相同实际设备的适用 scopes，再展开地址并绑定，因此 Scope 与 Interface 规则重叠时不会因重复用途创建多组 socket。绑定端口由 Network 内部决定，不属于配置接口；每个 socket 绑定后读取实际端口。当前 Dock 以 SocketAddr 为键，不支持把两个不同网卡上相同的绑定地址视为独立资源；出现该冲突应明确报错，不能把其中一个静默合并到另一张网卡。

### 接入检查由 Network 统一负责

```text
实际接收网卡 / socket + QUIC 路径来源
  → Network 检查该入口的 scopes
  → 查找已监听的 servername，检查该 Endpoint 的 scopes 并完成 TLS/QUIC 接入
  → 交付该 Endpoint 的 HTTP Service
```

不符合范围的接入在 Network/传输接入层拒绝，不交给 Endpoint 的应用。尽可能在创建完整连接前检查；交付前仍应确认目标服务有效。来源取自实际收包与传输路径信息，不来自 HTTP header 或 URI。

范围按接收 socket 对应的配置判断，不能用所有网卡 scopes 的并集替代：例如仅允许 Internal 的网卡不会因为另一张网卡启用 External 而放行外部来源。共享 socket 合并后的策略只对应该共享资源，不能泄漏到其他入口。

首次 accept 不是唯一检查点。QUIC 后续新路径、地址迁移及网络资源重建也要遵守相同来源规则，已建立连接不能借换路径扩大准入范围。未知或无法可靠归属的入口不应直接交付到 Endpoint。

qconn 的 `QuicEndpoint::listen` 接收逐 servername 的 scopes，并在 QUIC 收包路径检查来源。dhttp 将 Endpoint.listen 指定的 scopes 原样传入；Network 还在实际接收 socket 上检查其配置。因此逐身份范围和逐入口范围共同生效，不能用所有网卡 scopes 的并集代替任一层。

复用依据：[来源分类](/Users/lixiaofeng/code/genmeta/dquic/qconn/src/endpoint.rs:215)、[QUIC 收包检查](/Users/lixiaofeng/code/genmeta/dquic/qconn/src/recv.rs:54)。

### 7.3 监听初始化

初始化先完成规则校验和系统变化订阅，再展开当前快照，通过 `UdpSocket::bind_to_device` 绑定具体地址与网卡，交给 Dock 接收分发，接入 `qtransport::QuicRouter` 并登记协议端点。External 只改变该绑定允许的来源范围；DHTTP 不因 External 解析 bootstrap、探测 STUN 或向 AddressBook 写入 outer 地址。协调首次快照和变化事件后才公布全局实例；配置或共享监听设施初始化失败要回收已启动资源。Scope 规则当前没有可用资源仍允许建立持续监听。

### 7.4 网络变化监听与恢复

网络变化监听、网卡快照维护和资源恢复是 `DhttpNetwork` 的核心职责，与 init / shutdown 属于同一生命周期。Network 按配置决定使用哪些网卡和 scopes，绑定端口由内部策略决定；qudp 提供 socket 绑定与 I/O，qprotocol 提供协议分发、登记和地址簿。操作系统通知可以复用独立的平台库，事件处理与恢复策略由 Network 统一管理，不依赖已废弃的 qinterface，也不要求每个 Endpoint 单独监听。

init 建立进程内共享的系统网络监听任务，并协调首次快照与事件订阅，避免初始化期间漏掉变化。监听覆盖整个系统的网卡新增、删除、up/down、索引及 IPv4 / IPv6 地址变化，不能只订阅初始化时选中的网卡。每次变化都重新对完整快照求值 Scope 规则，新网卡无需修改配置即可加入。路由变化不会改变 External 的接收范围定义。平台事件作为重新读取系统快照的触发信号，重复或连续事件合并处理；必要时用轮询补足平台通知能力。

Network 根据最新快照更新实际资源：

- 保留未受影响的 socket，只对新增、失效或需要替换的资源操作。新增或重新出现的网卡按最新快照判断规则匹配，并解析当前索引。
- 地址失效、网卡删除或 down 时，停止使用对应入口，撤销 AddressBook 中的旧地址和 QUIC 登记，再移除 Dock 中的旧 socket。
- 网卡新增或 up、新地址出现时，重新求值选择规则，为新匹配资源绑定、加入 Dock 并登记协议端点。External 不额外发布外部地址。
- 初始化后的暂时断网或绑定失败只使受影响资源不可用；保留配置，等待网络变化后恢复。已有 Endpoint/app 登记继续保留。

Network 管理本地网络资源及可用地址变化；已有 QUIC 连接的路径验证和迁移由 qconn / qtransport 承担，具体变化通知接缝在实现时对接。网络资源恢复不等于所有既有请求都能继续，失去可用路径的连接仍遵守底层失败语义。

shutdown 先停止监听及重绑，再取消并等待相关后台任务，清理共享 socket 与协议登记；所有步骤共用同一个 deadline。锁只保护短暂的状态读取和提交；Endpoint.close 不停止进程的网络监听。

网络启动与身份加载互不依赖。network.init 不要求初始化 home 或先加载 servername；Endpoint.listen 才将身份和 app 交给运行层。凭据读取不启动服务。

重复 init 返回错误；global 在初始化前返回错误；shutdown 终结全进程网络，不隐式重新初始化。Endpoint.close 只清理自己的登记、交换和复用权限，不关闭其他身份仍使用的 interface。

连接池请求从发起方 Endpoint 得到其名称 Arc。内部池 key 按名称 Arc 的实例身份和远端 authority 区分连接；克隆的 Endpoint 共享池条目，独立加载的同名 Endpoint 不会误共享。池未命中时 Network 按名称读取凭据、构造 qconn::QuicEndpoint 并建连；这属于池工厂工作，不要求逻辑 Endpoint 持有底层端点。凭据来源更新时还需使旧池条目失效，不能只比较名称文本。活动连接的资源引用不等于 Network 拥有身份目录。

入站连接由 qconn 的 `listen` 回调交付，Network 将已接受的连接构造成 Server 角色的 H3 connection，并跟踪接入任务。`outbound_pool` 只复用 Client 角色的出站连接；已接受的 Server 角色连接不能作为新出站请求的池条目。

## 8. 错误与关闭报告

```rust
pub type Result<T> = std::result::Result<T, Error>;

pub enum Error {
    InvalidName { name: String },
    InvalidUri { source: http::uri::InvalidUri },
    AlreadyListening,
    EndpointClosed,
    NetworkClosed,
    NetworkUnavailable,
    NetworkNotInitialized,
    AlreadyInitialized,
    InvalidNetworkConfig { message: String },
    IdentityNotFound { name: String },
    Credentials { source: qtls::RustlsError },
    Http { source: http::Error },
    Http3 { source: h3x::Error },
    Quic { source: qconn::Error },
    Io { source: std::io::Error },
    Home { path: PathBuf, source: Box<dyn std::error::Error + Send + Sync> },
}

pub struct ShutdownReport {
    pub forced_connections: usize,
    pub cancelled_exchanges: usize,
    pub unfinished_tasks: usize,
}
```

请求入口接受已解析的 `Uri`；`impl From<http::uri::InvalidUri> for Error` 支持在返回 `dhttp::Result` 的调用方直接写 `endpoint.get("https://example.com/".parse()?)`。源码中的可克隆错误包装保存同一个原始解析错误。

保留底层错误来源，不把 HTTP/3 stream 错误压成一个无内容的 Transport。名称、路由和关闭状态是 dhttp 自己的错误。Home 保留出错文件或目录及底层原因，包括读取、解析、权限、保存及回滚错误；具体转换与 Display/Error 实现不在本轮实现。

deadline 是同一个绝对 `std::time::Instant`，不是每个关闭步骤重新计时。达到 deadline 属于关闭报告：剩余交换被取消，连接被强关，未完成任务计数返回；无法完成清理本身的错误通过 Result 返回。Session 尚未进入本轮接口，报告中不放 session 字段。

## 9. 普通 DHTTP 应用的使用形状

```rust
// Endpoint 内部读取凭据并使用底层身份类型，调用方只给出名称。
let endpoint = Endpoint::load("alice.dhttp.net").await?;

// 网络配置由调用方提供，不依赖 home 配置格式。
let network = DhttpNetwork::init(network_config).await?;

// 无请求体的便捷调用：await 得到带流式 body 的 h3x Response<R>。
let mut response = endpoint.get("https://bob.dhttp.net/info".parse()?).await?;
let mut body = Vec::new();
response.read_to_end(&mut body).await?;

// 调用方写请求体：首次 await 返回请求 body 和独立的响应 future。
let (mut request_body, response) = endpoint.post("https://bob.dhttp.net/upload".parse()?).await?;
request_body.write_all(chunk).await?;
request_body.shutdown().await?;
let response = response.await?;

// app 由应用提供，实现 Service<http::Request<Body>>。
// dhttp 不构造路由器。
// app 由调用方提供；Network 统一判断来源，只有显式 listen 才启动服务。
endpoint.listen(scopes, app).await?;
```

示例表达目标调用形状，所需请求执行绑定尚未定稿；不能据此认为当前 h3x::Request<W> 已可 await。body 读写使用 Tokio AsyncReadExt / AsyncWriteExt。

## 10. Pishoo 接入边界

Pishoo 负责 Server 发现、应用内容、OpenAPI、策略、路由、发布、WASM 运行与身份沙盒；dhttp 负责凭据读取、通信、共享网络、标准 HTTP 消息和交换生命周期。具体 Server 文件路径如何交给轻量 home 读取，在接入时再定，不为这个问题设计完整 home 框架。

Endpoint 的上层使用形状保持简单：

```rust
let endpoint = Endpoint::load(servername).await?;
endpoint.listen(scopes, app).await?;
```

Pishoo 组织一个混合 Router：静态、代理、原生 handler 和多个 WASM 应用共享 Server 执行边界，WASM 分支再受当前身份沙盒约束。Pishoo 自己加载组件和同名 OpenAPI，逐条注册声明入口，在 guest 执行前授权；完成组装后调用 Endpoint.listen(scopes, router)，不为每个 handler 创建 Endpoint、监听或网络。

WASI HTTP body 桥接、Store/Instance、guest 调用和应用任务回收全部归 Pishoo；DHTTP 通过标准 Service/body 提供通用传输与生命周期衔接。不存在 dhttp::WasmApp 或 WASM 宿主注入接缝。Pishoo 既有设计中尚引用这些旧上游接口的部分按本次边界调整，见 [接入说明](pishoo-service-boundary.md)。gmutils 后续按新的接口适配，不要求本轮保留旧 identity/home 抽象。

## 11. 本轮审查与实施边界

1. 按最简单的模型重构，不以旧 identity/home 或 gmutils 兼容为接口约束。
2. 删除重复身份和名称包装，直接使用 dquic/qtls/h3x 已有类型；保留必要的 DHTTP 名称与证书规则函数。
3. home 暂时只是目录定位和凭据读取辅助，不详细设计其对象、配置、缓存、扫描或生命周期；Endpoint 只暴露 load(servername)。
4. NetworkConfig.listen 保存 Scope/Interface 监听规则，不包含 home、逐名称监听表或端口；`listen external` 直接表达 External 范围，持续展开到全部适用网卡。External 不启动 STUN 探测。Network 负责系统网卡新增、删除、up/down 等变化的监听、资源重绑与恢复；使用 qprotocol 的全局 Dock 管理 socket，按入口和来源统一准入，Endpoint.listen 接收 scopes 和 app。
5. HTTP 消息复用 h3x；Endpoint 返回的 `Request<()>` 和 `Request<ArcWndBuf>` 分别实现两种 IntoFuture 输出。get 等无请求体便捷调用直接 await 得到响应；post 等需要调用方写请求体的调用直接 await 得到请求 body 写入端和 `dhttp::Response`。接口声明已同步到代码，执行能力与消息的绑定仍待实现；只给未绑定的 h3x 请求增加 IntoFuture 无法补足配对接收流。
6. listen 仅约束 tower_service::Service，不依赖 Axum；Pishoo 组装 Router，完整负责 WASM、WASI HTTP、OpenAPI、逐 API 授权和身份沙盒。DHTTP 不增加 WASM 类型、feature、依赖或私有清单。
7. Pishoo 和 gmutils 的具体调用迁移留到接入阶段；本轮只收敛接口稿，后续同步修改依赖关系，不用兼容层长期保留旧 identity 模型。
