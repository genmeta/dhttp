# DHTTP

带身份的 HTTP/3 通信库。按 Pishoo 的[三仓第一版冻结清单](../pishoo/design/README.md)实现独立 Endpoint、全局 Network、标准 HTTP Body 和 Tower Service 接入。

```rust,ignore
dhttp::resolve::Resolver::add(my_resolver); // Arc<dyn dhttp::resolve::Resolve>
dhttp::DhttpNetwork::init().await?;
let endpoint = dhttp::Endpoint::load("alice").await?;
let uri: http::Uri = "https://bob~/profile".parse()?;
let response = endpoint.get(uri)
    .header(http::header::ACCEPT, http::HeaderValue::from_static("application/json"))
    .await?;
```

匿名请求使用 `Anonymous.get(uri)` 等方法，与 Endpoint 的请求方法对称，无需本地身份材料；远端身份仍会验证。与具名请求一样，发送前需要注册解析器并初始化 Network：

```rust,ignore
dhttp::resolve::Resolver::add(my_resolver);
dhttp::DhttpNetwork::init().await?;
let response = dhttp::Anonymous.get("https://bob~/profile".parse()?).await?;
```

`Endpoint` 直接持有 `Arc<qbase::endpoint::Endpoint>`；`Endpoint::load` 读取名称对应的证书链、私钥和 OCSP，加载失败立即返回错误，clone 共享已加载的身份材料。监听和新建连接直接使用这些凭据，池仍按双方名称复用连接；匿名与具名请求使用不同池条目。凭据文件更新后需要重新 load，已有 Endpoint 保留加载时的材料。

`Endpoint::new(identity)` 必须接收已准备好的 `Arc<qbase::endpoint::Endpoint>`，与底层 QUIC 的构造参数一致。`name()` 返回 `&str`；Endpoint 始终有身份，可以发起请求和监听。`Anonymous` 是无状态的出站入口，提供相同的 get/head/post/put/patch/delete/options/request/from_request 方法，不提供 listen。`Anonymous.from_request(http_request)` 和 `Request::new(http_request)` 都可接入已有的标准 HTTP 请求。

Endpoint 加载和请求构造不访问网络；await 请求时才取得共享连接。`Request<B>` 组合可选的具名 Endpoint 和 `http::Request<B>`；`B` 为 `Empty` 或 `WndBuf`。`dhttp::Empty` 是标准 `http_body_util::Empty<Bytes>` 的别名，其 `Body::Data` 为 Bytes，本身不保存数据。GET/HEAD（以及默认的 DELETE/OPTIONS）返回 `Request<Empty>`，await 时直接发送空 body、结束请求方向并等待响应。POST/PUT/PATCH 和通用 `request(method, uri)` 返回 `Request<WndBuf>`，构造时就持有 h3x 的可写缓冲；首次 await 消费构造器、建连、开流并启动上传，返回 `(RequestWriter, RequestFuture)`。同一个 WndBuf 直接交给 h3x，与 RequestWriter 共享。通过 RequestWriter 继续写入，响应 future 可独立等待响应头。两种请求分别实现 IntoFuture，共用 URI 处理和连接获取逻辑。

```rust,ignore
use tokio::io::AsyncWriteExt;
use bytes::Bytes;

let response = endpoint.get(uri.clone()).await?;

let (mut writer, response) = endpoint.post(uri.clone()).await?;
writer.write_all(b"content").await?;
writer.shutdown().await?;
let response = response.await?;

let (mut writer, response) = endpoint.post(uri.clone()).write(b"initial-").await?;
writer.write_all(b"more").await?;
writer.shutdown().await?;
let response = response.await?;

let tag = dhttp::HeaderName::from_static("x-tag");
let (mut writer, response) = endpoint
    .post(uri.clone())
    .trailer(tag.clone(), dhttp::HeaderValue::from_static("initial"))
    .await?;
writer.write_all(b"content").await?;
writer.append_trailer(tag, dhttp::HeaderValue::from_static("computed"))?;
writer.shutdown().await?; // 自动发送剩余 DATA、trailers，再结束上传
let response = response.await?;

let body = dhttp::WndBuf::new(64 * 1024);
body.write_bytes(Bytes::from_static(b"content")).await?;
let (mut writer, response) = endpoint.post(uri).body(body).await?;
writer.shutdown().await?;
let response = response.await?;
```

`.body(window)` 设置请求使用的 WndBuf；`.write(data)` 创建容量至少为数据长度的 WndBuf，再写入初始字节（默认容量为 64 KiB）。后续可用 `write_all` 继续写入，调用 `AsyncWriteExt::shutdown()` 发送 EOF 并等待上传完成。空的 WndBuf 也需要 shutdown；显式 `.body(dhttp::Empty::new())` 则按空请求处理。`from_request` 和 `Request::new` 同样接受以 `Empty` 或 `WndBuf` 为 body 的标准请求。流式请求首次 await 不等待响应头，因此服务端可以等待完整请求后再响应。请求头和初始 body 在发送前配置；发送后的 RequestWriter 实现 AsyncWrite 和 dquic 的 CancelStream（由 dhttp 重导出）。在它上面调用 header、append_header、body 或再次 await 会在编译期报错。`cancel(error_code)` 按指定 HTTP/3 错误码 reset 请求方向；丢弃句柄会取消未完成的上传。响应 Body 的读取或丢弃不控制上传任务。

Request 构造阶段支持 `.trailer(name, value)` 替换同名字段、`.append_trailer(name, value)` 追加同名值；替换 body 时保留这些字段。发送后，RequestWriter 提供同名方法并返回 `io::Result<()>`，可继续补充或修改 trailers；登记 trailers 后仍可写 DATA。首次轮询 `shutdown()` 时冻结字段，后台按剩余 DATA、trailers HEADERS、FIN 的顺序发送，并等待上传完成。开始 shutdown（包括等待期间）或取消后，再写 DATA 或修改 trailers 返回 `BrokenPipe`；重复成功的 shutdown 幂等。空请求预设的 trailers 在 await 时自动发送。

服务请求携带实际 `qtls::HandshakeSummary`；对外不暴露 QUIC/H3 连接。

`DhttpNetwork::init()` 为所有适用活动网卡准备 UDP 绑定；重复或并发调用返回同一个 Network。netwatcher 先交付当前快照，再持续监听系统网卡事件。每次扫描保留匹配 socket 的实际端口，添加新绑定并撤销失效绑定；IPv6 link-local 地址保留网卡 scope ID。没有可用网卡或部分绑定失败时仍可初始化，后续网卡变化会重新扫描。

扫描按平台排除部分已知辅助网卡名称：macOS/iOS 的编号 bridge、awdl、llw，Linux/Android 的常见容器网桥和虚拟接口，以及 Windows 的已知 WSL、DockerNAT、默认 Hyper-V 交换机和 Host-Only 名称；具体规则见[目标地址](docs/design/network-detailed-design.md#32-目标地址)。这是候选筛选策略，被排除的接口不绑定、不发布地址，也不探测 NAT。未知名称、VPN、Linux 通用网桥及树莓派有线、无线、USB 网卡保留；不依据硬件地址或私网地址判断。名称可被重命名或本地化，规则不保证识别全部虚拟接口，也不替代底层路径竞速与失败接替修复。忽略未指定、多播和 IPv4 全局广播地址，拒绝零接口索引；每个候选地址交由操作系统实际绑定，单个绑定失败不影响其他接口。回环及 IPv4/IPv6 link-local 地址只保留本地通信绑定，不启动 STUN；私网和 IPv6 ULA 地址保留 NAT 探测，探测失败不撤销本地绑定。

Linux GNU/musl、macOS 和 Windows 的测试覆盖绑定维护；iOS 设备/模拟器及 Android 四种 ABI 增加交叉编译检查，配置见 [Network platforms](.github/workflows/network-platforms.yml)。交叉编译不替代移动端实机验证。Android 应用声明 `INTERNET` 与 `ACCESS_NETWORK_STATE` 权限；未由框架初始化 `ndk-context` 时，先从 JNI 调用 `dhttp::set_android_context` 并传入 application Context，再调用 `DhttpNetwork::init()`。iOS/macOS 的本地网络访问受系统隐私权限约束；具体接入要求和实机检查见[网络设计](docs/design/network-detailed-design.md#跨平台验证)。

手机唤醒或应用回到前台时，调用进程级恢复接口，无需先调用 suspend：

```rust,ignore
dhttp::DhttpNetwork::global()?.resume().await?;
```

`resume()` 直接调用网卡维护对象，刷新监听器、重新读取当前网卡快照并修复绑定；仍有效的 socket 和端口保留，并发调用与后台维护通过同一互斥锁串行修改状态。返回时本轮扫描已完成，STUN 刷新已安排，不等待公网探测完成，也不保证互联网已可达。单个绑定失败继续由后台检查重试；监听器创建、网卡读取或维护任务停止的错误返回给调用方。地址变化沿用底层 QUIC 路径发现和验证；已经终止的连接由后续请求重新建立，已发送请求不会自动重放。

`DhttpNetwork` 保存 HTTP/3 连接池、服务表和网卡维护对象。池键分为 Incoming 和 Outgoing，分别要求本端或远端身份；双方身份齐全时按同一名称对匹配，出站请求可以复用入站连接。socket、收包任务、直接 QUIC 地址登记及清理统一交给 dquic 的 `Dock`，地址发布到配套 `AddressBook`；纯客户端也可直接建连。收包失败由 Dock 清理，Network 在网卡事件、resume 或每秒存活检查时补齐绑定。初始化时使用的 Tokio runtime 必须持续存活；resume 不重建已经销毁的 runtime。

初始化不等待 STUN/NAT 探测。Network 使用 dquic 的协议能力为每个适用绑定执行一次 NAT 分类，之后每20秒刷新公网映射并同步地址簿；resume 取消旧的心跳测量并立即重测，已退出的 STUN 发现也可重试。已完成的 NAT 分类在同一绑定上保留，Loopback 和 IPv6 link-local 不探测。所有连接使用通过 `dhttp::resolve::Resolver::add` 注入的解析器。Pishoo 等上层负责按域名分流：DHTTP 名称交给 DDNS/mDNS，普通 DNS 域名交给 `SystemResolver`。全局 Resolver 并发合并已注册来源，本身不决定域名分流规则。

请求 URI 中只有 `bob~`、`~` 等显式简写展开为 DHTTP 名称。普通 DNS 名称保持原域名，显式端口传到连接层，并参与连接池匹配；`https://ddns.genmeta.net:4433` 不会变成 `.dhttp.net` 名称或丢失端口。通过 HTTP/3 查询 DDNS 时，其服务 origin 也走全局 Resolver，必须由上层的域名分流交给系统解析，避免递归进入 DDNS 查询。DHTTP authority 的 `:序号` 仍只保留在请求 URI 中，传输地址和端口来自解析结果。TLS 仍使用配置的信任根并验证名称和 OCSP。

```rust,ignore
dhttp::DhttpNetwork::init().await?;
let addresses = dhttp::AddressBook::global();
let public_addresses = addresses.ddns_endpoints();
let updates = addresses.subscribe_ddns(); // 名称发布服务直接订阅地址变化
// 针对某个本地绑定，可使用 addresses.subscribe_mdns(bound)。
```

`endpoint.listen(scopes, service).await` 接受标准 Tower Service，登记成功后返回 `ListenFuture`；调用方 spawn 或持有它以维持监听。`scopes` 原样交给 qconn，按名称限制来源范围。接入回调直接装配 H3 并启动请求驱动。丢弃 `ListenFuture`（包括未 poll 的 future）撤销名称和 Service，socket 和已有连接保留；重新监听同名服务后，旧连接上的新请求交付给新 Service。解析器与名称发布服务需配套：system DNS 默认解析到 443，而 Network 绑定动态端口，部署时需发布实际地址。

h3x 内部保留有界收发缓冲，接收消息和 Service 响应使用标准 HTTP Body；dhttp 的空请求以 `http::Request<Empty>` 直接交给 h3x 的泛型 `WriteRequest<B>` 实现，流式请求走 `WriteRequest<WndBuf>`。泛型发送路径直接读取 body 帧，空请求无需装箱或转换为另一种 body。`WndBuf::new` 创建空窗口，`write_bytes` 让 Bytes 无拷贝进入窗口；所有写入都遵守容量限制。发送前预填数据时应保证容量足够；超过容量的数据应在开始发送后通过 RequestWriter 写入，让消费和写入并发进行。DATA、多值 trailers、EOF、错误、提前丢弃和 HEAD/204/304 语义由 h3x 处理。客户端直接返回 h3x 的响应 Body；流式上传任务由返回的 `RequestWriter` 独立持有。

等待取得连接的期限为 30 秒；业务请求和终端会话期限由调用方决定。远端停止在后续流 I/O 中观察，不提供独立终态订阅。

`dhttp-home` 负责目录定位，`Endpoint::load` 从 `DHTTP_HOME/<name>/ssl` 或用户默认 home 读取身份材料并装配 QUIC 端点。TLS 身份和握手类型直接复用 qtls。`dhttp-home` 同时承载 DHTTP 名称、证书链标识、SKI 解析和规范签名验证；需要这些规则的应用直接调用其证书接口，签名使用 qtls 的本端身份能力。入站请求的握手信息作为 `qtls::HandshakeSummary` 放在 request extensions 中。

2026-10-09 适配本地新 dquic：具名 Endpoint 直接拥有 qbase 身份，匿名出站使用匿名 QuicEndpoint；监听采用新 dquic 的严格客户端 OCSP 要求。具名客户端缺少或提交无效 staple 时握手失败，匿名客户端仍按现有身份/授权规则处理。不再提供旧的客户端 OCSP 宽松兼容入口。

当前依赖相邻 `../dquic` 和 `../h3x`，传输仅使用 QUIC。具名请求从已加载的身份构造局部 QuicEndpoint::from，匿名请求使用 QuicEndpoint::anonymous，两者调用同一 connect 流程。匿名只表示不提交客户端凭据，仍验证服务器身份。出站路径发现由 qconnection 消费全局 Resolver 和 AddressBook；双方采用新 dquic 的默认 client/server transport parameters，开放 HTTP/3 所需的流和流控额度。dhttp 显式配置两端的 `h3` ALPN，在装配 H3 前校验实际协商值，握手摘要保留实际结果。未交付建连的取消及 QUIC 清理由 dquic 管理。WASM、授权、应用路由和终端执行由 Pishoo 负责。

```sh
cargo test -p dhttp --lib --tests
cargo check -p dhttp --no-default-features --all-targets
# 需要 OpenSSL 和本地 UDP socket 权限；生成临时证书及有效 OCSP，验证真实双向 TLS 与 HTTP 请求
cargo test -p dhttp --test quic_roundtrip -- --ignored
cargo test -p dhttp --test dns_bootstrap -- --ignored
```

真实网络测试使用自建 CA、实际生成的证书/私钥和有效 OCSP。生成器明确指定 named_curve 与 SHA-256，并核对证书/私钥公钥一致、证书链和域名、OCSP 签名。需要支持 `pkey -check` 与 `ocsp -rmd` 的 OpenSSL；若子进程命中系统自带的兼容实现，可通过 `DHTTP_TEST_OPENSSL` 指定可执行文件。例如 macOS：

```sh
DHTTP_TEST_OPENSSL=/opt/homebrew/bin/openssl cargo test -p dhttp --lib --tests -- --include-ignored
```

Node.js/Python SDK 已恢复首版高层客户端和 handler，支持流式收发、身份、取消与关闭，并通过本机 npm/wheel 安装和跨进程验收。使用说明见 [SDK](api/README.md)。当前发现支持 System DNS 和显式 peers；默认 H3 DNS/mDNS、名称发布及多平台发行仍待完成。
