# DHTTP

带身份的 HTTP/3 通信库。按 Pishoo 的[三仓第一版冻结清单](../pishoo/design/README.md)实现独立 Endpoint、全局 Network、标准 HTTP Body 和 Tower Service 接入。

```rust,ignore
let endpoint = dhttp::Endpoint::load("alice").await?;
let uri: http::Uri = "https://bob~/profile".parse()?;
let response = endpoint.get(uri)
    .header(http::header::ACCEPT, http::HeaderValue::from_static("application/json"))
    .await?;
```

Endpoint 加载和请求构造不访问网络；首次 await 才取得共享连接。所有请求方法默认使用标准 Empty body，`.body(body)` 可替换为任意标准流式 Body，`from_request` 使用相同驱动。上传与响应读取并发，响应头不等待上传 EOF。服务请求携带实际 `qtls::HandshakeSummary`；对外不暴露 QUIC/H3 连接。

`DhttpNetwork::init()` 在进程中初始化一次。各 Endpoint 在监听时传入 `Scopes`；Network 汇总活动服务的范围，创建并持有实际 socket、AddressBook、连接和服务登记。没有活动服务时不绑定监听 socket。每两秒重读网卡快照，保留未变化绑定，撤销失效绑定的地址、协议和 Dock 登记；服务退出后重新汇总范围并回收多余绑定。

`endpoint.listen(scopes, service)` 接受标准 Tower Service。`scopes` 同时指定该服务允许的来源范围，并参与 Network 的网卡选择。`listen` future 持续处理接入；结束时撤销监听登记，之后可用同名 Endpoint 再次监听。

Body 适配使用现成 `StreamBody` 和 `UnsyncBoxBody`，保留 DATA、多值 trailers、EOF、错误、提前丢弃和 HEAD/204/304 语义。操作等待期限为 16 分钟，连接期限为 30 秒；业务请求和终端会话期限由调用方决定。远端停止在后续流 I/O 中观察，不提供独立终态订阅。

身份材料从 `DHTTP_HOME/<name>/ssl` 或用户默认 home 读取；TLS 身份和握手类型直接复用 qtls。`certificate` 提供 owner_hash 文本字节提取、现有规范算法的签名验证，以及实际握手的对端 authority 查询。仅证书规范算法复用旧 identity crate，不引入新的身份资源容器。

当前依赖相邻 `../dquic` 和 `../h3x`。**qconn 的出站 connect 仍缺路径发现/插入，真实出站握手不能完成**；本层实施了有界等待，并未补建其他 HTTP 客户端或降级传输。HTTP 消息、全双工、trailers 和取消通过内存双向流测试验收，真实联网互通仍待底层完成后验收。WASM、授权、应用路由和终端执行由 Pishoo 负责。

```sh
cargo test -p dhttp --lib --tests
cargo check -p dhttp --no-default-features --all-targets
```

旧 Node.js/Python 包装已移除；语言绑定和发布版本固定待 Rust 接口及真实联网验证完成后处理。
