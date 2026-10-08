# DHTTP SDK 公共绑定层

2026-10-08 开始恢复 Node.js / Python SDK。`api/` 现在是可构建的 `dhttp-api`
crate，两种语言将共用这里的流桥接、错误和生命周期实现。
`api/` / `dhttp-api` 沿用 v0.6.2 的语言绑定包名称，职责限定为绑定适配。
完整目标见 [SDK 接口草案](../docs/api/sdk-interfaces.md)。

当前已接入 N-API / PyO3，恢复 Node `@genmeta/dhttp` 和 Python `dhttpy` 的高层客户端与
handler 服务端。两种包装复用公共层的有界流、取消与任务所有权，不恢复旧 raw connection API。

## Node.js

```sh
cd api
npm run build
```

```js
import {Endpoint, init} from '@genmeta/dhttp';

// peers 的地址来自远端服务进程的 addresses()；当前需要显式配置 DHTTP 名称解析。
await init({peers: {'bob.dhttp.net': '192.168.1.10:51234'}});
const endpoint = await Endpoint.load('alice');
try {
  const response = await endpoint.fetch('https://bob~/hello');
  console.log(await response.text(), response.remoteAuthority?.ownerHash);
  console.log(await response.trailers);
} finally {
  await endpoint.close();
}
```

Node 22.17+ 支持 ESM/CommonJS 和 TypeScript 声明。消息直接使用 Web Request、Response、
Headers 和 ReadableStream；响应附带 remoteAuthority、rawHeaders、trailers Promise 与 release()。
fetch 支持 AbortSignal、毫秒总期限 timeout、ownerHash，以及静态/Promise/函数形式的 trailers。
标准 Headers 会合并可合并的多值字段，rawHeaders 保留收到的原始字段对；服务响应可附加 rawHeaders。
`listen(scopes, handler)` 接收 Web Request 并要求返回 Web Response。
服务请求的 signal 在监听关闭时中止，SDK 不等待无法取消的用户 Promise。
缓存、cookie jar 和浏览器 CORS 策略仍由调用方负责；流式请求体无法在 307/308 跳转时重放。

## Python

```sh
cd api
uv run --with maturin maturin build --interpreter python3 --out dist
# 将 dist 中当前平台的 wheel 安装到项目虚拟环境。
```

```python
import dhttpy

await dhttpy.init(peers={'bob.dhttp.net': '192.168.1.10:51234'})
async with await dhttpy.Endpoint.load('alice') as endpoint:
    async with endpoint.get('https://bob~/hello') as response:
        print(await response.text(), response.remote_authority.owner_hash)
        print((await response.trailers()).items())
```

Python 3.10+ 的包装支持 await / async with、异步字节迭代器、JSON/text、重复 Headers、
秒单位总期限 timeout、owner_hash 和 asyncio 任务取消。handler 接收 ServerRequest，返回 Response；
Response 的 body 可为文本、字节或异步字节流，并可提供静态或异步 trailers。
包提供 py.typed 和类型声明。安装验收目前覆盖本机 CPython 3.14 / macOS arm64。

具名端点可以 load_from/loadFrom 指定 profile；local_authority/localAuthority 提供证书链、公钥、
SKI、owner hash 和签名能力，remote authority 只来自已验证握手。verify 使用现有证书签名规则。
签名入口不导出私钥。

## 初始化与发现范围

Native SDK 按进程安装一次 System DNS 和显式 peers 解析器。init 可显式调用，首次 request/listen
也会幂等初始化；load 本身不发布名称。root_certificates/rootCertificates 接受 PEM 信任根，
显式配置会替换进程默认信任根，首次配置后只允许相同值重复初始化。
peers 可增补或更新；addresses() 返回当前本地绑定，用于显式寻址和跨进程验收。
默认 H3 DNS、mDNS 和名称发布维护仍待接入，因此当前不是完整的开箱即用发现版本。

Native Node build 产物是本机构建的 dhttp.node；npm pack 可用于本机安装验证。
多平台 npm 二进制包、其他 Python wheel 平台和发布 CI 尚未恢复。当前包版本 0.1.0 为本地开发版本。

## 流式请求

使用公共 Rust 层时，嵌入方需要先按 Rust 核心接口注册解析器。`init()` 或首次 request/listen 会幂等
初始化共享 Network；Tokio runtime 必须保持存活。加载凭据本身不初始化网络或发布名称。

```rust,no_run
use dhttp_api::{Client, RequestOptions, upload_channel};
use http::{HeaderMap, Method};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::load_from("/path/to/home/alice").await?;
let (upload, body) = upload_channel();
let request = http::Request::builder()
    .method(Method::POST).uri("https://bob~/echo").body(Some(body))?;
let options = RequestOptions {
    timeout: Some(std::time::Duration::from_secs(30)),
    ..Default::default()
};
// request() 启动交换后返回等待响应头的 future，不预填整个 native 窗口。
let response = client.request(request, options).await?;
let cancellation = response.cancellation();

let sending = async {
    upload.send(vec![0x5a; 512 * 1024]).await?;
    upload.finish(HeaderMap::new()).await
};
let receiving = async {
    let response = response.await?;
    while let Some(bytes) = response.body().next().await? {
        // 在这里将 bytes 交付给语言侧消费者。
        let _ = bytes;
    }
    let trailers = response.body().trailers().await?;
    let _ = trailers;
    Ok::<_, dhttp_api::Error>(())
};
futures::try_join!(sending, receiving)?;
let _ = cancellation; // AbortSignal / asyncio 取消可以调用 cancellation.cancel()。
client.close().await;
# Ok(())
# }
```

上传队列最多保留 4 个 16 KiB DATA 块，native WndBuf 容量为 64 KiB。
`send()` 将大块拆分后按消费速度入队；调用方提供的源数据不计入桥接队列容量。
服务响应也可以使用 `upload_channel()` 返回的 Body，通过标准 HTTP Body 路径发送。
`finish(trailers)` 冻结上传并提交结束，直接丢弃未完成 writer 会传播 producer 错误。
取消部分完成的 `send()` 会失败整个上传，避免静默丢失剩余字节。

`BodyReader::next()` 按需读取 native DATA。同一个 body 只允许一个活跃读取；
并发读取返回 `ERR_BODY_IN_USE`。trailers 仅在成功 EOF 后可用，
`trailers()` 本身不消费 DATA；失败或取消返回错误。丢弃/取消未完成 reader
会释放 native Body；取消正在等待的 next future 也会取消本次接收。
正常接收 EOF 不自动取消仍在完成的上传。

## Handler 服务

```rust,no_run
use bytes::Bytes;
use dhttp_api::{Client, ServerRequest};
use http_body_util::{BodyExt, Full};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let endpoint = Client::load_from("/path/to/home/alice").await?;
let listener = endpoint.listen(dhttp::Scope::Loopback.into(), |request: ServerRequest| async move {
    let verified = request.extensions().get::<dhttp::HandshakeSummary>().and_then(|summary| summary.remote.as_ref());
    let _ = verified;
    let body = Full::new(Bytes::from_static(b"hello"))
        .map_err(|never| match never {})
        .boxed_unsync();
    Ok(http::Response::new(body))
}).await?;
listener.close().await;
endpoint.close().await;
# Ok(())
# }
```

handler 返回前发生异常或 panic 时生成空的 500，异常详情只记录到诊断日志。
返回响应后的 Body 错误终止该流，不重新发送 500。可信身份保留在标准请求/响应
extensions 中的核心 HandshakeSummary / RemoteAuthority；请求 header 和 URI 不参与身份构造。
公共层不定义第二份 HTTP 消息结构，也不新增 handler trait；listen 接收闭包。

## 已确定的生命周期

- 默认没有 SDK 总期限；调用方可以指定 `RequestOptions.timeout`，覆盖连接、上传和响应消费。
- close 默认立即取消，不隐式排空。listener 先撤销登记，再取消其 handler、请求接收和响应 Body。
- client close 拒绝新操作，取消并等待自有交换和 listener 清理，保留共享 Network/连接池。
- close 幂等。Client 克隆共享同一份 SDK 所有权；独立加载的句柄各自管理任务，即使名称相同。
  同名服务登记沿用核心规则，只允许一个 listener。
- Drop 只触发补充清理；适配器必须将语言侧显式 close/cancel 转换为这些原生操作。
- reload 成功才替换当前 Client 及其克隆的 Endpoint；失败保留原凭据。
  显式 profile 使用绝对路径重读，不修改 DHTTP_HOME。reload 不自动获取 OCSP；
  证书链或私钥轮换需重启，既有连接继续沿用其握手身份。
- 此阶段仍沿用核心按名称更新 TLS 登记的 reload 语义；语言适配需要保留同名登记的唯一所有权。

## 验证

```sh
cargo test --offline -p dhttp-api
DHTTP_TEST_OPENSSL=/path/to/openssl cargo test --offline -p dhttp-api \
  --test quic_roundtrip -- --include-ignored
cargo clippy --offline -p dhttp-api --all-targets --no-deps -- -D warnings
```

普通测试覆盖有界背压、生产者失败、接收错误/EOF/trailers、并发读取、取消、
handler 异常与 Body 取消。真实 QUIC 测试使用临时 CA、证书、匹配私钥和 OCSP，
覆盖具名/匿名请求、512 KiB 双向流式收发、早响应、多值 headers/trailers、
可信身份和错误 ownerHash、双向请求、各阶段取消/期限、同名句柄与两身份隔离、
重复监听/关闭、显式 profile reload 与失败保留凭据。

## 语言验收

```sh
DHTTP_TEST_OPENSSL=/path/to/openssl cargo run -p dhttp-api --example sdk_credentials -- target/sdk-fixtures
DHTTP_TEST_PROFILE_ROOT="$PWD/target/sdk-fixtures" node --test api/tests/node.test.cjs
# 在已安装本次 wheel 的虚拟环境中运行：
DHTTP_TEST_PROFILE_ROOT="$PWD/target/sdk-fixtures" python -m unittest discover -s api/tests -p test_python_sdk.py -v
```

两种测试都启动独立语言服务端进程，使用临时 CA、规范 DHTTP SKI、匹配私钥及 OCSP。
覆盖具名/匿名请求、512 KiB 流、早响应、重复字段和 trailers、签名验证、错误 owner pin、
producer/handler 异常、取消、期限、端点隔离、重载和重复关闭；Node 还覆盖反向请求。
Python 检查事件循环关闭前无遗留 asyncio 任务，两种服务端都验证正常退出。

## 后续实施顺序

1. 接入默认 H3 DNS / mDNS 和监听后名称发布，维护地址变化、续期、关闭与发布状态。
2. 增补跨语言互通、发现的跨进程验收，以及其他 Python 版本的事件循环测试。
3. 恢复多平台 npm 二进制包、Python wheels 和发布 CI。

跨设备公网、真实 NAT/relay 及 Linux/Windows 网卡变化验收仍单独进行。
