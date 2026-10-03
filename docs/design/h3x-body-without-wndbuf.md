# h3x 去掉 WndBuf 的详细设计

日期：2026-10-02。状态：未采用的备选设计。用户后续选择保留 WndBuf；下文删除窗口的方案仅供比较，不作为实施计划。接口和伪代码尚未编译验证。

## 当前选择：保留有界缓冲

保留 WndBuf 的价值是让 HTTP/3 解析和应用消费可以独立推进，在窗口容量范围内吸收短时速度差。去掉 WndBuf 后 QUIC 自身仍有缓冲，区别是没有额外的消息层预读队列；不能把两种方案理解成“有缓冲”和“完全无缓冲”。

| 维度 | 保留 WndBuf | 由应用直接驱动解析 |
| --- | --- | --- |
| 消费短暂停顿 | 解析任务可继续推进到窗口满 | HTTP/3 body 解析暂停，QUIC 仍可在自身额度内收包 |
| 长时间慢消费 | 窗口填满后同样背压 | 更早把背压传到传输读取 |
| trailers/EOF 发现 | 若剩余数据能装入窗口，可在应用读完前确认 | 随应用轮询推进 |
| 内存 | QUIC 缓冲之外增加消息队列和任务状态 | 无消息队列，仍有解析缓冲和应用持有的 Bytes |
| 调度 | 额外任务、锁和两端唤醒，可重叠解析与消费 | 少一层交接，解析工作在消费任务中执行 |
| 生命周期 | 要协调窗口两端、协议 reader/writer 和应用 Body | reader 直接归 Body，发送 writer 直接消费 Body |
| trailers 表达 | 字节窗口之外需要共享字段和完成顺序 | 解析器局部字段即可 |
| 迁移 | 可沿用现有窗口实现及行为测试 | 需重写消息收发和所有权路径 |

当前建议是先保留现有收发窗口，把标准 Body 与窗口的适配统一收进 h3x。公开收发接口仍统一使用 `http::Request<Body>` / `http::Response<Body>`，不需要公开 IncomingBody。保留窗口不要求保留自定义消息容器或让 dhttp 管理窗口和 trailers。

发送窗口的独立收益是允许源 Body 提前生产到容量上限；是否值得其成本应通过突发生产、慢写入和高并发负载测量。后续可单独评估，不影响统一的公开接口。保留窗口也不会自动补齐源 Body 永远 Pending 时的远端终止观察能力。

当前实现已将标准 Body 适配移入 h3x，并在 dhttp 删除窗口转发代码。收发窗口继续保留；窗口消息容器保持内部实现；公开接口直接实现在 `src/stream/read.rs` 和 `src/stream/write.rs`，只保留一套读写 trait，消息集成测试直接验证标准 Body 接口。未实施下文备选方案中的去窗口和 TransportAbort 改造。

以下为原备选方案。

本文基于相邻 h3x、dquic 和当前 dhttp 的工作区源码。目标是让 HTTP 消息的生产和消费直接驱动 HTTP/3 流，删除消息体中间窗口，同时统一收发公开接口。

## 1. 设计结论

- 收发都使用 `http::Request<Body>` / `http::Response<Body>`。
- `Body` 是现成 `UnsyncBoxBody<Bytes, BoxError>` 的类型别名，不新增 `IncomingBody` 结构体。
- 接收使用 `StreamBody` 包装持有 reader 的异步流；应用轮询 Body 才继续解析消息。
- 发送编码器直接消费 Body 帧；写完当前数据后再拉下一帧。
- 删除 `ArcWndBuf`、共享 `Trailers`、自定义 `Request<IO>` / `Response<IO>` 和 `R/W` 标记。
- 每个接收消息不再启动 body 解析任务；连接级控制流、QPACK 指令流继续独立驱动。
- dhttp 保留寻址、身份、服务接入，以及上传与响应的并发和生命周期策略。

```text
接收：QUIC reader → HTTP/3 解析 Stream → StreamBody → Body → 应用
                         ↑ 由应用 poll_frame 驱动

发送：应用 Body → HTTP/3 编码器 → QUIC writer
                    ↑ 写入可继续时才消费后续数据

独立运行：QUIC 连接驱动、HTTP/3 control、QPACK encoder/decoder 指令流
```

删除的是 HTTP 消息层的生产者/消费者队列。QUIC 的重组、收发缓冲和流控仍然存在，解析时仍需有限大小的工作缓冲；本方案不承诺零缓冲或端到端零拷贝。

## 2. 当前实现与具体改动

| 当前位置 | 当前行为 | 改动 |
| --- | --- | --- |
| h3x `common/request.rs`、`common/response.rs` | 消息绑定窗口，并通过 extensions 交接共享 trailers | 保留头部解析/校验函数和读写 trait，删除消息容器 |
| h3x `stream/read.rs` | 返回 headers 后 spawn，把 DATA 写入窗口 | 返回拥有 reader 的 Body |
| h3x `stream/write.rs` | 从窗口取 Bytes，再写 DATA | 从标准 Body 取帧并编码 |
| h3x `common/trailers.rs` | `Arc<Mutex<HeaderMap>>` | 改为普通字段转换/校验函数 |
| h3x `stream.rs`、`stream/bi.rs` | 按方向登记流，只保存 I/O Pending 的 waker | 保留登记和错误传播，补齐非 I/O 等待的唤醒 |
| dhttp `endpoint/body.rs` | 双向转发 | 删除 |
| dhttp `endpoint/response.rs` | 窗口装配、转发、无 body 响应处理 | 合并成对 h3x 的调用，保留必要的调用方结果策略 |
| dhttp `endpoint/request.rs` | 网络寻址、上传任务、响应读取、窗口装配 | 删除窗口装配，保留交换驱动 |

现有 `H3ReadStream::Drop` 和 `H3WriteStream::Drop` 调用的是 `finish()`。不能依赖它们完成未结束消息的协议取消；消息读写函数必须明确持有取消 guard。

## 3. 公开 API

### 3.1 唯一的 Body 类型

```rust
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BoxError>;
```

`Body` 可移动到其他任务，但无需 `Sync`；每个 body 只有一个消费者。泛型只用于构造入口。`Empty`、`Full`、Axum Body、文件流和其他标准 Body 均在交给消息写入接口之前转换。

调用方使用 `BodyExt` 提供的 `source.map_err(Into::into).boxed_unsync()` 完成转换，空消息体可直接用 `Body::default()`。

已经是 `h3x::Body` 时直接传递，避免重复装箱。h3x 内部生成接收 Body 时仅在最外层装箱一次。

### 3.2 对称的读写 trait

```rust
pub trait ReadRequest: Sized + Send {
    fn read_request(self, qpack: ArcQpack)
        -> impl Future<Output = Result<http::Request<Body>>> + Send;
}

pub trait WriteRequest: Sized + Send {
    fn write_request(self, request: http::Request<Body>, qpack: ArcQpack)
        -> impl Future<Output = Result<()>> + Send;
}

pub trait ReadResponse: Sized + Send {
    fn read_response(self, method: http::Method, qpack: ArcQpack)
        -> impl Future<Output = Result<http::Response<Body>>> + Send;
}

pub trait WriteResponse: Sized + Send {
    fn write_response(
        self, response: http::Response<Body>, method: http::Method, qpack: ArcQpack,
    ) -> impl Future<Output = Result<()>> + Send;
}
```

`Result` 仍为 h3x 的协议错误结果。响应读写都保留请求方法参数，以正确处理 HEAD 和 CONNECT。连接的 `open_bi` / `accept_bi` 继续返回分开的 reader 和 writer。

### 3.3 消息头处理

将原消息对象的方法抽成内部函数，例如：

```rust
decode_request_head(fields) -> Result<http::request::Parts>
encode_request_head(&parts) -> Result<Vec<Field>>
decode_response_head(fields) -> Result<http::response::Parts>
encode_response_head(&parts) -> Result<Vec<Field>>
decode_trailers(fields) -> Result<http::HeaderMap>
encode_trailers(&fields) -> Result<Vec<Field>>
```

保留现有伪头、字段大小、重复字段和 CONNECT 校验。普通重复字段使用 `HeaderMap::append`，敏感标记在 QPACK 转换时保留。`:protocol` 继续沿用现有 extensions 表示；重构时不顺带更改它的公开表示。接收消息的 version 明确设为 HTTP/3。

## 4. 接收流程

### 4.1 headers 与 body 的所有权交接

1. 调用 `read_request/read_response` 时，在返回 future 前创建 reader guard。
2. future 解析初始 HEADERS 并完成 QPACK 解码和头部校验。
3. 响应保持当前行为：跳过合法的临时 1xx，返回最终响应。
4. 根据请求方法和状态生成内部接收策略：是否允许内容、是否按普通消息检查 Content-Length。
5. 将 reader、QPACK 和策略移动到接收 Stream。
6. 包成 `StreamBody` 并装箱，立即返回标准消息。

初始 headers future 的取消使用 `H3_REQUEST_CANCELLED`。成功交接给 Body 后，提前放弃消费使用 `H3_NO_ERROR`，表示不再需要这一接收方向的剩余数据。完整交换是否取消，由 dhttp 决定。

两个 guard 的交接必须在同步代码中完成，中间不插入 await。Body 的 guard 也必须在创建异步 Stream 之前建立，并被 Stream 捕获，保证 Body 从未被轮询就 drop 时仍会清理。

### 4.2 Stream 持有的内部状态

无需公开结构体，局部变量由编译器保存到异步 Stream 中：

| 状态 | 用途 |
| --- | --- |
| reader guard | 独占接收方向并承担提前丢弃清理 |
| QPACK 句柄 | 解析尾部字段 |
| 当前 DATA 剩余长度 | 处理跨多次读取的大帧 |
| 一块 `BytesMut` 工作缓冲 | 读取当前数据片段 |
| `Option<HeaderMap>` | 暂存尾部字段，直到确认消息结束 |
| 已接收内容长度及适用的预期长度 | EOF 时校验消息完整性 |
| trailers 阶段标志 | 禁止后续 DATA 或第二段尾部 HEADERS |

不保留窗口容量、生产者句柄、共享 trailer 锁、body 任务 JoinHandle。

### 4.3 DATA 解析与内存

沿用 `read_next_frame` 和现有帧解析器：读取 DATA 的帧头后，只消费其声明长度内的内容。

- 单次向应用交付的数据片段目标上限沿用 8 KiB。
- 大 DATA 帧分多次读取和交付，不按对端声明的整帧长度分配内存。
- 必须显式限制一次读取可写入的缓冲长度；不能仅依赖 `BytesMut::reserve` 的容量作为上限。
- 短读产生的剩余缓冲容量在下一次读取中复用，避免每个一字节片段都另占一个 8 KiB backing allocation。
- 长度为零的 DATA 合法，跳过并继续；不能把它当成 QUIC EOF。
- 声明的 payload 尚未读完就 EOF，报告 framing 错误。
- 内容长度计数使用 checked_add；适用 Content-Length 时，超出声明长度的数据在交付应用前拒绝，长度不足在正常 EOF 时报告。
- 未知扩展帧分块丢弃；HEADERS 保留现有 64 KiB 编码 payload 上限及解码字段限制。

应用持有已交付的 Bytes 可能保留其 backing allocation；h3x 无法限制应用积累的数据。发送侧源 Body 也可能一次交付很大的 Bytes，不能宣称整个交换只占 8 KiB。

### 4.4 trailers 与正常结束

本设计保持当前 dhttp 的交付时机：**先确认合法流结束，再向应用交付 trailers。**

```text
读取 DATA → 逐段 yield DATA
读取尾部 HEADERS → 解码为局部 HeaderMap
检查其后只有允许跳过的扩展帧，直至 QUIC EOF
校验适用的 Content-Length
正常完成接收方向，解除取消 guard
如存在尾部 HEADERS，yield trailers（允许空 HeaderMap）
Stream 结束，Body 返回 None
```

因此，应用收到 trailers 时，协议尾部已经验证完成。没有 trailers 时，必须等到 Body 返回 None 才知道消息完整结束。读完预期 DATA 字节数不能提前结束解析。

帧顺序和长度校验依据 [RFC 9114 §4.1–4.1.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1)。HEAD/304 中描述假想内容的 Content-Length 不作为实际接收长度；无内容响应和成功 CONNECT 的策略分别处理。

### 4.5 EOF 与登记清理

当前 `H3ReadStream::poll_read` 读到 EOF 就通知 registry 正常结束。重构应把“底层 EOF”与“消息校验完成”分开：

- 底层 EOF 将方向 I/O 标为结束，释放底层 reader。
- 消息解析器完成帧边界、长度和字段校验后，再通知 registry 正常结束。
- EOF 后的最终校验失败仍经过 `fail(error)` 上报，不能被正常结束吞掉。
- guard、正常完成和错误路径的通知要幂等，每个方向只完成一次有效清理。

这可以复用现有 H3Stream 状态并增加完成通知记录，不需要新的公开消息类型。

### 4.6 轮询取消与公平性

接收 Stream 必须持久保存当前解析 future。应用暂时取消一次 `body.frame()` 等待，之后重新轮询同一个 Body，不能丢失已读取的 varint 或 payload 前缀。

`async_stream` 中持续存在的 await 满足这个实现方向；不能每次 poll 都新建并丢弃 `read_next_frame()` future。

大量零长度 DATA、未知帧或临时响应可能长时间不向应用 yield。内部循环设置协作预算，例如连续处理 32 个不产出数据的帧后 `yield_now().await`；丢弃大未知 payload 时也按字节预算让出执行权。这是调度预算，不是新的消息缓存。

### 4.7 读取伪代码

以下 `report_failure`、`complete` 等为待实现的内部辅助函数名：

```rust
fn receive_body(reader, qpack, policy) -> Body {
    let guarded = guard_reader(reader, qpack.clone(), ErrorCode::NoError);
    let frames = async_stream::try_stream! {
        let mut reader = guarded;
        let mut trailers = None;
        let mut received = 0_u64;

        // 每次解析错误都先调用 report_failure，再向 Body 返回错误。
        while let Some(frame) = read_next_checked(&mut reader, trailers.is_some()).await? {
            match frame {
                Data(frame) => {
                    // 校验 policy；分块读取完整 payload，每段更新 received 并 yield。
                }
                Trailer(frame) => {
                    // 校验 policy；QPACK 解码并保存 HeaderMap。
                }
            }
        }
        // 校验长度，完成登记并解除 guard；释放 reader 后再交付 trailers。
        complete(reader, policy, received)?;
        if let Some(fields) = trailers {
            yield http_body::Frame::trailers(fields);
        }
    };
    StreamBody::new(frames).map_err(Into::into).boxed_unsync()
}
```

实际实现需要将整个解析过程的错误汇总到统一出口，不能让 `?` 绕过错误作用域传播和 QPACK 清理。

## 5. 发送流程

请求、响应只分别处理初始头部，共用内部 body 编码函数。

1. 在构造发送 future 时创建 writer 取消 guard，覆盖未轮询就 drop。
2. 拆出标准 parts 和 Body，校验并编码初始 HEADERS。
3. 若响应禁止内容，直接 drop 源 Body，不轮询，发送 headers 后正常 shutdown。
4. 轮询源 Body，将 DATA 编码发送；每次写完当前片段后才继续。
5. 收到 trailers 后校验并保存到局部 HeaderMap，随后继续轮询确认源 Body 结束。
6. trailers 后再出现任何 DATA 或第二个 trailers，视为本地源 Body 违反消息契约；reset 当前发送流，不向网络发送非法顺序。
7. 源 Body 返回 None，检查适用的内容长度，编码并写出暂存 trailers，然后 shutdown。
8. shutdown 成功后解除 guard，返回成功。

暂存 trailers 到源 Body EOF 保持现有时机，避免把错误源 Body 的后续帧发送到线上。源 Body 在 trailers 后必须及时返回 None；若 Pending，仍需允许终止信号打断。

DATA 的大 Bytes 用共享切片拆成当前 8 KiB 的发送片段；编码帧头使用小缓冲，payload 不拼入同一个 Vec。当前传输接口是 AsyncWrite，是否在 QUIC 内部复制数据取决于传输实现。

发送长度累计同样检查溢出；超出有效 Content-Length 的帧在写入前拒绝，长度不足在源 EOF 时 reset。发送成功仍按当前底层 shutdown 契约定义；当前 dquic writer 的 shutdown 会等待已写数据被确认，不能在源 Body 返回 None 时提前报告发送成功。

`write_response` 在本版表示最终响应；需要发送 1xx 时应另行设计 interim headers API，不把 1xx 当成会结束发送方向的最终响应。

## 6. 终止与错误

### 6.1 生命周期契约

| 事件 | 行为 |
| --- | --- |
| headers future 被丢弃 | 取消正在读取的消息，清理已登记 QPACK 解码 |
| Body 未读完被丢弃 | STOP_SENDING H3_NO_ERROR，清理当前接收方向；不自动中断另一方向 |
| Body 正常读尽 | 完成接收方向，不发送停止信号 |
| 本地发送 future 被丢弃 | RESET_STREAM H3_REQUEST_CANCELLED，并 drop 源 Body |
| 源 Body 返回错误 | reset 发送方向，返回带原始 source 的 h3x 流错误 |
| 收到流级协议错误 | 由现有 registry 按策略结束该交换，不影响其他交换 |
| 收到连接级错误 | 通过连接错误通道关闭连接，并唤醒相关方向 |
| 对端停止当前发送方向 | 结束发送并释放源 Body；保留原因，调用方决定交换结果 |

Body 的通用 Drop 表示放弃这一个接收方向。客户端放弃完整交换时，由 dhttp 同时取消上传任务。服务端提前返回响应时，drop 请求 Body 不应把合法响应也取消。提前响应和停止请求上传的关系见 [RFC 9114 §4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1)。

### 6.2 必须区分的三种等待

1. 正在等底层 read/write：传输的 I/O waker 负责唤醒。
2. 正在等 QPACK：解码器的 waker 和解码取消负责唤醒。
3. 正在等源 Body：应用 Body 的 waker 不会自动感知 QUIC 终止。

当前 `ArcH3Stream` 只在 I/O Pending 时保存 waker。删除窗口后，不能假设取消信号仍会经由窗口唤醒转发循环。设计增加每方向一个独立的终止等待槽，在非 I/O 等待时登记调用任务；状态转为错误时唤醒它。

登记 waker 与检查终态使用同一锁，或采用 register 后再次检查的模式，避免终止发生在检查与登记之间。不持有状态锁调用应用 `poll_frame`、QPACK poll 或外部回调；取出需要的状态后释放锁。

### 6.3 传输接口缺口与具体补齐方案

当前 `Transport` 只要求 AsyncRead/AsyncWrite、主动 stop/cancel 和错误映射。它没有“没有执行 I/O 时观察远端终止”的接口。只给 h3x 增加 waker，无法凭空观察远端 STOP_SENDING。

若要求源 Body 永远 Pending 时也能及时结束，本设计需要扩展 h3x 与 dquic 之间的传输契约：

```rust
// 拟新增的传输能力，当前仓库尚未提供。
pub trait TransportAbort {
    fn poll_aborted(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<crate::Error>;
}
```

契约：

- 返回当前方向的 reset、peer stop 或连接失败；保留 HTTP/3 错误码与作用域。
- 健康方向 Pending 并登记独立 waker；普通 FIN/正常 shutdown 不作为错误返回。
- 不消费字节、不 flush、不触发 shutdown，不与 I/O 共用会互相覆盖的 waker 槽。
- 终止状态持久保存，事件发生后首次调用也能立即观察；重复轮询返回同一终止原因。
- h3x reader/writer 都可使用：writer 等源 Body，reader 等 QPACK 时观察底层 reset。

实现位置：dquic `qrecovery` 的收发共享状态保存终止 waker，并在 reset/stop/连接错误转换后唤醒；dhttp 的 `RecvStream` / `SendStream` 映射为 h3x Error；h3x 将该能力纳入 Transport 的关联类型约束。测试传输也必须实现。

h3x 内部 `poll_aborted` 同时检查 registry 中已记录的错误和底层终止事件，释放锁后汇报事件。发送在等待下一帧时同时 poll 此方法与源 Body；QPACK 等待采用相同原则。失败胜出时丢弃未完成的解析/生产 future，再走统一清理。

不能用空写、反复 flush、定时空轮询代替这个契约。它们不保证通知，并可能改变 I/O 语义。

这是实现完整终止保证所需的相邻仓库改动。若第一阶段只改 h3x 的消息路径，可以保留当前“下一次 I/O 才观察远端停止”的限制，但不能宣称已经满足永远 Pending 源 Body 的及时取消测试。删除 WndBuf 本身不依赖这个新 trait。

### 6.4 保留错误来源

公开 Body 使用 BoxError，接收帧错误装箱保存 h3x Error；发送源 Body 失败需转换为当前发送流的 RequestCancelled，并保留 source。

建议给现有 `ErrorDetail` 增加可选的 `Arc<dyn Error + Send + Sync>` source，并让 Error::source 返回它；保持现有 Stream/Connection 分支及 Clone。任意 source 无法自然支持结构性 Eq/Hash，因此相应移除派生，测试改为检查 scope、code、reason 和 source。此项属于本次 API 破坏性变更的一部分。

不能因为源 Body 的错误恰好是另一个连接的 h3x Connection error，就关闭本次发送所用的连接；例如代理正在转发另一连接的接收 Body。源 Body 错误在本次发送边界始终作为本地流失败处理，原始作用域只保留在 source 中供诊断。

## 7. QPACK、背压与资源回收

### 7.1 QPACK 保持独立驱动

当前 H3Connection 已分别驱动 encoder/decoder 指令流，继续保留。应用暂停消费某条消息不会停止这些连接级任务。

初始 HEADERS 和 trailers 解码都可能 Pending。沿用 QPACK 的 `StreamDecoder` drop guard 清理已注册解码；registry 取消也可能触发相同清理，必须保持幂等。取消未注册或已经完成的解码不能产生多余的解码取消指令。

### 7.2 背压的实际边界

- 接收：应用不 poll，h3x 不继续 read；QUIC 可以继续在其接收额度内缓冲，但不会无限前进。
- 发送：当前帧写入 Pending 时不拉下一帧；源 Body Pending 时不再写数据。
- 移除窗口减少一层队列和跨任务唤醒，不等于移除 QUIC 缓冲或所有内存分配。
- h3x 不主动 collect Body，不自动启动后台 drain。

连接级流控可能受未消费数据影响。应保留 QUIC 资源限制，并验证一个暂停的大消息不会饿死控制/QPACK 流；独立任务本身不保证传输额度充足。

### 7.3 懒读取带来的行为变化

原来后台任务最多提前解析到窗口满；现在 body 部分由应用请求下一帧时解析。因此：

- trailers、后续协议错误和 EOF 的发现时机随应用消费推进。
- 不轮询也不 drop 的 Body 会继续持有流登记；连接优雅排空可能等待它。
- 调用方不需要 Body 时应直接 drop；需要完整验证时应消费到 None。
- 消息期限和持有期限由上层管理，h3x 不增加隐式超时或自动排空。

HEAD/204/304 的接收 Body 也需解析到合法结束才能确认没有非法 DATA，不能仅根据 headers 返回无验证的 Empty body。`size_hint` 初版采用保守值；`is_end_stream` 不得仅因 Content-Length 为零就报告结束。

## 8. dhttp 的接入

### 8.1 类型和服务入口

`dhttp::Body`、`BoxError` 直接复用 h3x 的别名，EmptyBody 仍可用标准 Empty。dhttp 的 `.body(B)` 和 Tower service 接入可保留泛型便利入口，在调用 h3x 前转换为统一 Body；h3x 四个公开读写接口始终对称。

服务端大致流程：

```rust
let mut request = reader.read_request(qpack.clone()).await?;
let method = request.method().clone();
// dhttp 完成 URI 校验、可信身份 extensions 和 Service readiness。
let response = app.oneshot(request).await?;
writer.write_response(response, method, qpack).await?;
```

实际代码保留当前应用失败和 421 响应的 writer 清理 guard。URI 不合法时 drop 请求 Body 即可停止接收，无需提取窗口。

### 8.2 上传与响应并发

客户端仍需独立驱动上传，不能先 await `write_request` 完成再 `read_response`，也不能用等待两边都完成的简单 try_join 延迟交付响应头。

保持当前所有权策略：

1. 请求 future 持有上传任务的 abort guard。
2. 收到响应头后，把上传任务 guard 转交给响应 Body 的包装 Stream。
3. 响应 Body 提前 drop 或发生读取错误，取消上传。
4. 响应 Body 完整消费成功后，释放 abort 所有权，允许尚未完成的上传继续运行。

这层 Stream 只管理交换生命周期，不搬运到中间窗口，也不需要自定义 Body 结构体。避免将它理解为 HTTP/3 接收适配。

上传错误需要观察：响应头返回前，上传失败应唤醒请求 future 并返回错误；对端正常停止上传时仍等待并接收响应。响应头返回后，沿用流登记传播真正的交换失败；上传任务的最终结果应被明确记录或观察，不能丢掉 JoinHandle 后悄悄忽略 panic/失败。完整响应成功后不因请求上传被提前停止而追溯性否定响应。

h3x 返回原始停止原因；dhttp 仅按流方向、错误作用域及完成阶段处理 NoError。不能把连接级 NoError 或任意 Body 错误统一吞成成功。

## 9. 文件组织与依赖

```text
h3x/src/
  h3x.rs                  Body/BoxError 类型别名
  common/request.rs       request head 编解码、读写 trait
  common/response.rs      response head 编解码、读写 trait
  common/trailers.rs      无状态 trailer 字段转换和校验
  stream/read.rs          headers 读取及持有 reader 的接收 Stream
  stream/write.rs         headers 写入及共享 body 编码循环
  stream.rs               方向状态、终止唤醒、完成通知
  stream/bi.rs            方向登记和交换错误传播
  transport.rs            传输约束，完整版本增加 TransportAbort
  error.rs                保留原始 Body 错误 source
```

删除 `common/wnd_buf.rs` 和公共 WndBuf/ArcWndBuf/R/W/Trailers 重导出。`Trailers` 模块保留函数但不保留共享容器类型。

`http-body`、`http-body-util` 从 dev-dependencies 提升到普通 dependencies，新增 `async-stream`；继续使用已有 scopeguard 和 futures。

dhttp 删除 body 转发函数、BODY_WINDOW_BYTES/BODY_READ_CHUNK_BYTES 常量及窗口专用错误转换。具体是否删除整个 response.rs 取决于剩余调用方逻辑，不以减少文件数为目标。

## 10. 实施步骤

1. **冻结行为测试。** 将现有 DATA/trailers、早响应、取消、HEAD/204/304 测试保留为迁移基线；补充未轮询 Drop 和 Pending/终止竞态用例。
2. **补齐终止契约。** 完整版本先在 dquic、测试传输和 h3x 接通非 I/O 等待的终止通知，验证不丢唤醒。若分阶段实施，明确标注此保证尚未提供。
3. **抽离头部函数与统一类型。** 提供 Body 别名，调用方使用 BodyExt 转换；增加 source 错误支持。
4. **替换接收路径。** 用持有 reader 的 Stream 返回标准消息，验证部分帧取消可恢复和 Drop 清理。
5. **替换发送路径。** 直接消费标准 Body，验证背压、trailer 顺序和源错误。
6. **迁移 dhttp 和 h3x 使用方。** 更新服务接入、上传驱动、测试与示例；覆盖真实 QUIC 往返。
7. **删除旧接口。** 搜索所有 WndBuf、R/W、共享 Trailers、旧消息类型和转发函数引用，删除窗口代码和仅测试窗口自身的测试。

这是破坏性 API 变更。工作区路径依赖应协调修改；发布前搜索其他消费 h3x 的项目并安排版本升级。暂存迁移步骤可以保留旧接口，最终方案不保留双套消息体系。

## 11. 验收测试

| 分类 | 必须验证的场景 |
| --- | --- |
| 数据 | 空 body、零长度 DATA、大 DATA、多次短读、任意分片的帧头，内容顺序和字节数一致 |
| trailers | 多值字段、空尾部字段、敏感标记；收到 trailers 前已经确认 EOF；尾部之后非法 DATA/HEADERS 报错 |
| 帧完整性 | DATA 长度不足、截断 varint、截断 HEADERS、超限字段；错误作用域保持正确 |
| 内容语义 | HEAD/204/304 的源 Body 完全不被轮询；接收非法内容报错；Content-Length 正确/过长/过短；CONNECT 分支不按普通内容误判 |
| 懒读取 | headers 返回后不主动读取 body；应用请求一帧时只做必要读取；不启动 per-body 接收任务 |
| 背压 | writer Pending 时不继续 poll 后续源帧；应用暂停时不创建消息队列；慢流下控制/QPACK 仍可前进 |
| 取消 | headers future、发送 future、接收 Body 在从未 poll 时 drop 仍清理；正常完成不重复 stop/reset |
| 部分轮询 | 取消一次 frame 等待后继续消费，不丢 varint/payload 前缀；取消整个 Body 只清理一次 |
| 非 I/O 等待 | 源 Body 永远 Pending 时远端 stop/连接关闭能结束发送；QPACK Pending 时 reset/GOAWAY/连接关闭能结束解码 |
| 竞态 | 终止发生于 waker 登记前/中/后均可观察；同时 Body 就绪与终止时不在已失败流继续写 |
| 错误来源 | 源 Body 错误保留 source；代理另一连接的 Body 错误不会错误关闭本连接 |
| 交换 | 上传未结束就交付响应头；服务端 drop 请求 body 后响应仍可发送；客户端 drop 响应取消上传；完整响应后允许上传继续 |
| 排空 | Body 持有时 GOAWAY 等待，正常消费或 drop 后解除登记；错误终态不被正常 EOF 覆盖 |

优先运行 h3x 单元/协议测试、dhttp endpoint 生命周期测试和真实 QUIC roundtrip。本文只完成设计，尚未执行上述实现验收。

## 12. 参考

- [HTTP/3 消息帧与取消语义](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1)
- [StreamBody：将标准帧 Stream 包装为 Body](https://docs.rs/http-body-util/latest/http_body_util/struct.StreamBody.html)
- [UnsyncBoxBody：Send 的装箱 Body](https://docs.rs/http-body-util/latest/http_body_util/combinators/struct.UnsyncBoxBody.html)

接收的具体 trailers 交付时机、装箱策略、终止通知接口和迁移顺序是本设计的选择；RFC 并不指定这些 Rust API。
