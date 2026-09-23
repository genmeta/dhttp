# Pishoo 服务接入边界

状态：职责与接口约定，尚未实现应用或网络运行行为。本轮决定由 Pishoo 完整负责 WASM，DHTTP 接收调用方组装的 Router。本文替代此前 DHTTP 内置 WasmApp、apis() 及私有 WIT 清单方案。

Pishoo 的应用约定参考 [身份级 WASM 沙盒与 OpenAPI](../../../pishoo/design/wasm-sandbox-design.md) 和 [整体设计](../../../pishoo/design/pishoo-wasm-db-redesign.md)。这些文档中尚存的 `dhttp::WasmApp`、由 DHTTP 注入 WASM 宿主设置等表述，以本次职责调整为准：相关加载、实例化和执行逻辑归 Pishoo。网络配置以 [DHTTP 顶层接口](top-level-review.md) 为准。

## 1. 唯一应用入口

```rust
let endpoint = Endpoint::load(servername).await?;
// router 由 Pishoo 组装，包含静态、代理、原生及 WASM 路由。
endpoint.listen(router).await?;
```

DHTTP 对 router 的约束继续是 `tower_service::Service<http::Request<Body>, Response = http::Response<B>>`。Pishoo 可以使用 Axum；DHTTP 不依赖、重导出或检查 Router 的具体实现，也不区分某次响应来自原生代码、代理还是 WASM。

| 责任 | DHTTP | Pishoo |
|---|---|---|
| 通信 | 名称与凭据、QUIC/TLS、HTTP/3、连接复用和共享网络 | 选择身份并交付应用服务 |
| HTTP 消息 | h3x 与标准 HTTP/body 的流式桥接、背压和取消 | handler、代理及 WASI HTTP 的业务适配 |
| 可信身份 | request.extensions 中的 ArcConnection / HandshakeSummary | Server 绑定、authority 核对及 daccess 授权 |
| 路由与发布 | 驱动同一个 Service 的 readiness 和 call | OpenAPI 解析、路径挂载、路由冲突、组件与文档配对发布 |
| WASM 运行 | 无专属接口或依赖 | 编译、imports 校验、Store/Instance、WASI 能力及 guest 任务 |
| 资源与关闭 | HTTP 交换、连接及网络任务的生命周期 | 身份总预算、guest/host I/O 回收、应用与身份取消 |

## 2. Pishoo 的应用描述与准入

一个 `.wasm` 是包含多个 handler 的代码加载单位，配套同名 `.openapi.json`，例如 `chat.wasm` 与 `chat.openapi.json`。Pishoo 静态读取 OpenAPI 3.1.x JSON，不执行 guest 获取路由清单。操作的 method/path 用于匹配和授权；operationId 可选，提供时在文档中唯一，用于标识和日志。

Pishoo 首版仅接受显式方法与字面量路径；未支持的模板路径、callbacks、webhooks、路径级引用等影响路由的构造拒绝加载。schema 可供文档和 SDK 使用，首版不承诺通用运行时 schema 校验；不因此收集完整流式 body。具体业务数据由 handler 校验。

普通 OpenAPI 可以不带 Pishoo 扩展。可选 `x-access` 是部署时的默认权限建议，不绕过既有 daccess 决策；`x-pishoo-execution` 只能进一步收紧身份沙盒能力。扩展解释、可信 SubjectId 适配、默认规则导入与 ACL 管理均属于 Pishoo/daccess，DHTTP 不读取它们。

Pishoo 从组件相对路径确定 AppId 与挂载前缀，逐条注册声明的 method/path，并在进入 guest 前授权；`index.wasm` 只发布声明的根级入口。未声明路径返回 404，已声明路径的未声明方法返回 405；HEAD/OPTIONS 业务入口必须显式声明。OpenAPI 的 servers 字段不改变 Server 身份、网络资源或挂载位置。

授权后剥离一次挂载前缀并保留 query，将标准 HTTP 请求交给 guest 自身路由。宿主鉴权使用可信 extensions；Pishoo 负责清洗和注入其保留的身份/API headers，投影给 guest 的 header 不作为宿主鉴权依据。

组件与文档共同形成一个稳定内容快照。缺文件、解析失败或声明摘要不符时拒绝候选，热更新保留旧 Router；只有两份文件均确认删除时才移除该应用。可选摘要存在时验证，没有摘要时仍需部署工具保证成对提交，不能用文件监听去抖代替原子发布。

这些规则由 Pishoo 实现。DHTTP 不新增 OpenAPI 模型、清单格式或业务 Request/Response 类型，也不提供专门的应用打包 SDK。

## 3. 身份沙盒与 Server 执行边界

一个规范化 Server 身份对应一个 WASM 沙盒；同身份的所有 App 共享 `/data`、能力上限、聚合资源账户和身份取消域。每次调用创建独立的 Store、Instance、ResourceTable 和请求私有 `/tmp`，只共享不可变编译代码，不跨请求复用可变 guest 内存。

同身份 App 属于同一信任域，拥有写能力时可能修改彼此的共享数据；不同身份的数据、上下文和资源账户分离。身份总预算覆盖新旧应用版本和并发调用，更新或切换 App 不能重置资源账户。

Pishoo 的 Server 执行边界覆盖静态、代理、原生处理与 WASM 的身份校验、总预算和完整请求生命周期。WASM 身份沙盒只约束 WASM 分支；普通 native handler 不会因一层 middleware 获得 WASM 或操作系统隔离。

文件能力、出站授权和每 API 的能力收紧全部由 Pishoo 施加到实际执行实例与宿主 I/O。首版权限管理由前端以真实主体直接调用 daccess，guest 不获得 ACL 写能力，也不能借出站或自调用绕过该限制。

## 4. 标准服务与完整交换生命周期

```text
DHTTP HTTP/3 → http::Request<Body> + 可信握手 extensions
  → Pishoo ServerGuard + Router
      ├─ 静态 / 代理 / 原生 handler
      └─ OpenAPI 路由 + daccess 准入
          → 身份沙盒账户与能力 → Pishoo WASI HTTP 适配 → guest
  → http::Response<B> → DHTTP HTTP/3 输出
```

DHTTP 流式传递 HTTP body/trailers、保持背压、处理连接与流取消。Pishoo 将标准 body 与 WASI HTTP 流互相转换，允许提前响应，并持有 guest task、host I/O、预算和内容快照直至执行回收。

Service 返回响应头、body EOF 与实际网络输出完成是不同阶段。DHTTP 负责跟踪实际 HTTP 输出和交换终态，Pishoo 负责关联应用任务；完成/取消的通用通知接缝尚待实现核对，不新增 WASM 专属 Context 或宿主注入接口。不能用一次 Service::call 返回或外包 timeout 宣称 guest 已经结束。

响应头前的应用失败由 Pishoo 转成 HTTP 错误响应，未处理的 Service 错误走 DHTTP 通用错误契约；响应头后的失败通过 body 错误及当前流终止传播，不关闭共享连接。HEAD/204/304 或替换响应 body 时，Pishoo 回收原执行，DHTTP 按 HTTP 语义完成最终输出。

移除单个 App 时由 Pishoo 撤销其路由并取消该应用执行，其他 App 和共享数据继续存在；删除身份时由 Pishoo 协调所有应用停止与 Endpoint.stop_listening/close。DHTTP 关闭交换时应触发通用应用取消衔接，Pishoo 等待 guest 与宿主任务清理；关闭某个身份不停止进程共享网络。

## 5. 当前同步范围

DHTTP 已删除 WASM 模块、feature、Wasmtime 依赖、专属错误及私有 WIT 声明。现存接口仍只有成员和 todo!() 占位。Pishoo 自身的 WASM、OpenAPI、沙盒与上述生命周期集成尚待实现；本轮未修改 Pishoo 仓库或运行其集成测试。
