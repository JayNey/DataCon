# 安全与执行环境增量（v0.2）

本文件是 [v0.1 安全设计](../security-design.md) 的增量。未覆盖的授权边界、容器基线、路径校验、供应链与证据防篡改规则继续按 v0.1 执行。

## 1. 新增信任边界

v0.2 新增三类材料或出口：

1. **模型出口**。分析模型可能把源码片段、补丁、日志与假设送出控制面；默认必须离线。
2. **在线情报**。v0.2 允许从白名单来源获取公告快照，但外部内容仍只作数据。
3. **探索材料**。fuzz harness、种子语料、crash seed 与 campaign 构建制品进入轮次复用链，必须冻结来源并限制容器权限。

原有的“人工审批、确定性判定、工具枚举路由、外部文本不作为指令”四项边界不变。v0.2 只把审批对象从单计划扩展为“信封 + 首份计划”，并把轮次内准入交给可离线重算的 policy。family 的 child 串行执行，不因此放宽容器或执行槽位边界。

## 2. T14 模型出口

### 2.1 默认离线

- 未显式配置外部 endpoint 时，分析、假设生成与实验规划全部使用离线规则或测试替身，不发起任何外部模型请求。
- 外部模型是可选配置；启用时必须同时配置 endpoint 白名单、允许字段、脱敏规则、模型版本与 prompt 版本。
- 模型失败、超时、返回非法结构或触发脱敏拒绝时，回退到离线路径或阻断当前分析；不得通过放宽字段、跳过校验或改用未登记 endpoint 来“恢复”。

### 2.2 可送字段

只允许送出完成当前分析所需的最小字段集合：

| 允许 | 说明 |
| --- | --- |
| 已冻结的公告片段 | 去除本地路径、内部 URL、操作者标识 |
| 补丁 diff 片段 | 只含目标仓库的相对路径与 hunk 内容 |
| 源码片段 | 按符号与行号裁剪，去除注释中的凭证样式文本 |
| 公开 CVE 编号与版本标识 | 不含任务 ID、family ID 或证据路径 |
| 已审核的 harness 摘要 | 只送摘要，不送可执行内容或原始字节 |

禁止送出：宿主路径、数据库连接串、容器 ID、审核人身份、证据包路径、原始 seed 字节、未脱敏日志、其他任务内容、模型自身的系统提示或工具凭证。

### 2.3 脱敏与审计

- 送出前按固定规则脱敏：绝对路径替换为仓库相对路径；邮箱、令牌样式、私钥头、连接串与长十六进制随机串按模式遮蔽；日志中的控制字符与 ANSI 序列剥离。
- 审计记录包含：任务 ID、阶段、模型供应方、模型版本、prompt 版本、允许字段集合的摘要、脱敏规则版本、请求与响应的摘要、耗时、结果状态。该记录以 `model_audit` 角色进入 v2 证据包。
- T14 落地后，`model_audit` 成为 v2 `execution`/`campaign` 的必需角色；此前允许缺失，但出现时必须使用该角色，不得以其他角色代替。
- **offline 也必须写审计**：`provider` 固定为 `offline`，`outcome` 固定为 `offline`，`model_version` 与 `prompt_version` 写 `null`，`allowed_fields_digest` 与 `redaction_version` 仍必填。不得省略 `model_audit` 对象，不得把 `provider` 留空或写成 `null`。
- 审计只保存摘要与结构化字段，不保存未脱敏原文；原始响应进入受限制品目录，按 v0.1 证据权限管理。
- 模型输出只接受结构化 hypothesis（`kind=hypothesis`）。模型来源的 `kind=fact` 视为非法输出并阻断；确定性工具事实由工具结果与证据引用承载，不经模型出口转述。任何自由文本命令、shell 片段、可执行 harness 或工具参数都视为非法输出并阻断。

### 2.4 Endpoint 白名单

- endpoint 必须精确匹配配置中的 HTTPS 主机与路径前缀；拒绝 IP 字面量、重定向到非白名单主机与证书校验失败。
- 地址拒绝集与 T15（第 3.2 节）完全统一，IPv4 与 IPv6 适用同一拒绝集：私网、回环、链路本地、组播、保留地址、CGNAT `100.64.0.0/10`、未指定地址（`0.0.0.0/8`、`::/128`）、云元数据地址（如 `169.254.169.254`、`fd00:ec2::254`）以及 IPv4-mapped IPv6（如 `::ffff:127.0.0.1` 等解包后落入上述集合的地址）。
- 防 DNS 重绑定时点固定为：**DNS 解析 → 地址校验 → 直接向已校验 IP 建立 TCP/TLS 连接（显式固定 TLS SNI 与 HTTP `Host` 头，禁用跨重定向连接复用）→ 发送任何 HTTP 字节前再次校验 socket `getpeername()`**。
- 白名单变更需要维护者审核并记录版本；运行中的任务不得动态扩大白名单。

### 2.5 失败回退

| 失败 | 回退 |
| --- | --- |
| endpoint 不可达、超时或 5xx | 使用离线规则；记录降级事件，不改变判定 |
| 返回非 JSON 或未知字段 | 丢弃该响应；当前分析标记为 `ANALYSIS_ERROR` 或使用离线结果 |
| 脱敏规则命中禁止字段 | 阻止发送；记录拒绝原因 |
| 模型建议越出信封 | 不生成 ExperimentSpec；记录 `ENVELOPE_VIOLATION` 候选 |
| 模型建议试图改变判定或审批 | 忽略并记录审计事件；判定仍由六次回放产生 |

## 3. T15 在线情报

### 3.1 域名白名单

- 只允许配置中列出的公告、维护方与镜像来源域名；子域匹配必须显式列出，不做通配放行。
- 案例注册表记录每个来源的许可、允许用途与快照策略；未登记来源不得抓取。
- 离线案例只读取已固定快照，不发起网络请求；离线快照仍以 `intel_snapshot`/`license_record` 角色归档，不因离线而省略。

### 3.2 地址复检

- 解析域名后与 T14（第 2.4 节）使用同一套 IPv4/IPv6 拒绝集：拒绝私网、回环、链路本地、组播、保留地址、CGNAT `100.64.0.0/10`、未指定地址（`0.0.0.0/8`、`::/128`）、云元数据地址（如 `169.254.169.254`、`fd00:ec2::254`）以及 IPv4-mapped IPv6（如 `::ffff:127.0.0.1` 等解包后落入上述集合的地址）。
- 防 DNS 重绑定时点固定为：**DNS 解析 → 地址校验 → 直接向已校验 IP 建立 TCP/TLS 连接（显式固定 TLS SNI 与 HTTP `Host` 头，禁用跨重定向连接复用）→ 发送任何 HTTP 字节前再次校验 socket `getpeername()`**。
- 禁止使用环境代理绕过白名单；需要代理时只允许受控代理，并对目标做同样复检。

### 3.3 逐跳重定向校验

- 每一跳都重新执行 HTTPS、域名白名单与地址复检；任一跳失败即终止。
- **最大重定向 5 跳**；第 6 跳直接失败并记录跳数。拒绝 30x 到非白名单、私网、回环或非 HTTPS 目标。
- 不自动跟随跨域重定向到对象存储或第三方 CDN，除非该域已显式列入白名单。

### 3.4 传输、大小与超时

- 只允许 HTTPS；TLS 证书必须通过系统信任链校验，禁止关闭校验。
- 固定超时：**连接 10 秒、单次读取 30 秒、整次抓取总时长 60 秒**；任一层超时即失败关闭。
- **8 MiB 为压缩前线上传输体上限**；强制采用**流式边读边解压计数**——线上传输体超过 **8 MiB**、解压累计超过 **32 MiB** 或压缩比超过 **100:1** 时立即中断并关闭连接（禁止先全量解压进内存再判断），截断或超限内容不得进入快照。
- 抓取失败、内容截断或来源冲突时按[接口契约增量](interface-contract-delta.md)第 10 节归属 `MATERIAL_MISSING` / `SOURCE_CONFLICT` / `POLICY_DENIED`（并在审计 `detail.sub_reason` 记录 `REDIRECT_LIMIT_EXCEEDED`/`FETCH_TIMEOUT`/`SIZE_LIMIT_EXCEEDED`/`DECOMPRESSION_BOMB`/`LICENSE_REJECTED`），不得静默改用缓存。

### 3.5 不可变快照与许可

- 抓取结果写入内容寻址的不可变快照，记录来源 URL、采集时间、HTTP 状态、内容摘要、许可标识、重定向链摘要与采集工具版本；快照以 `intel_snapshot` 角色、许可以 `license_record` 角色进入 v2 证据包。
- T15 落地后，`intel_snapshot` 与 `license_record` 成为 v2 `execution`/`campaign` 的必需角色；此前允许缺失，但离线案例同样归档。
- 快照写入后只读；后续抓取产生新快照，不覆盖旧快照。
- 证据包引用快照摘要与许可记录；无许可或用途不符的材料以 `POLICY_DENIED`（审计 `detail.sub_reason=LICENSE_REJECTED`）阻断，不得进入复现流程。report 的 `intel` 只是摘要对象（快照摘要、许可标识、重定向链摘要），原始快照与许可正文分别由 `intel_snapshot`、`license_record` 文件角色承载。
- 外部文本在进入模型、日志与报告前按数据转义；公告中的指令不改变路由、工具授权或判定。T10 负责在 v2 角色表中预留 `intel_snapshot`/`license_record`/`model_audit`；T15/T14 只填充这些角色，不修改 v1/v2 已有结构。
- T11 的 `intel` 节点消费快照：快照缺失返回 `MATERIAL_MISSING`，来源冲突返回 `SOURCE_CONFLICT`，不得用未验证内容继续。T15 可先独立实现采集，但最终验收依赖 T10 的角色枚举与 T11 的 `intel` 节点。

## 4. fuzz 容器隔离

- fuzz 与 build/replay 使用同一套一次性容器基线：`--network none`、非 root UID、只读根文件系统、`--cap-drop ALL`、`no-new-privileges`、固定 seccomp profile。
- fuzz 容器额外限制：语料只读挂载；工作区可写但有上限；不得挂载 Docker socket、宿主凭证、证据目录或 campaign 目录；不得访问控制面网络。
- fuzz harness 是审核过的冻结材料，与 build recipe 同级；模型合成、改写或未审核的 harness 一律拒绝并给出 `HARNESS_REJECTED`。
- fuzz 输出只允许声明过的目录与文件角色；符号链接、设备文件、绝对路径、父路径与越界写入一律拒绝。
- 超时、OOM、PID 耗尽或磁盘写满时终止容器并记录限额事件；崩溃本身是观测，不是判定。

## 5. corpus 与日志预算

| 对象 | 预算与规则 |
| --- | --- |
| 种子语料 | 按 `seed_corpus_digest` 冻结；**总 64 MiB、单文件 8 MiB、文件数 4096**；新增语料必须进入新轮次信封 |
| crash seed | 固化字节与 SHA-256，附 provenance（campaign job、fuzz log digest、RNG seed）；不得用可变路径或模型生成文本代替 |
| fuzz 日志 | 沿用单次工具调用原始日志总量上限；按角色记录截断，截断影响证据完整性 |
| 证据文件 | 单文件、总字节与文件数上限沿用 v0.1（单文件 128 MiB、总 256 MiB、4096 个文件、1024 个目录）；目录单独计数，防止用大量空目录规避文件上限 |
| 轮次预算 | 受 `max_total_seconds`、`max_fuzz_seconds` 与 family 账本共同约束；fuzz 消耗同时扣总预算与 fuzz 子预算；耗尽进入 `BUDGET_EXHAUSTED` |

## 6. 准入与审核边界

- policy 准入只写 `admissions`，不得写 `reviews`；`reviews` 的唯一写入者是人工决议，且 v0.2 中 `reviews.job_id` 是 family job。
- 审核窗口期间 family 保持不可领取的 `AGGREGATING`，首份 child 持 `AWAITING_REVIEW` 与 `review_deadline_at`；`record_review`/`expire_review` 固定先锁 family、再锁首份 child，超时在同一事务把 child 与 family 置 `BLOCKED(REVIEW_EXPIRED)`，避免出现“child 已封、family 仍可领取”的半收敛状态。
- 每次人批都写 `family_approvals`；`approval_digest` 由 `{family_id, envelope_digest, first_plan_digest, reviewer_id, decided_at}` 计算并排除自身；换信封产生新 approval，`supersedes` 指向旧 approval。
- （D42）待审信封由 `family_envelopes` 承载，每个 family 至多一个 `status='pending'`；reject 把 pending 置 `rejected` 并收敛 child/family 到 `BLOCKED(REVIEW_REJECTED)`，审核超时置 `expired` 并收敛到 `BLOCKED(REVIEW_EXPIRED)`；换信封重批必须命中当前 pending，否则返回 `REVIEW_ENVELOPE_MISMATCH`。不会出现信封仍 pending 而执行已放行，或 child 已封而 family 仍可领取的半收敛状态。
- 每条 policy 准入必须可离线重算：给定信封（含 `mutation_limits`）、父审批摘要、seed 摘要、轮次号、预算账本快照与 predicate 版本，能重新得到同一结论。重算所需的信封正文与预算快照必须分别以 `envelope`、`budget_snapshot` 文件角色随 validation 证据归档，不能只依赖控制面当前状态。
- 无法离线重算的准入，必须在证据中显式标注“由 campaign bundle 佐证”，并记录 `supporting_bundle_digest`；不得伪装成可重算。
- 准入谓词变更需要新版本号并重新审批信封；旧轮次保留原 predicate 版本与结果。
- 人批与 policy 准入都写入只追加审计；事件至少包含 `job_id`、`parent_job_id`、`round_no`、摘要、predicate 版本、决定与时间。准入成功的事件名是 `round_admitted`，拒绝是 `round_admission_denied`。

## 7. 验收

1. 未配置外部模型时不发起网络请求；配置白名单后，越界 endpoint 与私网地址被拒绝。
2. 送出字段可由审计重建为允许集合；禁止字段与凭证样式文本不离开控制面；offline 时 `model_audit` 仍写入且 `provider=offline`。
3. 模型返回非法结构、超时、越权建议或 `kind=fact` 时回退或阻断，判定不变。
4. 在线情报的每一跳重定向都经过 HTTPS、域名与地址复检，超过 5 跳失败；连接 10 秒、读取 30 秒、总 60 秒与 8 MiB / 32 MiB / 100:1 上限生效。
5. fuzz 容器无外网、非 root、无宿主凭证与 socket；未审核 harness 被拒绝。
6. corpus 不超过 64 MiB / 8 MiB / 4096 个文件；crash seed 与日志受预算约束，超限可定位到角色与轮次。
7. policy 准入不产生 `reviews` 行；准入可离线重算，不能重算时有 campaign bundle 佐证；换信封后新 approval 通过 `supersedes` 可追溯。
8. 以上失败路径均不改变“模型假设不改变判定”的确定性边界，也不解除 family child 串行执行的单槽位约束。
