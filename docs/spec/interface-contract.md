# 接口与数据规范

**契约版本** `1`

以下命令、结构和持久化记录均为设计接口。JSON 使用 UTF-8。时间戳为 UTC RFC 3339，时长以秒计，空间以 MiB 计，内容摘要使用 `sha256:<64 位小写十六进制>`。

## CLI

- `datacon submit --request request.json` 校验并提交，输出 `job_id` 和 `state`。
- `datacon status JOB_ID` 返回任务状态、阶段、待审计划、原因码及证据引用。
- `datacon review JOB_ID --plan-digest DIGEST --decision approve|reject` 以当前操作者身份写入决议。重复的同一决议幂等，冲突决议返回错误。
- `datacon worker` 领取队列中的任务；进程重启后检查持久化尝试并继续。
- `datacon export JOB_ID --out DIR` 导出已封存的证据包。
- `datacon verify-bundle DIR` 离线校验。CLI 退出码 `0` 表示命令成功，`2` 表示参数或契约错误，`3` 表示当前状态、权限或证据阻断操作，`1` 表示其他操作错误。复现结论通过状态字段返回。

## 请求与案例

```json
{
  "schema_version": 1,
  "cve_id": "CVE-2099-0001",
  "target": {
    "kind": "source",
    "case_id": "fixture-c-parser",
    "goal": "验证固定输入在缺陷版触发预期 ASan 异常"
  },
  "limits": {
    "prepare_seconds": 600,
    "execute_seconds": 1200,
    "replay_seconds": 10,
    "cpu": 2,
    "memory_mib": 2048,
    "pids": 128,
    "scratch_mib": 512
  }
}
```

示例编号仅用于合成 fixture，禁止发起外部查询。真实案例通过本地案例注册表关联 CVE 和允许来源。请求必须声明版本、CVE 编号、目标类型、案例 ID 与非空目标，预算字段可省略并使用 SRS 默认值。预算字段必须为正整数，最大值为对应默认值；回放上限不得大于执行上限。目标类型枚举为 `source|binary`。拒绝未知字段和重复 JSON 键。

注册的案例描述材料来源模式（`fixture|public_snapshot`）、匹配的 CVE、仓库来源与许可、双版本、补丁出处、依赖快照、镜像摘要、构建配方、harness、候选与正常种子、预期退出码、正常输出断言和目标 ASan 签名。注册表引用不可变制品。Git 完整对象 ID 按仓库对象格式校验，计划固定原始 tag 解析结果。

## Agent 与工具接口

- `AgentInput` 字段为 `job_id`、`stage`、`state_version`、`deadline_at`、可空的 `plan_digest`、`inputs`（具名制品引用）和 `policy_version`。
- `AgentOutput` 字段为 `outcome`（`ok|blocked|error`）、`artifacts`、`findings` 和可空的 `reason_code`。每条 `finding` 有 `kind`（`fact|hypothesis`）、`statement`、`confidence`（`low|medium|high`）、`evidence_refs`。事实须有可解析的引用。
- `ToolRequest` 字段为 `tool_id`、`job_id`、`step_key`、`attempt_no`、按工具类型校验的 `params`、`input_refs`、`deadline_at`、`policy_version`，执行阶段另带 `plan_digest`。工具由枚举路由，如 `git.resolve`、`git.diff`、`tree_sitter.extract`、`sandbox.build`、`sandbox.replay`。构建与回放只接收已注册配方及计划绑定的制品。
- `ToolResult` 字段为 `status`（`completed|policy_denied|infra_error|resource_limited`）、可空的 `reason_code`、可空的 `exit_code` 与 `signal`、`duration_seconds`、`limits_hit`、`artifacts` 和 `truncated_roles`。完成状态可携带目标非零退出及 ASan 异常。
- `ArtifactRef` 字段为 `role`、`media_type`、`size_bytes`、`digest`、`relative_path`。工具输出的引用必须校验摘要与访问范围后才能被下游消费。

## 共享状态与审核

- `Job` 保存请求、提交时间、操作者、阶段、状态版本、执行代次、租约和各阶段截止时间。状态流为 `QUEUED → PREPARING → AWAITING_REVIEW → READY → RUNNING → ARCHIVING → 终态`。准备、审核和执行均可提前进入归档。
- 准备期限在首轮领取时固定。审核期限自计划挂起起为 24 小时。执行期限在获批后首轮执行领取时固定。阶段期限随重启保留。准备和执行阶段各预留预算的一成且最多 60 秒用于归档。审核拒绝或到期后单独允许最多 60 秒归档。
- `Plan` 固定案例配置、双版本、依赖、镜像、配方、harness、输入、签名、资源和策略。使用固定字段类型和规范化 JSON 计算摘要，字段排序和 UTF-8 编码由契约测试固定。审核记录 `Review` 保存 `job_id`、`plan_digest`、`reviewer_id`、`decision` 和 `decided_at`。首次决议与状态更新在同一业务事务提交。审核时限约束决议的提交时间。已获批的原计划受执行期限约束。
- `Attempt` 记录阶段、步骤、尝试号、执行代次、容器标识、输入摘要、状态与结果引用。 `GraphState` 记录任务 ID、阶段指针和最近读到的状态版本。
- 终态为 `REPRODUCED|NOT_REPRODUCED|INCONCLUSIVE|BLOCKED|FAILED`。前三者使用 SRS 判据。典型原因码为 `INVALID_REQUEST`、`MATERIAL_MISSING`、`SOURCE_CONFLICT`、`UNSUPPORTED_TARGET`、`REVIEW_REJECTED`、`REVIEW_EXPIRED`、`PLAN_MISMATCH`、`POLICY_DENIED`、`BUILD_FAILED`、`RUN_INCOMPLETE`、`DEADLINE_EXCEEDED`、`EVIDENCE_WRITE_FAILED`。归档无法按时完成或存储不可用时，终态为 `FAILED`，任务记录保留先前判定、错误和空制品引用。

## 证据包

目录包含 `manifest.json`、`report.json`、`report.md`，以及按角色归档的计划、审核快照、版本依据、构建日志、种子、运行元数据和原始诊断。阻断与失败时收录已有材料，报告列出缺失项及原因。

- 清单记录 `schema_version`、`job_id` 和逐文件条目，每条有相对路径、角色、字节数和 SHA-256。清单自身由任务记录保存摘要。
- 报告记录目标、状态、原因、两个提交、工具链及镜像摘要、参数和预算、种子摘要、每次回放的版本与观测、判定规则及证据引用。人读版本从同一结构化报告渲染。
- 校验器拒绝重复条目、绝对路径、父路径、符号链接、缺失、额外文件和摘要不符。哈希校验检查清单与文件是否一致；核验来源时另比对受信任务记录中的清单摘要。
