# 开发任务清单增量（v0.2）

本文件只登记 T09–T15。v0.1 的 T01–T08 已完成或按 [v0.1 任务清单](../tasks.md) 执行，不在此重复。每项均按 Red → Green → Refactor 推进；T09 不创建 T10–T15 的测试代码。

## 依赖与并行

`T09 → T10 → {T11, T12, T13, T14}`；`T15` 可先做，最终验收依赖 T10 与 T11。

- T12 在 T10 完成后可与 T11 并行；但 T12 的图容量验收坐标（`test_verify_iteration_requires_round_and_budget_capacity`）依赖 T11 创建的 `tests/unit/test_orchestration_graph.py`（其余信封、准入、预算与复用部分可与 T11 完全并行）。
- T11 只验收图结构与节点幂等；policy 准入、轮次与预算容量的验收归 T12，避免 T11 依赖 T12 才能开工。
- T13 在 T10 完成后可与 T11、T12 并行；若 T13 先改 plan 结构，T12 的复用测试须等待其接口冻结。
- T14 从 T10 起并行；模型出口不阻塞 T11/T12/T13。
- T15 可以先独立实现采集与快照，但最终验收依赖 T10 的 `intel_snapshot`/`license_record` 角色枚举与 T11 的 `intel` 节点；T15 不修改已有 v1/v2 证据结构。
- 全程保持单执行槽位：family 的 child 串行执行，不因并行开发而引入并行 child。

## T09 v0.2 增量规范与 CI 门禁

- **目标**。在 `docs/spec/v0.2/` 建立十二份增量文档，冻结 D1–D44 的规范语言；扩展现有 REQ/TC 门禁以支持 v0.1/v0.2 路径作用域。不修改业务代码。
- **依赖**。v0.1 规范冻结；现有 `src/datacon/ci_gates.py` 与 `tests/contract/test_ci_gates.py`。
- **验收**。
  - 十二份文件存在，六份 ADR 均含标题、Status、Date 与 6 个二级节（Context、Decision、Alternatives considered、Consequences、对应 REQ、测试坐标），文件总行数（含空行）60–120 行。
  - README 含版本声明、冲突规则、文档地图、REQ/TC 规则与目标编排图；Mermaid 与边表覆盖同一完整边集，可被 T11 直接引用。
  - SRS delta 含新增 REQ-11..16 与修改 REQ-02/03/06/07/08/09；接口 delta 含 Request v2、Plan v2、Envelope（含 `mutation_limits`）、ExperimentSpec、BuildSpec、Admission、`family_approvals`、jobs CHECK、Evidence v2 字段表与完整 JSON 示例；安全 delta 含 T14/T15、fuzz 隔离、corpus 数值上限与 policy 不写 review；测试 delta 含 TC-11..16、T10–T15 失败测试坐标、循环确定性与 B04-A/B04-H。
  - 门禁 `ok: true`、`checked_markdown=27`（仓库其余 15 份 + 本目录 12 份，且集合包含本目录 12 份）；四条路径作用域用例先失败后通过。
  - T09 不新增 T10–T15 测试代码，仅新增四条门禁作用域用例；不新增 `xfail`、`skip`；`git status --short` 只出现 `?? docs/spec/v0.2/`、`src/datacon/ci_gates.py` 与 `tests/contract/test_ci_gates.py`（使用 `-uall` 时列出本目录 12 个文件）。
- **明确不做**。不改 `workflow.py`、`execution.py`、`evidence.py`、`examples/`、根 README、`docs/spec/` 根目录；不新增业务测试；不提交、不推送。

## T10 计划身份、child job 与证据 v2 版本分派

- **目标**。落地 D1、D2 的身份部分、D4、D7、D15、D17、D22、D23、D24，以及 D36、D38、D40、D42、D43：`jobs` 增 `family_id`/`job_kind`/`parent_job_id`/`round_no`/`job_contract_version`、按 `job_contract_version` 的完整 CHECK、轮次唯一与 campaign partial unique；新增 `family_approvals`、`family_envelopes` 与审批链；`submit` 返回 family job_id、`review` 接收 family job_id、`reviews.job_id` 挂在 family；child plan 绑定 family、轮次、父审批（首份为 null）、信封、双版本 `build_ref`、`experiment_digest` 与 `build_provenance_rules_version`；新增 `admissions` 表骨架与完整 v2 角色表（v0.1 27 个 + v0.2 新增 13 个）；证据保留 v1 常量并新增 v2 常量与按 `manifest.schema_version` 分派；v1 分支冻结旧 `_extract_compile_args` 副本；新增 `log/build` 与 `log/fuzz` 引用语法；落地 D36 的审核状态机与锁序（`reviews.job_id` 挂 family、`AWAITING_REVIEW` 留在首份 child、family 保持 `AGGREGATING`、先锁 family 再锁 child、超时同事务收敛）；落地 D42 的待审信封身份与五元组幂等键（`family_envelopes`、`--envelope-digest`、`REVIEW_ENVELOPE_MISMATCH`）；落地 D43 的 COMPLETED 证据兼容（`finish_execution` 白名单与 007 `jobs_archived_evidence_check`）；落地 D38 的 release 解耦（`contracts.SCHEMA_VERSION_V2=2`、`release.CONTRACT_VERSION` 字面量 `1`、排空集合扩展到 v2 非终态、`rollback_release` smoke 前后各一次 drain gate、迁移从 `010_*.sql` 起）。
- **依赖**。T09。
- **关联需求与用例**。REQ-11、REQ-16、REQ-03、REQ-08；TC-11、TC-16、TC-03、TC-08。
- **验收**。
  - 迁移可重复执行；同一 `(parent_job_id, round_no)` 第二次插入失败；family/campaign/round 的身份组合被 CHECK 接受/拒绝；v1 行新身份列必须全为 NULL；`parent_job_id=job_id` 被拒绝且 `parent_job_id` 必须指向 `job_contract_version=2 AND job_kind='family'`；每个 family 至多一个 campaign；父 job 只聚合。
  - 首份计划 `parent_approval_digest=null` 且计入 `plan_digest`；`family_approvals` 的 `approval_digest` 由 `{family_id, envelope_digest, first_plan_digest, reviewer_id, decided_at}` 计算并排除自身；换信封产生新 approval 且 `supersedes` 指向旧 approval。
  - `plan_digest` 对完整 11 个 Plan v2 新增字段（含 `schema_version`、`build_spec`、`compile_flags`、`build_ref` 两版 artifacts 等）以及保留的 `build_recipe_digest` 与 campaign `inputs=null` 分别敏感（完整封闭字段集见[接口契约增量](interface-contract-delta.md)第 3 节）。
  - **审核状态机（D36）**。`record_review` 不再按同一个 `job_id` 查 `plans`，改为按 family 定位首份 child（`job_kind=campaign`，或 fixed 的 `job_kind=round AND round_no=1`）及其 plan；该实现变更不修改 `reviews` 表结构。状态迁移、锁序与三步校验顺序以[接口契约增量](interface-contract-delta.md)第 9.1 节为准：首次 approve 在同一事务写 `reviews(job_id=family)` 与 `family_approvals(supersedes=null)`，reject 不写 approval；`expire_review(child, generation)` 先读不可变 `parent_job_id`、复核 `AWAITING_REVIEW`/generation/lease，再在同一事务收敛 child 与 family 并归档 blocked bundle；换信封重批只锁 family、只追加 `family_approvals`，不重写 `reviews`。幂等键为五元组 `(family_id, first_plan_digest, envelope_digest, decision, reviewer_id)`，先验 `--plan-digest == first_plan_digest`，再按 `(family_id, envelope_digest)` 区分 `idempotent`/`conflict`/`expired`，最后对不存在或非当前 `pending` 返回 `REVIEW_ENVELOPE_MISMATCH`，均不新增行；`decided_at` 以 6 位小数 UTC 参与哈希。
  - **审核重批信封（D42）**。新增 `datacon propose-envelope FAMILY_ID --request envelope.json` 入口写入新待审信封（含 `review_deadline_at`）；`record_review` 增加 `--envelope-digest`（首轮可省略，换信封重批必填），`--plan-digest` 始终等于 `first_plan_digest`。`family_envelopes` 以 `UNIQUE(family_id, envelope_digest)` 与 partial unique index（每 family 至多一个 `pending`）落地，并支持换信封待审超时收敛 family 到 `BLOCKED(REVIEW_EXPIRED)`；完整状态迁移见[接口契约增量](interface-contract-delta.md)第 9.1 节。`reviews` 表结构不变；`family_approvals` 通过 `UNIQUE(family_id, envelope_digest)` 兜底。
  - **COMPLETED 证据兼容与无租约收敛（D40/D43）**。`finish_execution` 仅用于持有有效 worker lease 且处于 `RUNNING`/`ARCHIVING` 的 child job（含 `campaign` child 落 `COMPLETED`，archived 分支要求 `evidence_path` 与 `evidence_digest` 同时非空）；新增无执行租约的 `complete_family(family_id, evidence_path, evidence_digest)` 将 family 从 `AGGREGATING → COMPLETED` 收敛并设置 `evidence_status='archived'` 与非空指针，满足 007 `jobs_archived_evidence_check`，且 `family.json` 不被当作 `bundle_kind`（不新增角色或 bundle kind）。本任务验 007 CHECK 兼容、两条收敛接口契约与 `family.json` 不被当作 `bundle_kind`；`family.json` 落盘、崩溃恢复补收敛、`status` 展示与 `export --family` 字节一致归 T12。
  - **终态与 release 解耦（D38/D40）**。迁移 007 的 `INCONCLUSIVE`/`verdict=NULL`/`archived` 组合保持有效；新增 v2 终态 `COMPLETED`（`verdict`/`reason_code` 为 null、`evidence_status='archived'`），`claim_next` 不领取，排空门禁不包含。`contracts.SCHEMA_VERSION` 保持 `1` 并新增 `SCHEMA_VERSION_V2=2`；`release.CONTRACT_VERSION` 改为字面量 `1` 或独立常量，不依赖 `contracts.SCHEMA_VERSION`。保留 `state.RELEASE_ACTIVE_STATES`（v1 3 状态）不破坏 v1 升级保留 `AWAITING_REVIEW` 的基线契约，新增 v2 排空条件 SQL（针对 `job_contract_version=2` 检查 7 个非终态 `QUEUED`/`PREPARING`/`AWAITING_REVIEW`/`AGGREGATING`/`READY`/`RUNNING`/`ARCHIVING` 及 `state='BLOCKED' AND workflow_synced=false`），由 `PostgresPromotionBackend.active_slots()` 与 `switch()`（含 `rollback` 分支）共同执行；`rollback_release` 在 smoke 前后各执行一次 drain gate，回滚静默窗口须对 `submit` 施加共享发布锁或入口停写以防竞态插入新 v2 `QUEUED` 任务；未使用的 `release.ACTIVE_JOB_STATES` 同步或删除。新增迁移从 `010_*.sql` 起，纯增量迁移冻结后登记到 `ROLLBACK_COMPATIBLE_MIGRATIONS`（文件名 + SHA-256），未登记导致回滚阻断属预期行为。
  - v2 角色表包含 `normal_output`、`normal_error`、`asan_log`、`case_config`、`symbolizer_log` 与 `envelope`、`budget_snapshot`、`build_provenance`。
  - v1/v2 回滚围栏有测试：v2 非终态 job 存在时 v1 领取路径不得误领，排空集合必须包含 `QUEUED`、`PREPARING`、`AWAITING_REVIEW`、`AGGREGATING`、`READY`、`RUNNING`、`ARCHIVING` 与 `BLOCKED` 且 `workflow_synced=false`；回滚 gate 阻断残留；本版采用排空/静默，不引入独立队列。
  - T09 的四条路径作用域用例保持全绿，新增身份与分派测试按 [测试计划增量](test-plan-delta.md) 通过。
  - v1 bundle 继续通过冻结分支校验；v1 job 可 export、可 verify、不可 re-run；无在线回填。
- **明确不做**。不实现 campaign 搜索、预算扣减、构建溯源核对面、模型出口或在线情报；不改 v1 证据内容；不引入新存储后端。

## T11 目标编排图与两条循环

- **目标**。按 [README](README.md) 第 5 节落地 `prepare → intel → version → route → patch/source/reverse → hypothesis_aggregator → review → build → build_diagnose → campaign/verify → archive`，以及 family 分支 `prepare → AGGREGATING → archive`；实现 campaign 分支、构建诊断重试循环与验证迭代循环；节点重入 no-op。图与边表必须覆盖 T11 边集测试引用的完整边集，包括 `review → archive`、`build_diagnose → verify`、`build_diagnose → archive`。
- **依赖**。T10。
- **关联需求与用例**。D21、D34、REQ-04、REQ-11；TC-04、TC-11。
- **验收**。
  - 图的节点名与边可枚举，并与 README 的 Mermaid 和完整边表逐条一致；campaign 分支可挂载；`reverse` 只归档 `UNSUPPORTED_TARGET`。
  - `build_diagnose` 对可重试失败最多额外重试一次；重试耗尽或溯源失败进入 `archive`，不继续 `verify`。
  - `campaign → hypothesis_aggregator` 与 `verify → hypothesis_aggregator` 是 family 级创建下一轮 child 的逻辑转移；当前 child 自己完成 `archive`，不能在同一 campaign job 里继续跑 verify。
  - family job 使用不可领取的 `AGGREGATING` 状态，`prepare` 进入该分支，聚合结束进入 `archive`；不得用 `RUNNING` 表示聚合。
  - family 的多个 child 串行执行；同一时刻只有一个执行槽位。
  - 同一节点以相同幂等键重入时不重复 build、replay、admission、charge 或 archive。
- **明确不做**。不实现二进制逆向、Ghidra、VM 后端；不扩展新的 Agent 类型；不改变六次回放判据；不在本任务实现 campaign 搜索算法；不验收 policy 准入或预算容量（归 T12）。

## T12 探索信封、自动准入、预算账本与 campaign/validation 复用

- **目标**。落地 D2、D3、D5、D6、D8、D9、D10、D12、D26、D29、D32、D33，以及 D36、D37、D39、D40、D41、D43：信封与摘要（含 `mutation_limits`）；人批首份计划（campaign 或 fixed round 1）+ `family_approvals` 审批链 + policy 自动准入；`admissions` 独立表与 `round_admitted` 审计；family 级预算账本与 `(job_id, step_key, attempt_no)` 幂等扣费；campaign child 建一次双版本并搜索、不产 verdict；validation 只做六次回放；validation 证据自包含并带按两版记录的 `reuse_origin`；fixed 的退化信封与 null `build_ref`/`reuse_origin`；crash seed 固化与 provenance；fuzz harness 冻结；`status`/`export --family` 输出；fuzz 容器隔离与语料只读；D37 marker 双标规则；D39 证据固定路径；D40 campaign/family `COMPLETED` 终态；D43 的 `family.json` 落盘、`export --family` 根 `family.json` 字节一致与 `status` 的 `evidence_path`/`evidence_digest` 展示。
- **依赖**。T10；可与 T11 并行（其中图容量验收坐标依赖 T11 的 `tests/unit/test_orchestration_graph.py`）。
- **关联需求与用例**。REQ-12、REQ-14、REQ-07、REQ-16；TC-12、TC-14、TC-07、TC-16。
- **验收**。
  - 首份计划人批写 `reviews`（job_id=family）与 `family_approvals`；换信封产生新 approval；policy 准入不写 `reviews`；每条准入可离线重算，不能重算时带 campaign 佐证；`round_admitted`/`round_admission_denied` 事件成对可查。
  - 审核状态机与锁序复用 T10 的 `tests/integration/test_review_locks.py` 中 D36 四条与 D42 四条坐标，复验重批后的 approval 链尾、待审信封与 policy 边界；不另起重复坐标，也不修改 `reviews` 表结构。
  - `mutation_limits` 进入 `envelope_digest`；`ExperimentSpec.mutation_constraints` 逐项 subset；fixed 的 `allowed_ops=[]`、`max_input_bytes=0`。
  - `budget_charges` 含 `family_id`、`attempt_no`、`fuzz_seconds`、`charge_kind`；同一 attempt 恢复不重复扣费，新 attempt 新扣费；fuzz 同时扣两档预算；并发扣减不透支。并发预算测试只用两个数据库连接模拟竞争，验证 SQL 原子性，不代表生产多 worker；family 的 child 仍串行执行。
  - `round_no <= max_rounds` 由 predicate 检查；`UNIQUE(parent_job_id, round_no)` 只防重复轮次；耗尽返回 `BUDGET_EXHAUSTED`。
  - report 的 `budget` 含 6 个字段且可由 charge 按 family 重建；`status` 返回 family（`AGGREGATING`）、campaign、rounds 与含 fuzz 字段的 budget；`export --family` 聚合导出 campaign 与每轮独立 bundle。
  - campaign 归档后经 `finish_execution` 落 `state=COMPLETED`，family 运行中 `AGGREGATING`、归档时落盘 `family.json` 并调用无执行租约的 `complete_family` 落 `COMPLETED`；若末轮 child 已归档终态但进程在 `family.json` 落盘或提交前崩溃，worker 恢复扫描幂等补落盘 `family.json` 并调用 `complete_family` 收敛；`verdict`/`reason_code` 为 null、`evidence_status='archived'`，不再用 `INCONCLUSIVE` 表示 campaign 完成。`status` 展示 `evidence_path`/`evidence_digest` 指向该索引且满足 007 的归档 CHECK；导出根 `family.json` 与归档件字节一致。
  - v2 证据使用固定路径（见[接口契约增量](interface-contract-delta.md)第 8 节）：`metadata/execution.json`、`metadata/probe.json`、`metadata/case.json`、`build/{version}/metadata.json`、`build/{version}/build.log`、`build/{version}/parser`（默认单产物名）、`build/{version}/build_provenance/{compile_commands.json,cc-shim.log,shell-face.log}`、`replay/{version}/{phase}/{stdout.log,stderr.log,metadata.json}`（18 个条目）、`plan.json`、`review.json`/`admission.json`、`envelope.json`、`budget/{snapshot,ledger,charges}.json`、`experiments/*.json`、`model/audit.json`、`intel/{snapshot,license}.json`；review 与 admission 按轮次二选一，`build_provenance` 必需角色校验按分阶段生效归 T13。
  - marker 按 D37：`tests/integration/test_fuzz_isolation.py`、`tests/integration/test_toolchain_image.py` 与 sandbox/build/replay 容器用例必须**双标 `postgres`+`docker`**；只标 `docker` 会落入 contract 组，禁止；`asan` 用例禁止叠 `postgres`。
  - campaign child 有 family、parent、`round_no=null`、独立 plan 和人批首份计划，不产 verdict；campaign bundle 的 `build_ref`/`reuse_origin` 为 null；0 crash 的 campaign 允许没有 `crash_seed`，但必须有 `fuzz_log` 与 `fuzz_provenance`；fixed execution 的 envelope 非空但 `build_ref`/`reuse_origin` 为 null；复用型 validation 两者非空，任一版本摘要不符返回 `REUSE_MISMATCH`。
  - fuzz 容器沿用无外网、非 root、只读根、cap-drop、no-new-privileges、seccomp；语料只读挂载，输出目录受限，日志/corpus 受预算约束。
  - v2 构建记录与构建容器只含构建材料，回放记录保留 `input_digest`；v1 旧包继续要求两个 input 别名并通过冻结回归。
  - crash seed 含字节、SHA-256、campaign job、fuzz log digest 与 RNG seed；未完成六次回放不得出结论。
  - 未审核或模型合成的 harness 在执行前返回 `HARNESS_REJECTED`。
- **明确不做**。不新增 fuzz 引擎或改变 libFuzzer 边界；不允许 LLM 合成 harness；不引入工具链镜像 v2；不实现 B05 基准；不做二进制目标；不解除单执行槽位。

## T13 构建溯源、生效参数与工具链边界

- **目标**。落地 D13、D14、D31、D35、D41：统一 `BuildSpec`（cmake/make/shell，统一通过 `env` 注入 `CC` shim，`install` 可选）；plan 显式 `compile_flags` 与 `build_provenance_rules_version`；固定模板注入；CMake `compile_commands.json`、Make `cc-shim.log`、shell `shell-face.log` 及 `shell_face_digest`/`shell_face_review` 单独审核；多编译单元解析与封闭 7 项连写/分写归一化集合（见[接口契约增量](interface-contract-delta.md)第 5 节），保留顺序，`-I a -I b` ≠ `-I b -I a`；判据“声明 ⊆ 生效（多重集），两版共同编译单元生效有序序列逐一严格相等”；无核对面在冻结阶段返回 `BUILD_PROVENANCE_MISSING`；核对面原文以 `build_provenance` 角色归档并在 T13 落地后成为 `execution`/`campaign` 必需角色；固定镜像工具边界、release/v1 读取边界（D35）与按案例升级镜像 v2 的规则。
- **依赖**。T10；可与 T11、T12 并行。
- **关联需求与用例**。REQ-15、REQ-06、REQ-03；TC-15、TC-06、TC-03。
- **验收**。
  - 声明未生效、两版生效不等、顺序不同（`-I a -I b` vs `-I b -I a`）、无核对面均失败关闭；错误信息可定位版本、声明项、顺序差异与核对面。
  - `-I include` 与 `-Iinclude`、`-L dir` 与 `-Ldir`、`-l foo` 与 `-lfoo` 归一后等价；声明侧与生效侧使用同一归一化函数；`-I a -I b` 与 `-I b -I a` 的反例仍判不相等。docker 组用例（含 `tests/integration/test_toolchain_image.py`）双标 `postgres`+`docker`。
  - CMake 与 Make 成功路径分别采集并归档核对面原文；shell 配方没有 `shell_face_review` 时不计为可比；`shell_recipe_digest` 不被当作核对面。
  - 固定镜像已有 cmake、make、autoconf、automake、libFuzzer；缺少 pkg-config、libtool、ninja、git 的案例不被默认假设可用。
  - Oniguruma 类案例不要求新镜像；确实需要缺失工具的案例才使用工具链镜像 v2。
  - `build_provenance_rules_version` 进入 plan 与 report，并计入 `plan_digest`。
  - release smoke/B03 本任务保持 v1 兼容路径，发布 manifest 的 `contract_version` 固定为 `1`，`release.CONTRACT_VERSION` 不依赖 `contracts.SCHEMA_VERSION`；回滚 drain gate 使用扩展后的 v2 非终态集合；v2 smoke 另立后续任务，不在 T13 中静默混入。
- **明确不做**。不向固定镜像安装缺失工具；不把 shell legacy 直接改成自由脚本；不引入新构建系统；不修改 v1 计划的只读语义；不实现 v2 发布 smoke。

## T14 模型出口与 ExperimentSpec

- **目标**。落地 D11、D27、D28、D30 与修改后的 REQ-09、REQ-13：ExperimentSpec 九字段与 `expected_signature` 统一签名；模型只产 hypothesis（`AgentOutput` v2 禁止模型 `kind=fact`，确定性事实走工具结果）；默认离线；endpoint 白名单；字段允许集与脱敏；模型/prompt 版本审计写入 `model_audit`，offline 也必须写 `provider=offline`；失败回退；假设不改变判定；B04-A 保持 v0.1 门禁，新增 B04-H hypothesis quality 报告与人工标注集。
- **依赖**。T10；可从 T10 起与 T11/T12/T13 并行。
- **关联需求与用例**。REQ-13、REQ-09；TC-13、TC-09。
- **验收**。
  - 默认离线零外部请求；非白名单 endpoint、私网与回环被拒绝；offline 仍写 `model_audit` 且 `provider=offline`。
  - 审计含模型版本、prompt 版本、允许字段摘要与脱敏规则版本；禁止字段不外送。
  - 模型故障、非法输出、`kind=fact` 或越权建议回退/阻断，策略不变；不触发未登记工具。
  - ExperimentSpec 出信封、mutation 超出上限或签名不匹配被拒；`operation`/`access_size` 缺失/存在不一致不算匹配；删除 hypothesis 不改变六回放判定。
  - B04-H 报告含 end-to-end precision、accepted precision、recall、rejection_rate 与样本量；`annotation_version` 形如 `b04-annotations-v1+<摘要>`（摘要带 `sha256` 前缀）且冻结；人工标注集是本任务显式工作项。
  - B04-A 六类 Agent 场景与路由/可追溯/越权指标仍按 v0.1 执行，是发布门禁；B04-H 不替换 B04-A。T14 落地后 `model_audit` 成为 `execution`/`campaign` 的必需角色，缺该角色的包验包失败。
- **明确不做**。不接入新的模型供应方；不把外部模型设为默认；不许模型批准计划、改预算、提交终态或合成 harness；不在本任务实现 B04 的真实案例拍摄，只做离线标注集评测。

## T15 在线情报

- **目标**。落地 D44、修改后的 REQ-02 与安全设计增量第 3 节：域名白名单、统一 IPv4/IPv6 地址拒绝集与直连 IP/`getpeername()` 复检、逐跳重定向校验（最多 5 跳）、HTTPS、超时（连接 10s/读取 30s/总 60s）、流式边读边解压计数上限（压缩前线上传输 8 MiB、解压后 32 MiB、压缩比 100:1）、不可变快照与许可门禁；外部文本只作数据。
- **依赖**。可以先独立做；最终验收依赖 T10 的角色枚举与 T11 的 `intel` 节点。
- **关联需求与用例**。REQ-02、REQ-16；TC-02、TC-16。
- **验收**。
  - 非白名单域、私网、回环、链路本地、云元数据地址与非 HTTPS 请求均失败关闭。
  - 每个重定向跳点重新校验；超过 5 跳、超时、超过 8 MiB/32 MiB/100:1 与截断有确定原因码。
  - 快照内容寻址、只读，记录来源、采集时间、摘要、许可、重定向链摘要与工具版本；以 `intel_snapshot`/`license_record` 角色进入 v2 证据包；离线快照同样归档。
  - report 的 `intel` 只是摘要对象；原始快照与许可正文不内联进 report。
  - T11 的 `intel` 节点消费快照；缺失返回 `MATERIAL_MISSING`，冲突返回 `SOURCE_CONFLICT`，不使用未验证内容。
  - 公告中的伪造指令不改变路由、工具授权或判定。T15 落地后 `intel_snapshot` 与 `license_record` 成为 `execution`/`campaign` 的必需角色（离线案例同样归档）。
- **明确不做**。不实现通用网页代理、爬虫或搜索引擎；不抓取未登记来源；不把在线内容写入模型训练；不改变离线案例路径。

## 后续（不进本轮）

- 二进制目标、Ghidra、CodeQL、VM 执行后端、远端对象存储与跨任务向量检索。
- B05 基准与真实案例扩大验收。
- 工具链镜像 v2 的默认切换；仅在 T13 证明某案例确实缺少工具后按案例引入。
- v2 发布 smoke 与发布世代迁移；本轮 T13 只保持 v1 release smoke/B03 兼容路径。
