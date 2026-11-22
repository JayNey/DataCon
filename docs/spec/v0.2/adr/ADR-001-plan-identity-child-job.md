# ADR-001 计划身份与 child job

**Status** Accepted  
**Date** 2026-11-21

## Context

v0.1 把“一次任务”与“一份计划”绑定：一个 job 在准备阶段冻结一份 plan，人工批准后执行一次构建与六次回放，终态由该 plan 的观测决定。这个模型适合单次复现，却无法表达同一 family 内的多轮探索：搜索会产出一个候选 seed，验证要复用同一对构建制品，而每轮的输入、实验与判定又必须可独立追溯。

若继续在一个 job 上原地修改 plan，会破坏 v0.1 的审核语义：已有 `reviews` 通过 `plan_digest` 绑定计划，计划一变，旧批准就必须失效；但若每轮都要求人工重新批准，探索循环又会被审核时延切断。规范需要把“family 聚合”“轮次执行”和“人工审批对象”拆开。

另一个约束来自复用：campaign 会先构建两版并做搜索，validation 轮次只做六次回放。若 validation 重新构建，两版制品可能与 campaign 不同，复用就失去意义；若 validation 直接引用 campaign 目录而不固化来源，campaign 被移动或清理后证据就无法离线校验。因此身份必须同时绑定“哪一轮”和“复用了哪次构建”。

## Decision

1. **一个 round 一个 child job**。每个探索轮次创建独立 child job，拥有自己的 plan、attempt、admission、预算扣减与证据包。父 job（`job_kind=family`）是 family 的聚合记录，只保存 family 身份、审批链、预算账本、轮次索引与终态汇总，不重复执行子轮次。campaign 是 special child（`job_kind=campaign`），不是 round：它构建一次双版本并做搜索，不产 verdict。fixed 模式 = 一个 family + 一个 `round_no=1` 的 round，没有 campaign。family 的多个 child **串行**执行（D29），不解除 v0.1 的单执行槽位。
2. **数据库身份**。`jobs` 增加 `family_id`、`job_kind`、`parent_job_id`、`round_no` 与 `job_contract_version`。规则：family 的 `parent_job_id`、`round_no` 为 null 且 `family_id=job_id`；campaign 与 round 的 `parent_job_id=family_id`、`parent_job_id<>job_id`，campaign 的 `round_no=null`，round 的 `round_no>=1`。`job_contract_version=1` 的 v1 旧行四列全为 NULL；`=2` 的 v2 新行必须满足按 kind 的完整 CHECK。以 `UNIQUE(parent_job_id, round_no)` 保证同一 family 下轮次唯一，以 partial unique index 保证每个 family 至多一个 campaign，`parent_job_id` 外键引用 `jobs(job_id)`：

```sql
CHECK (job_contract_version IN (1, 2))
CHECK (
  (job_contract_version = 1
   AND family_id IS NULL AND job_kind IS NULL
   AND parent_job_id IS NULL AND round_no IS NULL)
  OR
  (job_contract_version = 2 AND (
    (job_kind='family' AND parent_job_id IS NULL AND round_no IS NULL AND family_id=job_id)
    OR
    (job_kind='campaign' AND parent_job_id IS NOT NULL AND round_no IS NULL
     AND family_id=parent_job_id AND parent_job_id<>job_id)
    OR
    (job_kind='round' AND parent_job_id IS NOT NULL AND round_no IS NOT NULL AND round_no>=1
     AND family_id=parent_job_id AND parent_job_id<>job_id)
  ))
)
CHECK (job_contract_version = 1 OR (job_kind IS NOT NULL AND family_id IS NOT NULL))
```

最后一条守卫是必要的：SQL 的 `CHECK` 在表达式为 NULL 时放行，缺少它时 `job_contract_version=2` 且身份列全为 NULL 的脏行会绕过上面的分支约束。`job_contract_version` 是 job/worker 契约版本，独立于证据 `schema_version`，也独立于发布 manifest 的 `contract_version`（后者本轮固定为 `1`；`release.CONTRACT_VERSION` 在 T10 改为字面量或独立常量，不再依赖 `contracts.SCHEMA_VERSION`）。

3. **身份归属与审核状态机**。`submit` 返回 **family job_id**；`datacon review JOB_ID` 接收 **family job_id**；`reviews.job_id` 挂在 **family** 上。首份计划属于 campaign child 或 fixed round 1 child，其 `plan_digest` 记入 `family_approvals.first_plan_digest`，不再要求 `reviews` 与首份 child plan 共用同一个 `job_id`。审核窗口期间 family 保持不可领取的 `AGGREGATING`，`AWAITING_REVIEW` 与 `review_deadline_at` 只落在首份 child（`job_kind=campaign`，或 fixed 的 `job_kind=round AND round_no=1`），以便现有 worker 收敛超时。所有同时涉及 family 与首份 child 的审核路径固定**先锁 family、再锁首份 child**：首次人批 approve 在同一事务写 `reviews(job_id=family)` 与 `family_approvals(supersedes=null)`，reject 不写 approval；`expire_review(child, generation)` 由 worker 调用，先读取不可变的 `parent_job_id`，按 family → child 加锁并复核 `AWAITING_REVIEW`、generation 与 lease，在同一事务收敛两行并归档 blocked bundle；换信封由 `propose-envelope` 写入新 `pending`（带 `review_deadline_at`），重批只锁 family、只追加 `family_approvals`，`supersedes` 指向链尾，不重写 `reviews`；`first_plan_digest` 固定为 family 首份 plan 摘要，不随换信封改变。幂等键为五元组 `(family_id, first_plan_digest, envelope_digest, decision, reviewer_id)`，校验顺序（先验 `first_plan_digest`，再按 `(family_id, envelope_digest)` 区分 `idempotent`/`conflict`/`expired`，最后判 `REVIEW_ENVELOPE_MISMATCH`）与完整状态表以[接口契约增量](../interface-contract-delta.md)第 9.1 节为准，本节只做摘要。
4. **plan 身份**。child 的 Plan v2 在 v0.1 `_PLAN_FIELDS` 之上新增 11 个字段：`schema_version`、`family_id`、`parent_job_id`、`round_no`、`parent_approval_digest`、`envelope_digest`、`build_ref`、`build_spec`、`compile_flags`、`experiment_digest`、`build_provenance_rules_version`，全部进入规范化 plan 并计入 `plan_digest`（完整封闭字段集、v2 保留 `build_recipe_digest` 为 `build_spec` 规范化 JSON 的 SHA-256 以及 campaign `inputs=null` 规则以[接口契约增量](../interface-contract-delta.md)第 3 节为准）。首份计划的 `parent_approval_digest` 必须为 `null` 并参与规范化；后续轮次使用非空摘要。`experiment_digest` 在 fixed 与 campaign 为 null，`build_provenance_rules_version` 覆盖 BuildSpec schema、归一化规则与核对面解析器版本。
5. **父审批链**。新增 `family_approvals`：`approval_id`、`family_id`、`approval_digest`、`envelope_digest`、`first_plan_digest`、`reviewer_id`、`decided_at`、可空的 `supersedes`。人批后按 `{family_id, envelope_digest, first_plan_digest, reviewer_id, decided_at}` 的规范化 JSON 计算 `approval_digest`，**排除 `approval_digest` 自身**；`decided_at` 统一渲染为 UTC RFC 3339 固定 6 位小数（`YYYY-MM-DDTHH:MM:SS.ffffffZ`）后参与哈希，保证离线重算一致。换信封产生新 approval，`supersedes` 指向旧 approval，旧轮次保留旧摘要；`reviews` 的 `UNIQUE(job_id)` 只承载首份计划的人批，不再承担多次换信封审批。
6. **build_ref**。`build_ref` 至少包含来源 `source_job_id`、`generation`、`build_inputs_digest`，以及 `artifacts.vulnerable` 与 `artifacts.fixed` 各自的 `artifact_digest`、`build_log_digest`。`generation` 是 campaign 构建 attempt 的 generation，两版 artifact 在同一 attempt 中共享同一个值；`reuse_origin.generation` 必须与它一致，本轮不按版本分别构建，也不引入 `artifacts.<version>.generation`。fixed 无 campaign 复用时 `build_ref` 为 null；只有复用型 validation 才要求非空。`build_ref` 是两版 artifact 的唯一权威；证据中的 `reuse_origin.artifacts` 必须与它逐字段相等。任一版本摘要、job 或 generation 不符即 `REUSE_MISMATCH`。
7. **信封绑定**。`envelope_digest` 必须进入 v2 plan（fixed 的退化信封同样非空）。信封正文不内联进 plan，因此不直接计入 `plan_digest` 的字节；但摘要进入 plan 后，fuzz 镜像、harness、签名集合与 `mutation_limits` 都通过 `envelope_digest` 被间接绑定。
8. **父 job 的终态与无租约收敛**。父 job 在所有 child 结束、预算耗尽或收到终止条件后聚合：保留每轮 plan 摘要、admission、verdict 与证据引用，不复制子轮次的执行记录。family job 运行期间使用不可领取的 `AGGREGATING` 状态，不得用 `RUNNING` 表示聚合；`prepare` 建立聚合并进入该状态，聚合完成后落盘 `family.json` 并调用无执行租约的 `complete_family(family_id, evidence_path, evidence_digest)` 将 family 置 `COMPLETED`（若末轮 child 已归档终态但在 `family.json` 落盘/提交前崩溃，worker 恢复扫描幂等补落盘并调用 `complete_family` 收敛，避免永久滞留 `AGGREGATING` 阻塞回滚）。`finish_execution` 仅用于持有有效 worker lease 且处于 `RUNNING`/`ARCHIVING` 的 child job（含 `campaign` child 落 `COMPLETED`）。`COMPLETED` 是 v2 新增终态：`verdict`/`reason_code` 为 null、`evidence_status='archived'`，`claim_next` 不领取，回滚排空集合不包含它；campaign 不再用 `INCONCLUSIVE` 表示搜索完成。（D43 补充）`family.json`（`kind="family_index"`，非 v2 bundle）满足 007 `jobs_archived_evidence_check`（非空 `evidence_path`/`evidence_digest`）；T10 落地两条收敛接口与 007 兼容，`family.json` 落盘、崩溃恢复补收敛、`status` 展示与 `export --family` 字节一致归 T12。
9. **轮次上限**。`max_rounds` 由准入 predicate 检查 `round_no <= max_rounds`；`UNIQUE(parent_job_id, round_no)` 只防重复轮次，不能当作“防超限”。预算由 family 账本原子扣减，轮次创建前仍须校验余额。
10. **兼容**。既有 v1 job/plan 没有上述字段，只读兼容：可查询、可 export、可 verify，不可重跑，不做在线回填。T10 新增迁移，不修改 v1 数据。
11. **实施边界**。T10 只建立身份、迁移、plan 字段与分派骨架，不实现 campaign 搜索或预算扣减；T12 才把复用、信封与账本接入。迁移必须可重复执行，且在旧表上只加列/约束，不删除既有数据。
12. **回滚围栏**。v2 worker 领取时按 `job_contract_version = 2` 过滤；已部署的 v1 worker 不认识该字段。本版采用**排空/静默**，不引入独立队列表：回滚到 v1 前必须排空全部 v2 非终态 job，明确包含 `QUEUED`、`PREPARING`、`AWAITING_REVIEW`、`AGGREGATING`、`READY`、`RUNNING`、`ARCHIVING` 与 `BLOCKED` 且 `workflow_synced=false`，并由回滚 gate 阻断残留。`AWAITING_REVIEW` 有 24 小时审核窗口，是运行中最常停留的状态。CHECK 只防脏数据，不能防旧 worker 误领；回滚后 v1 只读 v1 时代数据，v2 终态证据由保留的 v2 只读 verifier/export 读取。

## Alternatives considered

- **同一 job 内追加 plan 版本**。可以保留历史，但 `reviews` 的唯一约束、审核时限与“批准即执行”的状态流都要重写；旧执行者写回也更容易把不同版本的计划混在一起。
- **每轮新建独立 family，不复用 campaign 制品**。身份简单，但每次验证重复构建双版本，成本和构建漂移都不可接受，也无法证明 validation 与 campaign 的可比性。
- **只用一个 `parent_job_id` 而不加 `round_no` 唯一约束**。并发下同一轮次可能生成两份 plan 与两次预算扣减，事后去重无法恢复已消耗的容器时间。
- **保留 `reviews` 作为唯一审批表并用新 job 承载换信封**。会让每次换信封都产生一个只用于审批的假 job，轮次索引与预算归属随之失真；独立 `family_approvals` 链更直接。

## Consequences

- 状态查询、日志关联与证据导出都要同时理解父 job 与 child job；`status` 必须返回轮次列表，`export --family` 必须保留单轮包。
- 数据库迁移增加列与唯一约束；旧 v1 任务不受影响，但新任务不能复用 v1 plan。
- 计划摘要对身份字段敏感，任何轮次或构建来源变化都会触发新摘要与新准入，这是预期行为。
- 父 job 不执行，减少了重复构建；代价是父 job 的聚合逻辑必须幂等，且不能把子轮次失败误判为父 job 执行失败。
- v1 worker 的领取查询不认识 v2 版本字段；回滚安全必须由排空或队列隔离保证，不能靠 CHECK 或新增列自动实现。`AWAITING_REVIEW`、`AGGREGATING` 与未同步 `BLOCKED` 必须计入排空集合。
- 观测口径需要同时保留 `job_id` 与 `family_id`：日志按 job 串联，报表按 family 聚合，二者不能互相替代。
- 轮次号一旦分配不得回收；失败轮次保留编号与证据，后续实验使用新号，避免审计出现“同一轮次两种结果”。
- 迁移需要同时覆盖新库与已有库：新库直接建列与约束，旧库用可重入 `ADD COLUMN IF NOT EXISTS` 与幂等约束检查，不复制 v1 行。
- 父 job 的聚合结果只读；若某轮之后被人工重开，必须新建 child，而不是改写已归档轮次。
- 查询接口要区分“父 job 无执行记录”与“child 尚未开始”，避免把聚合空值误报为失败。
- 证据导出按 family 索引定位 child；索引损坏时宁可失败，也不猜测轮次与包的对应关系。
- `reviews` 与 `family_approvals` 并存，读取方必须按“首份计划”与“当前 approval 链尾”区分来源，不能假设只有一张审批表。

## 对应 REQ

- [REQ-11 计划身份与 family](../srs-delta.md)
- 修改后的 [REQ-03 可审核的分析与计划](../srs-delta.md)（审批对象与计划绑定）
- [REQ-14 family 预算账本](../srs-delta.md)（轮次上限与预算的边界）
- [REQ-16 证据 v2 与 family 导出](../srs-delta.md)（family 导出与单轮独立校验）

## 测试坐标

- 计划身份：`tests/contract/test_plan_family.py::test_round_plan_binds_parent_round_envelope_and_build_ref`
- 首份计划空父审批：`tests/contract/test_plan_family.py::test_first_plan_has_null_parent_approval_digest`
- 双版本制品：`tests/contract/test_plan_family.py::test_round_plan_binds_both_version_artifacts`
- 唯一约束：`tests/integration/test_migrations.py::test_jobs_parent_round_unique_rejects_duplicate`
- 身份 CHECK：`tests/integration/test_migrations.py::test_jobs_parent_round_checks_reject_half_null`
- 轮次下界：`tests/integration/test_migrations.py::test_jobs_round_no_rejects_zero`
- 拒绝自父：`tests/integration/test_migrations.py::test_jobs_rejects_self_parent`
- campaign 身份：`tests/contract/test_plan_family.py::test_campaign_identity_is_special_child`
- 父审批链：`tests/contract/test_plan_family.py::test_family_approval_chain_supersedes_on_envelope_change`
- 父子聚合：`tests/contract/test_plan_family.py::test_parent_job_aggregates_without_rerun`
- 回滚围栏：`tests/integration/test_worker_fence.py::test_v1_worker_cannot_claim_v2_non_terminal_job`
- 先锁 family 再锁 child：`tests/integration/test_review_locks.py::test_review_locks_family_then_first_child`
- 超时同事务收敛：`tests/integration/test_review_locks.py::test_review_expiry_converges_family_and_child`
- 重批只追加 approval：`tests/integration/test_review_locks.py::test_envelope_reapproval_only_appends_family_approvals`
- 首份摘要不符拒绝：`tests/integration/test_review_locks.py::test_review_rejects_mismatched_first_plan_digest`
- 重批必须给信封摘要：`tests/integration/test_review_locks.py::test_review_requires_envelope_digest_for_reapproval`
- 重批摘要须命中 pending：`tests/integration/test_review_locks.py::test_review_envelope_digest_must_match_pending`
- reject 信封落点：`tests/integration/test_review_locks.py::test_review_reject_marks_pending_envelope_rejected`
- 五元组幂等：`tests/integration/test_review_locks.py::test_review_idempotency_key_includes_envelope_digest`
- family 证据指针：`tests/contract/test_cli_status.py::test_family_completed_sets_evidence_path_and_digest`
- family index 必需：`tests/contract/test_cli_status.py::test_family_completed_requires_family_index`
- 导出字节一致：`tests/contract/test_export.py::test_family_index_is_byte_identical_to_export`
- 007 归档 CHECK：`tests/integration/test_migrations.py::test_family_completed_satisfies_archived_evidence_check`
- 复用摘要：`tests/contract/test_reuse.py::test_validation_reuses_campaign_build_and_detects_mismatch`
- 用例映射：[TC-11](../test-plan-delta.md)、[TC-03](../test-plan-delta.md)、[TC-16](../test-plan-delta.md)

以上坐标为 T10/T12 计划测试，T09 不创建代码。实现须先看到对应断言失败，再补最小行为。
