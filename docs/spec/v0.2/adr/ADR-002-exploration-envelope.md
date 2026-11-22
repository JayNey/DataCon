# ADR-002 探索信封与自动准入

**Status** Accepted  
**Date** 2026-11-21

## Context

guided 模式需要在首份计划之后根据验证结果继续生成候选 seed、扩展输入族或重跑实验。如果每一轮都要求人工审核，探索的反馈回路会被 24 小时审核时限切断；如果完全交给模型或 worker 自行决定，又会越过操作者授权，无法回答“这一轮为什么被允许执行”。

v0.1 的 `reviews` 表以 `UNIQUE(job_id)` 绑定单份计划，只适合人工决议。把 policy 决定混入 `reviews` 会让“谁批准了执行”无法区分，也会破坏审核时限、拒绝与过期的语义。因此需要一个新的、可离线审计的授权层。

信封还必须与 plan 分开存放：信封可能在多轮之间保持不变，plan 每轮都变；把信封正文写进每个 plan 会重复大对象，也会让“修改信封”与“修改计划”难以区分。规范选择只把 `envelope_digest` 写进 plan，同时把信封正文单独归档，供离线重算准入。信封还必须约束变异操作本身：只写 mutation family 不能阻止模型生成超大输入或任意写入操作。

## Decision

1. **信封是授权边界**。人批准的是一份 `Envelope` 加首份计划，而不是逐轮计划。信封字段固定为 `mode`、`allowed_mutation_families`、`mutation_limits`、`seed_corpus_digest`、`fuzz_image_digest`、`harness_digest`、`max_rounds`、`max_total_seconds`、`max_fuzz_seconds`、`accepted_signature_set` 与 `admission_predicate_version`；字段与规范化摘要见[接口契约增量](../interface-contract-delta.md)。`mutation_limits` 含 `allowed_ops` 与 `max_input_bytes`，并进入 `envelope_digest`。guided 的 `fuzz_image_digest` 默认等于固定工具链镜像摘要；只有经审核的独立 fuzz 镜像才允许不同。
2. **人批首份计划**。首份计划由人工批准，写入 `reviews`（`job_id`=family）与 `family_approvals`，并由后者生成 `approval_digest`。首份计划可以是 campaign 计划（guided）或 fixed round 1 计划；首份 plan 的 `parent_approval_digest` 为 `null` 且参与 `plan_digest`，审批摘要绑定 family、信封、首份 plan 与审批人，后续 round 只引用它，不复制人工决议。`first_plan_digest` **固定为 family 首份 plan 摘要**，不随换信封改变；换信封产生新 approval，`supersedes` 指向旧 approval，新 `approval_digest` 由新的 `envelope_digest` 与 `decided_at` 产生，不形成“approval 摘要包含计划、计划又引用 approval 摘要”的循环。重批只追加 `family_approvals`，不重写 `reviews`，也不改变 `reviews` 表结构。`decided_at` 参与哈希前统一渲染为 UTC RFC 3339 固定 6 位小数（`YYYY-MM-DDTHH:MM:SS.ffffffZ`）。

**待审信封与重批（D42 补充）**。待审信封由 `family_envelopes` 承载：`status ∈ {pending, approved, rejected, expired}`，`review_deadline_at` 非空（默认创建时间 + 24 小时），`UNIQUE(family_id, envelope_digest)`，partial unique index 保证每 family 至多一个 `pending`。首份 plan 冻结时插入首信封为 `pending`；换信封通过 `datacon propose-envelope FAMILY_ID --request envelope.json` 校验后插入新 `pending`。approve 把待审信封置 `approved`；reject 置 `rejected` 并收敛至 `BLOCKED(REVIEW_REJECTED)`；首轮审核超时或换信封待审超时（worker 定期扫描过期 `pending` 且 family 为 `AGGREGATING`）均将 `family_envelopes.status` 置 `expired`、family 收敛为 `BLOCKED(REVIEW_EXPIRED)` 并写 `review_expired` 审计（换信封超时只锁 family，不改既有 `reviews` 与已完成 child）。`review` 增加 `--envelope-digest`（首轮可省略，换信封重批必填），`--plan-digest` 始终等于 `first_plan_digest`；五元组 `(family_id, first_plan_digest, envelope_digest, decision, reviewer_id)` 的三步校验顺序与完整状态表以[接口契约增量](../interface-contract-delta.md)第 9.1 节为准。

**审核窗口与锁序**。审核窗口期间 family 保持不可领取的 `AGGREGATING`，首份 child 持 `AWAITING_REVIEW` 与 `review_deadline_at`。首次人批与超时先锁 family 再锁 child，重批只锁 family，完整状态表见[接口契约增量](../interface-contract-delta.md)第 9.1 节。

3. **轮次内 policy 准入**。下一轮由确定性 predicate 检查：`round_no <= max_rounds`；预算账本有余额；`input_family` 在 `allowed_mutation_families` 内；`mutation_constraints.allowed_ops` ⊆ `mutation_limits.allowed_ops` 且 `max_input_bytes <= mutation_limits.max_input_bytes`；`expected_signature` 逐字段等于 `accepted_signature_set` 中某一项（`error`/`function`/`source` 必填，`operation`/`access_size` 可选，字段存在性也要比较，不允许只比较 sanitizer 字符串或 error 类别）；`envelope_digest`、`parent_approval_digest`、`seed_digest` 与父记录一致；predicate 版本匹配；同一 `(parent_job_id, round_no)` 尚无 admission。
4. **独立 admissions 表**。policy 准入写入 `admissions`，字段包含 `approval_kind=policy`、`envelope_digest`、`parent_approval_digest`、`seed_digest`、`decided_at`、`predicate_version`、`recomputable` 与可空的 `supporting_bundle_digest`；同时追加 `round_admitted` 审计事件。`reviews` 只保存人的批准或拒绝，policy 永不写入。
5. **离线可重算**。给定信封（含 `mutation_limits`）、父审批摘要、种子摘要、轮次号、预算快照与 predicate 版本，必须能独立重算出同一准入结论。重算所需的输入随 validation 证据归档（`envelope`、`budget_snapshot`、`admission` 角色）；不能用只在控制面内存中存在的状态作为 predicate 输入。
6. **不可重算的标注**。若准入依赖 campaign 搜索过程产生的、无法从离线证据独立重算的信息，admission 必须标记 `recomputable=false`，并在证据中显式写明“由 campaign bundle 佐证”，同时记录 `supporting_bundle_digest`。不得把此类准入伪装成可重算。
7. **信封变更**。修改任一信封字段都必须重新人批：产生新的 `family_approvals` 行与新的 `approval_digest`，旧轮次保留原摘要与证据，不再获得新授权。模型、worker 或 policy 都不能扩大信封，也不能扩大 `mutation_limits`。
8. **fixed 模式**。无 `exploration` 的请求按 `fixed` 处理：`max_rounds=1`、`max_fuzz_seconds=0`、`allowed_mutation_families=[]`、`mutation_limits={"allowed_ops":[],"max_input_bytes":0}`、`seed_corpus_digest=null`、`fuzz_image_digest=null`；`harness_digest` 与 `accepted_signature_set` 仍必填。仍冻结退化信封以便统一审计，因此 `envelope_digest` 非空，但不产生 fuzz 轮次。fixed 没有 campaign，`build_ref` 与 `reuse_origin` 均为 null。
9. **失败语义**。越出信封返回 `ENVELOPE_VIOLATION`；predicate 不通过返回 `ADMISSION_DENIED`；轮次或预算耗尽返回 `BUDGET_EXHAUSTED`；harness 摘要不符返回 `HARNESS_REJECTED`。这些失败都不写 `reviews`，按任务阶段归档或阻断。`max_rounds` 的越界由 predicate 判定，不由 `UNIQUE(parent_job_id, round_no)` 代替。
10. **审计事件**。准入成功追加 `round_admitted`，拒绝追加 `round_admission_denied`；事件带 `job_id`、`parent_job_id`、`round_no`、`envelope_digest`、`parent_approval_digest`、`seed_digest`、predicate 版本与时间。

## Alternatives considered

- **每轮人工审核**。授权最直接，但探索循环被审核时延阻断，且审核人会被要求批准自己未参与设计的候选。
- **把 policy 决定写进 reviews**。查询方便，却混淆“人批准”与“程序准入”，破坏 `reviews` 的唯一约束、时限与拒绝语义，审计上也无法区分责任主体。
- **只设一个全局预算，不设信封**。实现简单，但无法约束 mutation family、变异上限、签名集合或 fuzz 镜像，模型可以合法地把实验推到未审核范围。
- **允许模型自行准入**。违反“审批、限额、状态流转和判定由确定性逻辑执行”的边界。
- **只比较 sanitizer 字符串或 error 类别**。会把 READ/WRITE 与访问大小不同的崩溃当成同一签名，放宽复现口径。

## Consequences

- 首份计划之后可以自动推进，但每条准入都必须有可重算输入或 campaign 佐证；证据量增加。
- `admissions`、`reviews` 与 `family_approvals` 三张表并存，查询方必须按 `approval_kind` 与 approval 链区分，不能再假设“有 review 才算批准”。
- 信封摘要成为 plan 的一部分，修改信封会自然触发新计划摘要与新证据，不会出现旧批准覆盖新范围。
- fixed 模式多了一个退化的信封记录；实现需要接受空 mutation family、空 `allowed_ops` 与零 fuzz 预算。
- 准入 predicate 的输入必须随证据冻结，否则重算会依赖控制面当前状态；重算器只能读取包内文件与公开算法。
- 信封字段一旦成为 plan 摘要的一部分，修改成本更高；这会把“调整探索范围”变成显式的重新审批，而不是运行时参数。
- 信封正文单独归档，plan 只存摘要；归档缺失时准入无法重算，应按 `ADMISSION_DENIED` 处理。
- 人工拒绝首份计划后不产生任何 admission；后续轮次不得引用被拒绝的父审批摘要。
- predicate 版本升级需要保留旧版本的只读实现，否则旧准入无法重算。
- 审计查询按 family 聚合，但每条事件仍必须能定位到唯一 child 与轮次。
- 签名匹配升级为全字段严格相等后，v0.1 中“同类 sanitizer 即命中”的宽松解释不再适用于 v2；v1 证据仍按冻结分支解释。

## 对应 REQ

- [REQ-12 探索信封与自动准入](../srs-delta.md)
- 修改后的 [REQ-03 可审核的分析与计划](../srs-delta.md)（审批对象）
- 修改后的 [REQ-07 证据驱动的结论](../srs-delta.md)（fuzz 观测不直接成结论）

## 测试坐标

- policy 不写 review：`tests/contract/test_envelope.py::test_policy_admission_never_writes_review`
- 越界拒绝：`tests/contract/test_envelope.py::test_out_of_envelope_experiment_is_denied_before_build`
- mutation 子集：`tests/contract/test_envelope.py::test_experiment_mutation_constraints_must_be_subset`
- mutation 进摘要：`tests/contract/test_envelope.py::test_envelope_digest_binds_mutation_limits`
- 签名全字段匹配：`tests/contract/test_experiment_spec.py::test_expected_signature_matches_full_accepted_signature`
- 离线重算：`tests/contract/test_admission.py::test_admission_predicate_recomputes_offline`
- 不可重算佐证：`tests/contract/test_admission.py::test_non_recomputable_admission_cites_campaign_bundle`
- 审计事件：`tests/contract/test_admission.py::test_policy_admission_appends_round_admitted_event`
- 首份计划：`tests/contract/test_plan_family.py::test_campaign_plan_is_human_approved_first_plan`
- 首份计划空父审批：`tests/contract/test_plan_family.py::test_first_plan_has_null_parent_approval_digest`
- 换信封：`tests/contract/test_plan_family.py::test_family_approval_chain_supersedes_on_envelope_change`
- 先锁 family 再锁 child：`tests/integration/test_review_locks.py::test_review_locks_family_then_first_child`
- 超时同事务收敛：`tests/integration/test_review_locks.py::test_review_expiry_converges_family_and_child`
- 重批只追加 approval：`tests/integration/test_review_locks.py::test_envelope_reapproval_only_appends_family_approvals`
- 首份摘要不符拒绝：`tests/integration/test_review_locks.py::test_review_rejects_mismatched_first_plan_digest`
- 重批必须给信封摘要：`tests/integration/test_review_locks.py::test_review_requires_envelope_digest_for_reapproval`
- 重批摘要须命中 pending：`tests/integration/test_review_locks.py::test_review_envelope_digest_must_match_pending`
- reject 信封落点：`tests/integration/test_review_locks.py::test_review_reject_marks_pending_envelope_rejected`
- 五元组幂等：`tests/integration/test_review_locks.py::test_review_idempotency_key_includes_envelope_digest`
- fixed 条件必填：`tests/contract/test_evidence_v2.py::test_fixed_execution_has_envelope_but_no_reuse_origin`
- fixed 信封字段：`tests/contract/test_envelope.py::test_fixed_envelope_sets_null_fuzz_fields`
- 用例映射：[TC-12](../test-plan-delta.md)、[TC-03](../test-plan-delta.md)、[TC-07](../test-plan-delta.md)

以上坐标为 T10/T12 计划测试，T09 不创建代码。实现须先看到对应断言失败，再补最小行为。
