# 测试与评估计划增量（v0.2）

本文件是 [v0.1 测试与评估计划](../test-plan.md) 的增量。TDD 工作流、测试分层、基准集定义继续按 v0.1 执行。T09 不新增 T10–T15 的测试代码，只登记坐标；T09 仅新增四条门禁作用域用例（`tests/contract/test_ci_gates.py` 的 v0.1 根拒绝、v0.2 允许、未知编号拒绝、仓库其他 Markdown 允许），不添加 `xfail` 或 `skip`。各任务开工时再按坐标创建测试。

## 1. TC-11..TC-16 与需求映射

| 用例 | 对应需求 | 观察点 | 不通过条件 |
| --- | --- | --- | --- |
| **TC-11** | REQ-11 | family/campaign/round 身份、`job_contract_version` 的 v1/v2 CHECK、campaign partial unique、自父拒绝、plan 绑定 family/轮次/审批/信封/双版本 `build_ref`/`experiment_digest`、`submit` 返回 family、父 job 只聚合 | campaign 被当成普通 round 或父 job；同一 family 出现第二个 campaign；半空、`round_no=0` 或 `parent_job_id=job_id` 数据可写入；v1 行携带新身份列；只改轮次或某一版 `build_ref` 不改变 `plan_digest`；父 job 产生 build/replay |
| **TC-12** | REQ-12 | 信封字段（含 `mutation_limits`）与摘要、人批首份计划与 `family_approvals`、policy 自动准入、`admissions`、`round_admitted`、越界拒绝、fixed 退化信封 | policy 写 `reviews`；首份计划 `parent_approval_digest` 非空；换信封不产生新 approval；无信封或过期信封仍准入；超出 family/签名/mutation/预算的轮次进入构建 |
| **TC-13** | REQ-13 | `ExperimentSpec` 九字段、`expected_signature` 与 plan/信封同结构（可选字段）、签名全字段严格匹配、`mutation_constraints` 子集、`experiment_digest` 进 plan、证据引用可解析、假设不改判定、AgentOutput v2 只允许 hypothesis | 实验含自由命令；`expected_signature` 只比较 sanitizer 字符串；READ/WRITE、access_size 或可选字段存在性不同仍匹配；模型合成 harness 被执行；模型 `kind=fact` 进入证据链；删除假设后判定变化 |
| **TC-14** | REQ-14 | family 账本原子扣减、`(job_id, step_key, attempt_no)` 幂等、fuzz 子预算、轮次上限 predicate、耗尽终态、单执行槽位 | 余额为负；恢复同一 attempt 重复扣费；新 attempt 未扣费；`round_no > max_rounds` 仍建轮次；耗尽后仍建轮次；并发测试伪装成生产多 worker |
| **TC-15** | REQ-15 | `BuildSpec` 统一字段、显式 `compile_flags`、CMake/Make 核对面、shell face、归一化与顺序、两版生效有序相等、工具链边界 | 声明未生效仍通过；两版生效顺序不同仍通过；`-I a -I b` 与 `-I b -I a` 被判相等；无核对面未阻断；`make_env` 残留；shell 配方无单独审核仍计为可比 |
| **TC-16** | REQ-16 | `schema_version` 分派、v1 冻结分支、campaign bundle、blocked 条件、自包含 validation、固定/复用条件的 `build_ref`/`reuse_origin`、v2 完整角色表、family 导出、新引用语法、v1 只读 v1 时代证据 | v1 包被 v2 校验器改写；campaign 要求 verdict；blocked 被要求 family/envelope/plan_digest；fixed 被要求 `reuse_origin`；复用 validation 缺 `build_ref` 仍通过；validation 缺 `envelope`/`budget_snapshot`/（T13 起）`build_provenance` 仍通过；v1 任务被重跑；v1 代码解析 v2 证据 |
| **TC-02** | REQ-02（修改） | v0.2 范围（T15）：HTTPS 域名白名单、统一 IPv4/IPv6（含 CGNAT/云元数据/IPv4-mapped IPv6）连接前与 `getpeername()` 复检、逐跳重定向 ≤5、10s/30s/60s 超时、流式 8 MiB/32 MiB/100:1 上限、不可变快照与许可门禁（`intel_snapshot`/`license_record`）、外部公告文本只作数据、边 #6 快照缺失/冲突阻断。**保留 v0.1 断言**：同一快照产生同一版本对与材料摘要；缺少提交、来源冲突或内容篡改均进入阻断。 | 非白名单域或私网/元数据/IPv4-mapped IPv6 地址被访问；超 5 跳重定向或超时/压缩炸弹未被截断拒绝；缺许可或用途不符材料进入复现流程；公告中伪造指令改变路由或工具调用；离线案例漏归档快照。 |
| **TC-03** | REQ-03（修改） | v0.2 范围：审批对象为信封 + 首份计划；`reviews.job_id=family`；`family_approvals` 链；policy 只进 `admissions`；摘要不符封闭执行。**保留 v0.1 断言**：错误摘要、拒绝、审核过期、计划漂移均无构建调用；重复批准维持同一决议。 | 首份计划无人批仍构建；旧 approval 在新信封上复用；`reviews` 挂在 child 上；重复批准产生第二次构建 |
| **TC-06** | REQ-06（修改） | v0.2 范围：声明 ⊆ 生效（多重集）、两版共同编译单元生效有序严格相等、顺序反例、无核对面冻结阶段阻断。**保留 v0.1 断言**：两版镜像、参数及输入哈希记录；更换一方种子或 harness 后判定 `INCONCLUSIVE`。 | 仅比较 recipe 文本；按集合比较忽略顺序；v1 计划被迫要求 BuildSpec |
| **TC-07** | REQ-07（修改） | v0.2 范围：crash seed 字节、SHA-256、provenance；fuzz 命中只产候选、仍须六次回放。**保留 v0.1 断言**：六次回放表驱动、双版本稳定触发差异、修复版同签名、对照失败、超时/OOM、ASan 截断与非目标崩溃的判定优先级不变。 | fuzz 命中直接出结论；缺少 provenance 仍回放；v1 六回放数量或优先级被改写 |
| **TC-08** | REQ-08（修改） | v0.2 范围：v2 证据字段（含 `verdict`/`reason_code`/`created_at`）、完整角色表、单轮独立校验、family 导出、campaign 归档、预算对账。**保留 v0.1 断言**：正常包通过校验；缺失、多余、改写、符号链接、绝对路径、父路径和重复条目失败；证据写入错误后查询返回 `FAILED` 与空包引用。 | family 导出重写单轮摘要；v1 包被误读；manifest 只列 report 与一个 `build.log` |
| **TC-09** | REQ-09（修改） | v0.2 范围：模型出口白名单、脱敏、离线默认、模型/prompt 版本审计、`provider=offline`、失败回退、AgentOutput 只允许 hypothesis。**保留 v0.1 断言**：公告/源码/diff/日志中的伪造指令不产生越权工具调用；错误证据引用不能晋升为事实；修改模型建议不改变同一观测的结论。 | 未登记工具被调用；模型失败导致策略放宽；模型 `kind=fact` 进入下游；offline 缺 `model_audit` 或 `provider` 为空 |

**编号规则**：v0.2 不新增 TC-11..16 以外的用例编号。TC-11..TC-16 与 REQ-11..REQ-16 一一对应，TC-02/03/06/07/08/09 只重定范围并保留 v0.1 断言。

## 2. T10–T15 计划中的失败测试坐标

以下路径与测试名为计划坐标，T09 不创建这些测试。每条先运行一次，断言必须因对应能力缺失而失败；首次失败信息用于证明 RED 成立。

### T10 计划身份、child job 与证据 v2 分派

T10 还必须验证审核状态机（D36，见[接口契约增量](interface-contract-delta.md)第 9.1 节）：`record_review` 不再按同一个 `job_id` 查 `plans`，改为按 family 定位首份 child 及其 plan；该实现变更不修改 `reviews` 表结构。D42 在同一状态机上补充待审信封身份与五元组幂等键，以下 D36 四条与 D42 四条坐标同属 T10。

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/contract/test_plan_family.py::test_round_plan_binds_parent_round_envelope_and_build_ref` | 分别改变 `parent_job_id`、`round_no`、`envelope_digest`、`build_ref`，每次 `plan_digest` 都变化 | `KeyError: 'build_ref'` |
| `tests/contract/test_plan_family.py::test_first_plan_has_null_parent_approval_digest` | 首份计划的 `parent_approval_digest` 为 null 且参与规范化；后续轮次用非空摘要 | `AssertionError: first plan required a parent approval digest` |
| `tests/contract/test_plan_family.py::test_round_plan_binds_both_version_artifacts` | 只改 `artifacts.vulnerable` 或 `artifacts.fixed` 的摘要，`plan_digest` 都变化 | `KeyError: 'artifacts'` |
| `tests/contract/test_cli_identity.py::test_submit_returns_family_job_id` | `submit` 返回 family job_id，`status`/`review` 接受该 id | `AssertionError: submit returned a child job id` |
| `tests/contract/test_cli_identity.py::test_review_writes_family_scoped_review` | `datacon review` 收到的 family job_id 写入 `reviews.job_id` 与 `family_approvals` | `AssertionError: review was written against the child job` |
| `tests/contract/test_plan_family.py::test_campaign_identity_is_special_child` | campaign 是 family 下的 special child，`round_no=null`，每个 family 至多一个 | `AssertionError: campaign treated as ordinary round` |
| `tests/contract/test_plan_family.py::test_campaign_plan_is_human_approved_first_plan` | campaign 计划是人批的首份计划，产生 `family_approvals` 行 | `AssertionError: campaign plan bypassed human review` |
| `tests/contract/test_plan_family.py::test_family_approval_chain_supersedes_on_envelope_change` | 换信封产生新 approval，`supersedes` 指向旧 approval，旧轮次摘要不变 | `KeyError: 'supersedes'` |
| `tests/contract/test_plan_family.py::test_parent_job_aggregates_without_rerun` | 父 job 不产生 build/replay，只聚合；family job 状态为 `AGGREGATING` | `AssertionError: parent job executed a child step` |
| `tests/contract/test_plan_family.py::test_plan_digest_binds_experiment_and_provenance_version` | 改 `experiment_digest` 或 `build_provenance_rules_version` 会改变 `plan_digest` | `KeyError: 'experiment_digest'` |
| `tests/integration/test_migrations.py::test_jobs_parent_round_unique_rejects_duplicate` | 直接插入重复 `(parent_job_id, round_no)` 触发约束 | `psycopg.errors.UniqueViolation: duplicate key value violates unique constraint "jobs_parent_round_key"` |
| `tests/integration/test_migrations.py::test_jobs_parent_round_checks_reject_half_null` | 半空身份或 v1 行携带新身份列的插入被 CHECK 拒绝 | `psycopg.errors.CheckViolation: new row violates check constraint` |
| `tests/integration/test_migrations.py::test_jobs_round_no_rejects_zero` | `round_no=0` 的 child 插入被 CHECK 拒绝 | `psycopg.errors.CheckViolation: new row violates check constraint` |
| `tests/integration/test_migrations.py::test_jobs_v2_identity_columns_cannot_all_be_null` | `job_contract_version=2` 但身份列全为 NULL 的插入被非空守卫拒绝 | `psycopg.errors.CheckViolation: new row violates check constraint` |
| `tests/integration/test_migrations.py::test_jobs_rejects_self_parent` | `parent_job_id=job_id` 被 CHECK 拒绝 | `psycopg.errors.CheckViolation: new row violates check constraint` |
| `tests/integration/test_worker_fence.py::test_v1_worker_cannot_claim_v2_non_terminal_job` | v2 非终态 job 存在时，v1 领取路径不得领取；回滚 gate 必须阻断 | `AssertionError: v1 worker claimed a v2 non-terminal job` |
| `tests/integration/test_worker_fence.py::test_rollback_gate_drains_every_v2_non_terminal_state` | 排空集合逐项覆盖 `QUEUED`、`PREPARING`、`AWAITING_REVIEW`、`AGGREGATING`、`READY`、`RUNNING`、`ARCHIVING`、`BLOCKED` 且 `workflow_synced=false`，缺一项即阻断回滚 | `AssertionError: rollback gate ignored a non-terminal v2 state` |
| `tests/integration/test_worker_fence.py::test_v1_worker_cannot_claim_v2_awaiting_review` | `AWAITING_REVIEW` 的 v2 job 同样在排空集合内 | `AssertionError: v1 worker claimed a v2 job in AWAITING_REVIEW` |
| `tests/integration/test_worker_fence.py::test_v1_worker_cannot_claim_v2_unsynced_blocked` | `BLOCKED` 且 `workflow_synced=false` 的 v2 job 同样被阻断 | `AssertionError: v1 worker claimed an unsynced BLOCKED v2 job` |
| `tests/contract/test_evidence_refs.py::test_log_build_and_log_fuzz_refs_resolve_to_frozen_lines` | `log/build:<version>#Lx-y` 与 `log/fuzz:<round>#Lx` 先校验摘要与行号再返回内容，越界或摘要不符不可解析 | `KeyError: 'log/build'` |
| `tests/contract/test_evidence_v2.py::test_v2_role_table_contains_v01_roles` | 角色表包含 v0.1 的 `normal_output`/`normal_error`/`asan_log`/`case_config`/`symbolizer_log` 与 `envelope`/`budget_snapshot`/`build_provenance` | `KeyError: 'normal_output'` |
| `tests/contract/test_evidence_v2.py::test_verify_bundle_dispatches_v1_and_v2_by_manifest_schema` | v1 包走冻结分支，v2 包走新分支，互不误读 | `AssertionError: schema_version 1 bundle accepted by v2 validator` |
| `tests/contract/test_evidence_v2.py::test_v1_job_cannot_be_rerun_with_v2_semantics` | v1 job 可 export/verify，但 re-run 被拒绝 | `AssertionError: v1 job re-ran under v2 plan` |
| `tests/contract/test_evidence_v2.py::test_campaign_bundle_allows_zero_crash_seed` | 0 crash 的 campaign 包没有 `crash_seed` 仍通过，但必须有 `fuzz_log`/`fuzz_provenance` | `AssertionError: zero-crash campaign required a crash_seed` |
| `tests/contract/test_evidence_v2.py::test_campaign_bundle_has_no_verdict` | campaign bundle 的 report 接受空 verdict | `AssertionError: campaign report requires a verdict` |
| `tests/integration/test_review_locks.py::test_review_locks_family_then_first_child` | 人批路径先锁 family 再锁首份 child；并发下先持 child 锁再请求 family 锁会等待/失败，而不是死锁或反向成功 | `AssertionError: review locked the child before the family` |
| `tests/integration/test_review_locks.py::test_review_expiry_converges_family_and_child` | `expire_review` 在同一事务把 child 与 family 都置 `BLOCKED(REVIEW_EXPIRED)`，`reviews` 不变，审计 `review_expired` | `AssertionError: family stayed AGGREGATING after review expiry` |
| `tests/integration/test_review_locks.py::test_envelope_reapproval_only_appends_family_approvals` | 换信封重批只锁 family、只追加 `family_approvals`，`supersedes` 指向链尾，不重写 `reviews` | `AssertionError: re-approval rewrote the reviews row` |
| `tests/integration/test_review_locks.py::test_review_rejects_mismatched_first_plan_digest` | `--plan-digest` 不等于 `first_plan_digest` 时拒绝，不写 `reviews` 或 `family_approvals` | `AssertionError: mismatched first plan digest was accepted` |
| `tests/integration/test_review_locks.py::test_review_requires_envelope_digest_for_reapproval` | 首轮人批可省略 `--envelope-digest`，缺省解析为首份 plan 的 `envelope_digest`；换信封重批缺该参数时拒绝且不写行；`--plan-digest` 始终必须等于 `first_plan_digest` | `KeyError: 'envelope_digest'` |
| `tests/integration/test_review_locks.py::test_review_envelope_digest_must_match_pending` | 换信封重批的 `--envelope-digest` 不等于 family 当前 `pending` 时返回 `REVIEW_ENVELOPE_MISMATCH`，不新增 `reviews`/`family_approvals` | `AssertionError: non-pending envelope digest was accepted` |
| `tests/integration/test_review_locks.py::test_review_reject_marks_pending_envelope_rejected` | reject 在同一事务把 `family_envelopes.status` 由 `pending` 置 `rejected`，child/family 进 `BLOCKED(REVIEW_REJECTED)`，不写 approval；审核超时置 `expired` 并进 `BLOCKED(REVIEW_EXPIRED)` | `AssertionError: pending envelope stayed pending after reject` |
| `tests/integration/test_review_locks.py::test_review_idempotency_key_includes_envelope_digest` | 同一 `(family_id, first_plan_digest, envelope_digest, decision, reviewer_id)` 重复调用返回既有结果；同一 `first_plan_digest` 换信封后追加新 approval；同信封不同 decision/reviewer 返回 conflict | `AssertionError: reapproval with a new envelope was treated as idempotent` |
| `tests/integration/test_migrations.py::test_new_migration_sequence_register_rollback_compatibility` | 新迁移从 `010_*.sql` 起，纯增量迁移登记到 `ROLLBACK_COMPATIBLE_MIGRATIONS`（文件名 + SHA-256）；未登记时回滚 gate 阻断 | `AssertionError: migration 010 missing from rollback allowlist` |
| `tests/integration/test_migrations.py::test_family_completed_satisfies_archived_evidence_check` | family `COMPLETED` 行的 `evidence_path`/`evidence_digest` 非空，满足 007 的 `jobs_archived_evidence_check`；`family.json` 不是 `bundle_kind` | `psycopg.errors.CheckViolation: new row violates check constraint "jobs_archived_evidence_check"` |
| `tests/integration/test_worker_fence.py::test_finish_execution_accepts_completed_terminal` | `finish_execution` 接受持有有效租约的 child job（含 `campaign`）落 `COMPLETED` 且要求 `evidence_status='archived'`、`verdict`/`reason_code` 为 null；family 通过无执行租约的 `complete_family` 从 `AGGREGATING → COMPLETED` 收敛；`claim_next` 不领取 | `AssertionError: finish_execution rejected COMPLETED` |
| `tests/integration/test_worker_fence.py::test_rolled_back_v1_reads_only_v1_era_evidence` | 回滚后 v1 控制面只读 v1 时代证据，v2 终态证据由 v2 只读 verifier/export 读取 | `AssertionError: v1 control plane read v2 evidence` |
| `tests/contract/test_release.py::test_release_contract_version_is_not_derived_from_contracts_schema` | `release.CONTRACT_VERSION` 不依赖 `contracts.SCHEMA_VERSION`；v2 契约常量升级不改变发布 manifest 的 `contract_version=1` | `AssertionError: release contract version tracked contracts.SCHEMA_VERSION` |
| `tests/integration/test_release_rollback.py::test_rollback_drain_gate_runs_before_and_after_smoke` | `rollback_release` 在 smoke 前后各执行一次 drain gate；smoke 期间新增的 v2 残留会阻断切换 | `AssertionError: rollback switch skipped the post-smoke drain gate` |
| `tests/integration/test_release_rollback.py::test_rollback_drains_all_v2_non_terminal_jobs` | 回滚 gate 阻断含 `AWAITING_REVIEW`、`AGGREGATING` 与未同步 `BLOCKED` 的残留 | `AssertionError: rollback promoted with a v2 job left` |

### T11 目标编排图与两条循环

T11 只验证图结构与节点幂等；policy 准入、轮次与预算容量的验收在 T12。

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/unit/test_orchestration_graph.py::test_graph_nodes_and_edges_match_v02_readme` | 节点名与边集合与 [README](README.md) 第 5 节的 Mermaid 和完整边表一致，含 `build_diagnose → archive` 与 family 分支 | `AssertionError: missing node hypothesis_aggregator` |
| `tests/unit/test_orchestration_graph.py::test_build_diagnose_retry_is_bounded_to_once` | 可重试构建失败最多触发一次重试，第三次进入归档 | `AssertionError: build invoked 3 times, expected at most 2` |
| `tests/unit/test_orchestration_graph.py::test_node_reentry_is_a_noop` | 同一 `job_id/stage/step_key/attempt_no/generation` 重入不重复 build/replay/charge | `AssertionError: duplicate build attempt on node re-entry` |
| `tests/unit/test_orchestration_graph.py::test_reverse_route_archives_as_unsupported` | `reverse` 占位只归档，不进入 build | `AssertionError: reverse route reached build` |
| `tests/unit/test_orchestration_graph.py::test_campaign_branch_is_mounted_in_graph` | campaign 分支节点与边可枚举，不替代 verify | `AssertionError: campaign branch missing` |
| `tests/unit/test_orchestration_graph.py::test_family_level_transitions_create_next_round_child` | `campaign`/`verify → hypothesis_aggregator` 是 family 级派生下一轮 child 的逻辑转移，原 child 自己完成 `archive` | `AssertionError: next round reused the finished child job` |
| `tests/unit/test_orchestration_graph.py::test_family_children_execute_serially` | family 的 child 串行执行，同一时刻只有一个执行槽位 | `AssertionError: two family children ran concurrently` |

### T12 信封、准入、预算与 campaign/validation 复用

审核状态机与锁序的四条 D36 坐标及 D42 的四条信封坐标见 T10 的 `tests/integration/test_review_locks.py`；T12 复用它们验证重批后的 approval 链尾与 policy 边界，不重复创建测试。T12 另登记 D43 的 family 归档索引坐标与 `budget_ledger` 交叉 CHECK 坐标。

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/contract/test_envelope.py::test_policy_admission_never_writes_review` | policy 准入后 `reviews` 无新行，`admissions` 恰一行 | `AssertionError: reviews row created for policy admission` |
| `tests/contract/test_envelope.py::test_out_of_envelope_experiment_is_denied_before_build` | 越界 family 或签名集合在准入前返回 `ENVELOPE_VIOLATION` | `AssertionError: out-of-envelope round reached build` |
| `tests/contract/test_envelope.py::test_experiment_mutation_constraints_must_be_subset` | `allowed_ops` 或 `max_input_bytes` 超出信封时被拒 | `AssertionError: mutation beyond envelope accepted` |
| `tests/contract/test_envelope.py::test_envelope_digest_binds_mutation_limits` | 改 `mutation_limits` 会改变 `envelope_digest` 与 `plan_digest` | `AssertionError: mutation_limits not covered by envelope_digest` |
| `tests/contract/test_envelope.py::test_fixed_envelope_sets_null_fuzz_fields` | fixed 的 `allowed_ops=[]`、`max_input_bytes=0`、fuzz 字段为 null/0 | `AssertionError: fixed envelope kept fuzz limits` |
| `tests/contract/test_envelope.py::test_guided_fuzz_image_defaults_to_toolchain_image` | guided 未显式指定独立 fuzz 镜像时，`fuzz_image_digest` 等于固定工具链镜像摘要 | `AssertionError: fuzz image was not bound to toolchain image` |
| `tests/contract/test_admission.py::test_admission_predicate_recomputes_offline` | 仅凭信封、父审批、seed、轮次与预算快照重算得到同一决定 | `AssertionError: recomputed admission differs from recorded decision` |
| `tests/contract/test_admission.py::test_non_recomputable_admission_cites_campaign_bundle` | 不可重算的 admission 带 campaign 摘要与标注 | `KeyError: 'supporting_bundle_digest'` |
| `tests/contract/test_admission.py::test_policy_admission_appends_round_admitted_event` | 准入成功追加 `round_admitted`，拒绝追加 `round_admission_denied` | `KeyError: 'round_admitted'` |
| `tests/unit/test_orchestration_graph.py::test_verify_iteration_requires_round_and_budget_capacity` | 无剩余轮次或余额时不回到 `hypothesis_aggregator`（由 T12 验收） | `AssertionError: new round created after max_rounds` |
| `tests/contract/test_admission.py::test_round_beyond_max_rounds_is_denied` | `round_no > max_rounds` 由 predicate 拒绝，不依赖唯一约束 | `AssertionError: round beyond max_rounds was created` |
| `tests/contract/test_budget_ledger.py::test_concurrent_charge_cannot_overdraw_family_budget` | 两个数据库连接模拟竞争，最多一笔成功，余额不为负 | `AssertionError: remaining_total_seconds is negative` |
| `tests/contract/test_budget_ledger.py::test_recovery_does_not_charge_twice` | 同一 `(job_id, step_key, attempt_no)` 恢复后只扣一次 | `AssertionError: budget charged twice after recovery` |
| `tests/contract/test_budget_ledger.py::test_retry_with_new_attempt_charges_again` | 重试产生新 `attempt_no` 并再次扣费 | `AssertionError: retry was free` |
| `tests/contract/test_budget_ledger.py::test_fuzz_charge_decrements_both_budgets` | fuzz charge 同时扣总预算与 fuzz 子预算，`fuzz_seconds <= seconds` | `AssertionError: fuzz charge only decremented one budget` |
| `tests/contract/test_budget_ledger.py::test_exhaustion_returns_budget_exhausted_terminal` | 预算耗尽进入终态并返回 `BUDGET_EXHAUSTED` | `AssertionError: exhausted family created another round` |
| `tests/contract/test_budget_ledger.py::test_report_budget_includes_fuzz_sub_budget` | report 预算 6 个字段齐全，可由 charge 按 family 重建 | `KeyError: 'remaining_fuzz_seconds'` |
| `tests/contract/test_reuse.py::test_validation_reuses_campaign_build_and_detects_mismatch` | 校验包带 `reuse_origin`；任一版本摘要不符返回 `REUSE_MISMATCH` | `KeyError: 'reuse_origin'` |
| `tests/contract/test_export.py::test_export_family_keeps_campaign_and_rounds` | family 导出含 campaign 与每轮独立 bundle，摘要不变 | `KeyError: 'campaign'` |
| `tests/contract/test_evidence_v2.py::test_family_export_keeps_each_round_independently_verifiable` | family 导出后每轮 bundle 仍能独立 verify | `AssertionError: family export rewrote a round manifest` |
| `tests/contract/test_cli_status.py::test_campaign_status_lists_campaign_and_rounds` | status 返回 family（`AGGREGATING`）、campaign、rounds 与含 fuzz 字段的 budget | `KeyError: 'campaign'` |
| `tests/contract/test_cli_status.py::test_campaign_and_family_terminal_state_completed` | campaign 归档后 `state=COMPLETED`，family 运行中 `AGGREGATING`、归档后 `COMPLETED`，`verdict`/`reason_code` 为 null | `AssertionError: campaign completion used INCONCLUSIVE` |
| `tests/contract/test_cli_status.py::test_family_completed_sets_evidence_path_and_digest` | family 归档后 `state=COMPLETED`、`evidence_status='archived'`，`evidence_path` 指向 `family.json`、`evidence_digest` 为该文件 SHA-256 | `AssertionError: family COMPLETED left the evidence pointer null` |
| `tests/contract/test_cli_status.py::test_family_completed_requires_family_index` | 缺 `family.json` 或摘要不符时归档失败，不得以 `evidence_status=NULL` 绕过归档指针 CHECK | `AssertionError: family COMPLETED without a family index` |
| `tests/contract/test_export.py::test_family_index_is_byte_identical_to_export` | `export --family` 根 `family.json` 与归档件字节一致，单轮 manifest 不被重写 | `AssertionError: export rewrote the family index` |
| `tests/integration/test_migrations.py::test_budget_ledger_has_no_cross_remaining_check` | `budget_ledger` 约束上下界与 `max_fuzz_seconds <= max_total_seconds`、不设剩余余额交叉 CHECK；`general` 扣费后 `remaining_fuzz_seconds > remaining_total_seconds` 仍可写入 | `AssertionError: cross remaining check rejected a valid ledger` |
| `tests/contract/test_budget_ledger.py::test_fuzz_cap_uses_min_of_both_budgets` | 可执行 fuzz 上限为 `min(remaining_total_seconds, remaining_fuzz_seconds)`；`general` 扣费后 fuzz 余额可大于总余额，不违反约束 | `AssertionError: fuzz started with only one budget available` |
| `tests/contract/test_evidence_v2.py::test_manifest_uses_fixed_evidence_paths` | manifest 使用 `metadata/execution.json`、`metadata/probe.json`、`metadata/case.json`、`build/{version}/metadata.json`、六组 18 个 `replay/.../stdout.log` 等固定路径 | `AssertionError: manifest used an ad-hoc evidence path` |
| `tests/contract/test_cli_status.py::test_round_status_uses_terminal_state_and_evidence_status` | round 的 `state` 使用终态枚举，归档状态写在 `evidence_status`；`admission_kind` 由 reviews/admissions 派生 | `AssertionError: round state ARCHIVED is not a job state` |
| `tests/contract/test_evidence_v2.py::test_v2_blocked_bundle_requires_only_blocked_fields` | blocked 包无 family/envelope/plan_digest 也能通过，且不要求 build_ref | `KeyError: 'family_id'` |
| `tests/contract/test_evidence_v2.py::test_validation_bundle_requires_envelope_and_budget_snapshot` | validation/fixed execution 缺 `envelope` 或 `budget_snapshot` 时失败（`build_provenance` 缺失断言归入 T13，避免阻塞 T12/T13 并行） | `AssertionError: validation bundle without envelope was accepted` |
| `tests/integration/test_fuzz_isolation.py::test_fuzz_container_profile_and_corpus_are_isolated`（双标 `postgres`+`docker`；sandbox/build/replay 容器用例同规则） | fuzz 容器无外网、非 root、只读根、语料只读、输出受限 | `AssertionError: fuzz corpus was writable` |
| `tests/contract/test_evidence_v2.py::test_fixed_execution_has_envelope_but_no_reuse_origin` | fixed execution 的 envelope 非空，`build_ref`/`reuse_origin` 为 null | `AssertionError: fixed execution required a reuse_origin` |
| `tests/contract/test_evidence_v2.py::test_reuse_validation_requires_build_ref_and_reuse_origin` | 复用型 validation 缺任一字段时失败 | `AssertionError: reuse validation missing build_ref was accepted` |
| `tests/contract/test_evidence_v2.py::test_v2_build_record_rejects_input_aliases` | v2 构建记录不接受两个 input 别名 | `AssertionError: v2 build record accepted input aliases` |
| `tests/contract/test_evidence_v2.py::test_v1_build_record_still_requires_input_aliases` | v1 旧包继续要求两个 input 别名并通过冻结回归 | `AssertionError: v1 build record no longer requires input aliases` |
| `tests/contract/test_fuzz.py::test_frozen_harness_rejects_model_generated_material` | 未审核或改写 harness 在执行前返回 `HARNESS_REJECTED` | `AssertionError: model-generated harness reached sandbox` |
| `tests/contract/test_fuzz.py::test_crash_seed_requires_provenance_and_six_replays` | 缺少 provenance 或未完成六回放不能出结论 | `AssertionError: verdict emitted before six replays` |

### T13 构建溯源与工具链边界

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/contract/test_build_provenance.py::test_declared_flags_must_be_subset_of_effective_flags` | 声明参数未出现在生效集合时返回 `BUILD_PROVENANCE_MISSING` | `AssertionError: declared flag absent from effective set was accepted` |
| `tests/contract/test_build_provenance.py::test_two_versions_must_have_equal_effective_flags` | 归一化后两版生效序列不等即失败 | `AssertionError: unequal effective flags were treated as comparable` |
| `tests/contract/test_build_provenance.py::test_include_order_is_significant` | `-I a -I b` 与 `-I b -I a` 不相等，即使集合相同 | `AssertionError: include order was normalized away` |
| `tests/contract/test_build_provenance.py::test_connected_and_split_flag_forms_are_equivalent` | `-I include ≡ -Iinclude`、`-L dir ≡ -Ldir`、`-l foo ≡ -lfoo` 归一后相等 | `AssertionError: split and joined flag forms were treated as different` |
| `tests/contract/test_build_provenance.py::test_declared_flags_are_normalized_before_compare` | `declared_compile_flags` 与生效参数走同一归一化函数，不只归一化生效侧 | `AssertionError: declared flags were compared without normalization` |
| `tests/contract/test_build_provenance.py::test_cmake_and_make_success_faces_are_captured` | CMake 与 Make 成功路径分别采集 `compile_commands.json` 与 `cc-shim.log`，并以 `build_provenance` 角色归档 | `KeyError: 'build_provenance'` |
| `tests/contract/test_build_provenance.py::test_validation_bundle_requires_build_provenance` | T13 落地后 `execution`/`campaign` 缺两版 `build_provenance` 角色时验包失败 | `AssertionError: bundle without build_provenance was accepted` |
| `tests/contract/test_build_provenance.py::test_build_provenance_rules_version_is_bound_in_plan` | `build_provenance_rules_version` 进入 plan/report 并影响 `plan_digest` | `KeyError: 'build_provenance_rules_version'` |
| `tests/contract/test_build_provenance.py::test_missing_face_blocks_plan_freeze` | 无 CMake/Make 核对面时冻结阶段阻断 | `AssertionError: plan froze without a provenance face` |
| `tests/contract/test_build_provenance.py::test_shell_recipe_requires_separate_face_review` | legacy shell 配方无 `shell_face_review` 或核对面时阻断；`shell_recipe_digest` 不能代替核对面 | `AssertionError: unreviewed shell recipe counted as comparable` |
| `tests/integration/test_toolchain_image.py::test_oniguruma_case_uses_existing_toolchain_image`（双标 `postgres`+`docker`） | 已有 cmake/make/autoconf/automake/libFuzzer 的案例不要求镜像 v2 | `AssertionError: Oniguruma-like case required toolchain image v2` |
| `tests/integration/test_toolchain_image.py::test_missing_tool_requires_toolchain_image_v2` | 需要 pkg-config/libtool/ninja/git 的案例被路由到新镜像或阻断 | `AssertionError: missing tool assumed present` |
| `tests/contract/test_release.py::test_release_manifest_keeps_contract_version_one` | release smoke/B03 仍按 `contract_version=1` 校验，v2 smoke 不混入 | `AssertionError: release manifest contract_version changed` |

### T14 模型出口与 ExperimentSpec

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_has_closed_nine_fields` | 九个字段必需，未知字段与自由命令被拒绝 | `AssertionError: unknown ExperimentSpec field accepted` |
| `tests/contract/test_experiment_spec.py::test_expected_signature_matches_full_accepted_signature` | `expected_signature` 与集合项逐字段匹配，READ/WRITE 或 access_size 不同不匹配 | `AssertionError: signature matched on error only` |
| `tests/contract/test_experiment_spec.py::test_unresolvable_evidence_refs_block_experiment_spec` | 引用不可解析时保留线索但不生成 ExperimentSpec | `AssertionError: experiment created from unresolvable evidence` |
| `tests/contract/test_model_outlet.py::test_model_audit_role_is_written` | 模型版本、prompt 版本、允许字段摘要与脱敏版本写入 `model_audit` | `KeyError: 'model_audit'` |
| `tests/contract/test_model_outlet.py::test_model_finding_must_be_hypothesis` | 模型来源 `kind=fact` 被阻断，确定性事实走 `ToolResult` | `AssertionError: model fact entered the evidence chain` |
| `tests/contract/test_model_outlet.py::test_offline_default_makes_no_external_request` | 默认离线时零外部请求，且仍写 `provider=offline` | `AssertionError: external model request attempted in offline mode` |
| `tests/contract/test_model_outlet.py::test_endpoint_allowlist_rejects_private_and_loopback` | 私网、回环、IP 字面量与非白名单主机被拒绝 | `AssertionError: private endpoint accepted` |
| `tests/contract/test_model_outlet.py::test_prompt_and_model_versions_are_audited` | 审计含模型版本、prompt 版本与字段摘要 | `KeyError: 'prompt_version'` |
| `tests/contract/test_model_outlet.py::test_redaction_strips_paths_and_secret_shapes` | 路径、令牌样式与私钥头不外送 | `AssertionError: secret-shaped text left the control plane` |
| `tests/contract/test_model_outlet.py::test_model_failure_falls_back_without_weakening_policy` | 超时/非法输出回退离线或阻断，策略不变 | `AssertionError: fallback relaxed policy` |
| `tests/contract/test_hypothesis_verdict.py::test_hypothesis_does_not_change_deterministic_verdict` | 同一观测下增删 hypothesis，判定不变 | `AssertionError: verdict changed with hypothesis text` |
| `tests/contract/test_b04_hypothesis_quality.py::test_b04_annotation_set_is_versioned` | 标注集有 `annotation_version`、来源与样本量，版本冻结 | `KeyError: 'annotation_version'` |
| `tests/contract/test_b04_hypothesis_quality.py::test_b04_reports_end_to_end_and_accepted_precision` | 真实 patch 标注集上产出 end-to-end precision、accepted precision、recall、rejection_rate 与样本量 | `KeyError: 'end_to_end_precision'` |
| `tests/contract/test_b04_hypothesis_quality.py::test_b04_agent_scenarios_remain_release_gate` | B04-A 六类场景与路由/可追溯/越权指标仍是发布门禁，不被 B04-H 替换 | `AssertionError: B04-H replaced the B04-A gate` |

T14 实现新增坐标（P3）。下列 38 条不在原计划表内，是实现与自审过程中补上的，与上表同属 T14 验收。标注「自审加固」的坐标来自对 T14 三个模块的逐行自审：先用探针复现缺陷，再写成 RED，修复后转绿。原计划坐标 `test_model_finding_must_be_hypothesis` 已归位到上表登记的 `test_model_outlet.py`。带「†」的失败信息是 P3 用探针对当时的实现直接观察到的行为，不是 pytest 的输出行。

- **两处规范的解释**（已定，写在实现里）：
  - security-design-delta §2.5「脱敏规则命中禁止字段 → 阻止发送」：按「先遮蔽，再对整个请求体扫一遍，仍有密钥类内容才阻止发送并记录原因」执行（`REDACTION_REJECTED`）。可遮蔽的形态遮蔽后照发；只有遮蔽覆盖不到的位置（例如字典的键名）残留密钥时才阻断。
  - §2.3「任何自由文本命令、shell 片段……视为非法输出并阻断」：T14 **不按文本特征阻断**。封闭的 `AgentOutput` 结构里没有命令或工具调用的落点；命令注入类缺陷的假设本身就会含 shell 文本，按文本阻断会误伤。此点待评审确认。
- **签名规则与信封一致**：`experiment_spec.validate_signature` 对值与类型的规则跟 `state._envelope_signature_set` 相同（`operation` 为 `READ` 或 `WRITE`，`access_size` 为 1 到 2^31-1），由 `test_signature_rules_agree_with_the_envelope_validator` 防漂移；文本字段另加两条更严的规则（无控制字符、不超过 200 字符）。
- **标注集版本格式**：`b04-annotations-v1`、一个冒号、`sha256:` 加 samples 的规范化摘要（`b04_eval.annotation_set_version`），加载时核对摘要。
- **尚未由坐标验证的几点**（要求不变）：连接与读取超时、重定向目标与证书校验的强制属于传输适配层，T14 的出口只把校验过的 endpoint 与脱敏后的请求体交给注入的传输层；B04 报告的分桶维度（按 family、模式、confidence）与证据引用有效率、契约拒绝率尚未实现，等真实标注集；信封交叉校验（`mutation_constraints` 是否为 `mutation_limits` 的子集、`input_family` 是否在允许集合内、目标是否落在版本与源码范围内）不在 T14 本轮。
- **最后防线的范围**：出口体按结构逐个字符串扫描（键名也算），不扫序列化后的 JSON 文本——JSON 的结构本身（`token": "`）会被读成键值形式的口令，曾使 `parse_token` 这样的普通键名阻断整次请求。以凭据词结尾的字典键名（`auth_token`、`DB_PASSWORD`，也包括 `max_token`）其值被遮蔽而不是阻断；空值保持原样。
- **已知限制**：12 位十六进制的容器短 ID 不遮蔽（与 git 短提交号无法区分）；不带账号口令的内部 URL 不遮蔽；以凭据词结尾的键名下的值一律遮蔽，无法区分凭据与同名配置（`max_token: 4096`）；`sort -u names.txt`、`psql -U admin` 这类命令会被多遮蔽紧随其后的一个词；散文里 `token:`、`password:` 后面紧随的一个词会被遮蔽。
- 带「※」的失败信息是对加固前实现（提交 `ca0a9a2`）实测得到的；标「未保留」的三条是实现与测试同轮提交的收尾用例，没有留下首次失败记录。

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/contract/test_model_outlet.py::test_online_outlet_requires_explicit_provider` | 在线出口缺 provider → `PROVIDER_REQUIRED`，传输层零调用 | 未保留 |
| `tests/contract/test_model_outlet.py::test_connection_errors_fall_back_like_timeouts` | 连接错误、`OSError` 与超时同样回退 `fallback_offline` | 未保留 |
| `tests/contract/test_model_outlet.py::test_constructor_job_id_flows_into_request_path_audit` | 构造时传入的 job_id 进入在线与离线两条路径的审计 | 未保留 |
| `tests/contract/test_model_outlet.py::test_redaction_masks_the_whole_private_key_block`（自审加固） | 私钥整块被遮蔽；缺 END 时抹到文本末尾 | `AssertionError: private key material survived redaction` |
| `tests/contract/test_model_outlet.py::test_redaction_masks_common_token_shapes`（自审加固） | GitHub 细粒度令牌、Stripe、Google、GitLab、PyPI、JWT、`Bearer`、`Basic`、口令赋值各形态被遮蔽 | `AssertionError: token shape survived redaction` |
| `tests/contract/test_model_outlet.py::test_redaction_masks_windows_unc_and_single_segment_paths`（自审加固） | Windows 盘符路径、UNC 路径、单段绝对路径变为 `[PATH]`；紧挨字母或数字的斜杠不受影响 | `AssertionError: assert 'opened C:\\U…' == 'opened [PATH] …'` |
| `tests/contract/test_model_outlet.py::test_redaction_masks_command_line_credentials`（自审加固） | 命令行里的凭据（`curl -u`、`--user`、`--password=`）只遮蔽值 | ※ `AssertionError: assert 'curl -u admi…' == 'curl -u [RED…'` |
| `tests/contract/test_model_outlet.py::test_redaction_keeps_plain_factual_sentences` | 防过度脱敏的守卫：普通技术描述原样保留 | 守卫用例，自始通过 |
| `tests/contract/test_model_outlet.py::test_redaction_reaches_nested_field_values`（自审加固） | 允许字段的值是嵌套的列表或字典时，令牌、私钥、连接串同样被遮蔽 | `AssertionError: assert 'ghp_…' not in '{"stage": …'` |
| `tests/contract/test_model_outlet.py::test_outlet_rejects_bytes_and_unserializable_field_values`（自审加固） | bytes、非有限浮点、非字符串键等 → `FIELD_TYPE_REJECTED`，传输层不被调用 | `TypeError: Object of type bytes is not JSON serializable` |
| `tests/contract/test_model_outlet.py::test_outlet_blocks_a_body_that_still_carries_a_secret`（自审加固） | 密钥藏在字典键名里 → `REDACTION_REJECTED`，传输层不被调用 | `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_allowlist_matches_on_path_segment_boundaries`（自审加固） | 白名单 `/v1` 放行 `/v1` 与 `/v1/x`，拒绝 `/v1evil` | `AssertionError: external model request attempted in offline mode` |
| `tests/contract/test_model_outlet.py::test_allowlist_matches_the_port`（自审加固） | 白名单匹配端口；未写端口按 443 | `AssertionError: external model request attempted in offline mode` |
| `tests/contract/test_model_outlet.py::test_endpoint_rejects_userinfo_and_dot_segments`（自审加固） | 带账号口令的 endpoint、含点段或 `%2e%2e` 的路径被拒 | `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_allowlist_entries_reject_userinfo_and_dot_segments`（自审加固） | 白名单条目自身带账号口令、点段或编码的点时构造器拒绝 | ※ `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_model_audit_requires_a_job_id`（自审加固） | `job_id` 必须是可解析为 UUID 的字符串 | `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_model_audit_enforces_the_offline_invariants`（自审加固） | `provider="offline"` 时版本、摘要为 null，耗时为 0，`outcome="offline"` | `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_model_audit_rejects_malformed_versions_and_outcomes`（自审加固） | 版本非字符串、空的脱敏版本、词表外的 outcome、非有限耗时被拒 | `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_online_outlet_requires_model_and_prompt_versions`（自审加固） | 缺模型版本或 prompt 版本 → 在触达传输层之前拒绝 | `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_outlet_requires_a_job_id_before_any_request`（自审加固） | 没有 job_id 的出口拒绝一切请求，传输层零调用 | `Failed: DID NOT RAISE OutletError` |
| `tests/contract/test_model_outlet.py::test_address_denied_transport_failure_blocks_as_outlet_error`（自审加固） | 连接层拒绝地址 → `ENDPOINT_ADDRESS_REJECTED` | `SafeHttpError: address answer is in the shared rejection set` |
| `tests/contract/test_model_outlet.py::test_other_safe_http_failures_fall_back_offline`（自审加固） | 连接层其它失败回退 `fallback_offline` | `SafeHttpError: guarded step failed` |
| `tests/contract/test_model_outlet.py::test_unexpected_transport_errors_block_as_outlet_errors`（自审加固） | 其它传输异常 → `TRANSPORT_FAILED`，带审计 | `RuntimeError: transport crashed` |
| `tests/contract/test_model_outlet.py::test_rejected_model_output_keeps_an_audit_trail`（自审加固） | 输出被拒后 `OutletError` 带审计，含实际外发请求体的摘要 | `AttributeError: 'OutletError' object has no attribute 'model_audit'` |
| `tests/contract/test_model_outlet.py::test_ordinary_key_names_do_not_block_a_structured_field`（自审加固） | 结构化字段里以凭据词结尾的普通键名（如 `parse_token`）不再阻断整次请求；键名原样保留，其值被遮蔽 | † `OutletError: … (key-value credential); refusing to send it`（请求被 `REDACTION_REJECTED` 阻断） |
| `tests/contract/test_model_outlet.py::test_credential_named_keys_have_their_value_masked`（自审加固） | 被拆成键值对的凭据（`auth_token`、`password`、数字、容器）其值被遮蔽；空值保持 | † `OutletError: … (key-value credential); refusing to send it`（请求被 `REDACTION_REJECTED` 阻断） |
| `tests/contract/test_model_outlet.py::test_outlet_rejects_values_the_strict_encoder_cannot_carry`（自审加固） | 孤立的代理字符、超出转换上限的整数 → `FIELD_TYPE_REJECTED`，不漏出编码器的异常 | † `UnicodeEncodeError: 'utf-8' codec can't encode character '\ud800'` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_rejects_unknown_keys_in_sub_objects`（自审加固） | 两个子对象是封闭键集，命令、shell 键被拒 | `Failed: DID NOT RAISE ExperimentSpecError` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_validates_sub_object_value_types`（自审加固） | 子对象的值类型、必填字段、`access_size` 的类型 | `Failed: DID NOT RAISE ExperimentSpecError` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_rejects_absolute_or_traversing_target_path`（自审加固） | `target_path` 是仓库相对路径 | `Failed: DID NOT RAISE ExperimentSpecError` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_bounds_symbol_family_and_rationale`（自审加固） | 符号、输入族与说明文字的词法和长度界限 | `Failed: DID NOT RAISE ExperimentSpecError` |
| `tests/contract/test_experiment_spec.py::test_signature_match_distinguishes_bool_and_float_from_int`（自审加固） | 签名比较要求值与类型都相同 | `AssertionError: assert True is False` |
| `tests/contract/test_experiment_spec.py::test_signature_rules_agree_with_the_envelope_validator`（自审加固） | 同一批签名过本模块与信封两边的校验，结论一致 | ※ `ImportError: cannot import name 'validate_signature'` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_rejects_non_text_confidence`（自审加固） | `confidence` 非文本 → `ExperimentSpecError`，不漏出原始异常 | ※ `TypeError: cannot use 'list' as a set element` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_bounds_lengths_and_control_characters`（自审加固） | C1 控制字符被拒；文本与列表字段有上界 | ※ `Failed: DID NOT RAISE ExperimentSpecError` |
| `tests/contract/test_b04_hypothesis_quality.py::test_annotation_set_rejects_malformed_samples`（自审加固） | 样本不是对象、缺字段、行号无序、签名不合法、文件不是 JSON → `ANNOTATION_INVALID` | `Failed: DID NOT RAISE B04GateError` |
| `tests/contract/test_b04_hypothesis_quality.py::test_annotation_version_binds_the_annotation_digest`（自审加固） | 版本串符合格式且摘要与 samples 一致；改样本不升版本被拒 | `Failed: DID NOT RAISE B04GateError` |
| `tests/contract/test_b04_hypothesis_quality.py::test_annotation_version_requires_the_canonical_separator`（自审加固） | 版本串只认 `b04-annotations-v1:sha256:…` 一种写法 | ※ `Failed: DID NOT RAISE B04GateError` |

### T15 在线情报

T15 可以先独立实现采集，但最终验收依赖 T10 的 `intel_snapshot`/`license_record` 角色与 T11 的 `intel` 节点。

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/contract/test_intel_fetch.py::test_domain_allowlist_and_address_recheck_reject_private_networks` | 非白名单域、私网、回环、元数据地址均被拒绝 | `AssertionError: private address fetched` |
| `tests/contract/test_intel_fetch.py::test_each_redirect_hop_is_revalidated` | 任一跳越界即终止，最多 5 跳，记录跳数与原因 | `AssertionError: redirect to non-allowlisted host followed` |
| `tests/contract/test_intel_fetch.py::test_https_only_with_size_and_timeout_limits` | 非 HTTPS、超过 8 MiB 响应、连接 10s/读取 30s/总 60s 超时均失败关闭 | `AssertionError: HTTP response accepted` |
| `tests/contract/test_intel_fetch.py::test_decompression_is_bounded` | 解压后超过 32 MiB 或压缩比超过 100:1 被拒绝 | `AssertionError: compression bomb accepted` |
| `tests/contract/test_intel_fetch.py::test_snapshot_is_immutable_and_records_license` | 快照只读，含来源、时间、摘要与许可；离线快照同样归档 | `KeyError: 'license'` |
| `tests/contract/test_intel_fetch.py::test_external_text_does_not_change_routing_or_tools` | 公告中的伪造指令不改变路由或工具调用 | `AssertionError: external text changed tool authorization` |
| `tests/contract/test_intel_fetch.py::test_missing_or_disallowed_license_is_rejected` | 缺许可或用途不符的材料以 `POLICY_DENIED`（审计 `detail.sub_reason=LICENSE_REJECTED`）拒绝，不得进入复现流程 | `AssertionError: material without allowed license entered workflow` |
| `tests/contract/test_intel_fetch.py::test_intel_node_archives_missing_or_conflicting_snapshot`（编排图边 #6 `intel → archive`，依赖 T11 `intel` 节点） | `intel` 节点遇到快照缺失返回 `MATERIAL_MISSING`、来源冲突返回 `SOURCE_CONFLICT` 并转入 `archive` 阻断，不使用未验证内容 | `AssertionError: missing or conflicting intel snapshot reached version node` |

## 3. 循环确定性策略

1. **假时钟**。所有轮次、审核、预算与重试测试注入可控时钟，禁止 `sleep`；时限推进用显式 `advance()`。UTC 时间由假时钟产生，数据库时钟只在集成测试中作为独立断言。
2. **假 sandbox**。单元与契约测试使用记录型替身返回固定的 `BuildResult` / `ReplayResult` 与日志字节；不启动 Docker。替身记录调用顺序、输入摘要、编译参数与容器名，用于断言重试与复用。
3. **故障注入**。在节点边界注入瞬时 PostgreSQL 错误、容器启动失败、构建诊断失败、超时、OOM、日志截断、租约丢失与旧 generation 写回；断言每次都有确定原因码，且不重复产生副作用。
4. **节点重入 no-op**。同一 `(job_id, stage, step_key, attempt_no, generation)` 重入必须返回已持久化结果；build、replay、admission、budget charge 与 archive 都不得重复。重入测试至少覆盖 prepare、review、build、verify、archive 五个节点。
5. **随机性**。fuzz 与实验排序使用固定 RNG seed 并记录 provenance；测试不得依赖系统随机数、当前时间或网络。种子语料与 crash seed 以字节和摘要比较，不以路径比较。
6. **幂等键**。预算扣费使用 `(job_id, step_key, attempt_no)`，准入、构建复用、证据归档各有一个持久化幂等键；测试通过重复调用验证结果一致、审计不重复。
7. **单执行槽位**。family 的 child 串行执行；并发预算测试只开两个数据库连接模拟竞争，验证 SQL 原子性，不代表生产多 worker。禁止用“并行 child”作为测试前提。

## 4. B04 质量指标

B04 由两个子基准组成，不能互相替换。

### 4.1 B04-A（v0.1，保留）

- 覆盖材料齐全、材料冲突、补丁歧义、二进制目标、提示注入与缺证六类 Agent 场景。
- 记录结构合规率、路由准确率、可追溯事实比例与越权尝试数；模型配置运行三轮。
- **发布门禁不变**：三轮零实际越权工具调用，进入下游的结果全部通过契约校验。v0.2 的任何新指标都不能覆盖、替换或放宽 B04-A。

### 4.2 B04-H（v0.2，新增）

B04-H 的“真实 patch 标注集”由人工在公开补丁与对应源码上标注：每个标注给出目标符号、路径、行号范围、可接受签名与输入族。评测单位是一条 hypothesis 是否命中标注。

- **end-to-end precision**（主指标）= 命中标注的 hypothesis 数 / 全部模型产出的 hypothesis 数；被准入拒绝、越界或证据不可解析的条目仍计入分母。
- **accepted precision**（辅助）= 命中标注的 hypothesis 数 / 通过准入的 hypothesis 数；该指标不能单独用于发布结论。
- **recall** = 命中标注的 hypothesis 数 / 标注集中可被该案例材料支持的标注数。一个标注被多条 hypothesis 命中只计一次。
- **rejection_rate** = 被拒绝条数 / 全部产出条数；同时报告拒绝原因分布，避免通过大量拒绝刷高 accepted precision。
- **样本量** = 参与评测的 hypothesis 总数、标注条数与案例数；样本量低于阈值时只报告不设门槛。
- **匹配规则**：符号与路径必须精确匹配；行号落在标注范围或 ±3 行内；签名按**完整签名**匹配——`error`、`function`、`source` 必须相等，`operation`、`access_size` 若存在也必须相等，可选字段存在性不同即不匹配；输入族必须匹配。不能只按 sanitizer 类别或 error 字符串匹配。超出标注文件范围的 hypothesis 记为未命中。
- **annotation_version**：格式为 `b04-annotations-v1` 加标注集摘要，例如版本标签 `b04-annotations-v1` 后接标注集摘要（带 `sha256` 前缀的 64 位小写十六进制）。来源是人工标注记录与对应公开补丁摘要；标注集写入后冻结，新增或修改标注必须升版本并保留旧版本，否则历史报告不可复现。
- **报告维度**：按 family、模式（fixed/guided）、confidence 分桶，报告 end-to-end precision、accepted precision、recall、rejection_rate、样本量、证据引用有效率与契约拒绝率；同时报告“无标注材料”上的 hypothesis 数，避免用未标注区域刷 precision。
- **发布门槛**：第一轮评测（三轮）建立基线并冻结阈值；候选相对基线 end-to-end precision 或 recall 下降超过 5 个百分点时阻断。B04-H 是新的质量报告/门槛，不能替代 B04-A；质量指标不参与 `REPRODUCED` 判定，判定仍完全由六次回放与确定性规则产生。

### 4.3 安全与归属

- 三轮评测零实际越权工具调用，所有进入下游的 hypothesis 与 ExperimentSpec 通过契约校验；B04-A 的这条硬门槛继续有效。
- B04 人工标注集是 T14 的显式工作项，从 T14 开始准备。B05 基准不在 T09–T15 范围内。

## 5. CI 约束

1. **四组 skipped=0**。`postgres`、`docker`、`asan`、`contract` 四组在 CI 中必须全部实际运行且 `skipped=0`；组间互斥且并集等于收集总数，由 `check_test_partition_counts` 校验。四组表达式冻结为 `postgres = "postgres and not docker"`、`docker = "postgres and docker"`、`asan = "asan"`、`contract = "not postgres and not asan"`，本轮不改 `ci.yml`。
2. **前置条件先失败**。缺少数据库、symbolizer、clang、patch 或固定镜像时在 pytest 之前失败，不把环境缺失转成 skip。
3. **无 xfail/skip**。T10–T15 的新测试不得以 `xfail`、`skip` 或条件跳过掩盖未实现能力；RED 阶段保留失败记录，GREEN 后删除临时标记。
4. **门禁配置**。T09 后仓库 Markdown 从 15 份增加到 27 份，即“仓库其余 15 份 + 本目录 12 份，且集合包含本目录 12 份”；REQ/TC 门禁必须 `ok: true`。v0.1 根目录文档引用 REQ-11..16 必须报错，v0.2 目录必须允许 01..16。
5. **每轮证据可独立校验**。CI 至少对每轮 bundle 单独运行 `verify-bundle`，再对 family 导出运行一次；不允许只校验聚合目录而跳过单轮。
6. **marker 组契约（D37，零改 ci.yml）**。每条测试坐标在落地 PR 中必须声明 marker 组。四组表达式保持现状，由此冻结以下规则：

| 组 | `ci.yml` 表达式 | 标记规则 |
| --- | --- | --- |
| `postgres` | `postgres and not docker` | 只依赖数据库的用例 |
| `docker` | `postgres and docker` | **必须同时标 `postgres` + `docker`**；只标 `docker` 会被 `contract` 表达式收走 |
| `asan` | `asan` | **禁止叠 `postgres`**；`asan` 表达式不排除 postgres，叠加会同时计入两组 |
| `contract` | `not postgres and not asan` | 纯契约/单元用例；不得把缺环境的用例塞进来 |

默认映射如下，`tests/unit/` 由 T11 创建并归入 contract 组：

| 测试路径 | marker 组 |
| --- | --- |
| `tests/contract/**`（并发预算用例除外） | `contract` |
| `tests/unit/**` | `contract` |
| `tests/integration/test_migrations.py`、`tests/integration/test_worker_fence.py` | `postgres` |
| `tests/integration/test_release_rollback.py`、`tests/integration/test_review_locks.py` | `postgres` |
| `tests/contract/test_budget_ledger.py` 的并发/事务用例 | `postgres` |
| `tests/integration/test_fuzz_isolation.py`、`tests/integration/test_toolchain_image.py`、sandbox/build/replay 容器用例 | `postgres` + `docker`（双标） |
| 六次回放与 ASan 签名用例 | `asan`（禁止叠 `postgres`） |

不允许把缺数据库、缺 Docker 或缺 symbolizer 的用例标成 contract 组来绕过 `skipped=0`。这是现行表达式约束；若未来要清理表达式（如 docker 独立成组），必须同时改 `ci.yml`、`scripts/run_suite.sh`、`check_test_partition_counts` 与相关测试，另立任务，不在本轮承诺。
7. **失败保留记录**。新增测试首次失败的命令、断言点与错误信息记入 PR 或任务记录；不把 RED 输出改写成通过。
