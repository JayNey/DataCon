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

改8 增补 family 转移决策入口与坐标，不改变 REQ/TC 与 §10 原因码：campaign 完成且无候选 seed 时，runtime 记录 `no_next_round` 决策后 family 归档；无决策保持 `AGGREGATING`。决策按决策点 `after_round_no` 记录（入口契约见[接口 §9.2](interface-contract-delta.md)）。以下五条坐标均标 `postgres`（`tests/integration/test_family_archive_recovery.py`），不叠 `docker`/`asan`，登记在下表 family 归档恢复三条坐标之后。

改7 准入持久化三路径：`admitted` 写一行 `admissions` 与一条 `round_admitted`；`denied`（谓词拒绝或同 `(parent_job_id, round_no)` 异参冲突）不写 `admissions`、写一条 `round_admission_denied`；`already_admitted`（同参幂等重入）不写行、不写事件并返回既有 admission。`ROUND_ALREADY_ADMITTED` 只作为 outcome 的 `sub_reason` 与异参冲突的审计 `detail.sub_reason`，不进入 `jobs.reason_code`。以下 7 条准入持久化坐标均标 `postgres`（`tests/integration/test_admission.py`），不叠 `docker`/`asan`；`test_conflicting_budget_snapshot_is_denied` 验证 `budget_snapshot_digest` 参与幂等比较，最后两条验证 admission 的 envelope 必须同时绑定当前 approval 链尾与 frozen plan。

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
| `tests/contract/test_admission.py::test_admission_envelope_must_match_approval` | 调用方 envelope 与 approval 链尾的 `envelope_digest` 不符时拒绝（`ADMISSION_DENIED` + `PARENT_APPROVAL_ENVELOPE_MISMATCH`），只产生 denied 事件 | `AssertionError: unapproved envelope was admitted` |
| `tests/contract/test_admission.py::test_admission_plan_envelope_must_match` | 调用方 envelope 与 frozen plan 的 `envelope_digest` 不符时拒绝（`ADMISSION_DENIED` + `PLAN_ENVELOPE_MISMATCH`），不写 admission 行 | `AssertionError: plan envelope mismatch was admitted` |
| `tests/unit/test_orchestration_graph.py::test_verify_iteration_requires_round_and_budget_capacity` | 无剩余轮次或余额时不回到 `hypothesis_aggregator`（由 T12 验收） | `AssertionError: new round created after max_rounds` |
| `tests/contract/test_admission.py::test_round_beyond_max_rounds_is_denied` | `round_no > max_rounds` 由 predicate 拒绝，不依赖唯一约束 | `AssertionError: round beyond max_rounds was created` |
| `tests/integration/test_admission.py::test_policy_admission_persists_one_row_and_one_event`（`postgres`） | 首次准入写一行 `admissions(approval_kind='policy')` 与一条 `round_admitted`，不写 `reviews`/`family_approvals` | `AssertionError: policy admission did not persist one row and one event` |
| `tests/integration/test_admission.py::test_predicate_denial_writes_round_admission_denied_event`（`postgres`） | 谓词拒绝（如 `round_no > max_rounds`）不写 `admissions`，写一条 `round_admission_denied` | `AssertionError: predicate denial did not persist a denied event` |
| `tests/integration/test_admission.py::test_idempotent_readmission_writes_no_second_event`（`postgres`） | 同参重入返回 `already_admitted`，不新增行、不写事件，返回既有 admission | `AssertionError: idempotent readmission wrote a second event` |
| `tests/integration/test_admission.py::test_conflicting_readmission_is_denied`（`postgres`） | 同 `(parent_job_id, round_no)` 异参冲突返回 `ADMISSION_DENIED` + `sub_reason=ROUND_ALREADY_ADMITTED`，写一条 denied 事件 | `AssertionError: conflicting readmission was accepted` |
| `tests/integration/test_admission.py::test_conflicting_budget_snapshot_is_denied`（`postgres`） | 同 `(parent_job_id, round_no)` 但 `budget_snapshot_digest` 不同的重入返回 `ADMISSION_DENIED` + `sub_reason=ROUND_ALREADY_ADMITTED`，不新增 admissions 行，写一条 denied 事件 | `AssertionError: conflicting budget snapshot was accepted` |
| `tests/integration/test_admission.py::test_unapproved_envelope_is_denied`（`postgres`） | 用不是 approval 链尾信封的 body 调 `record_admission`：返回 denied、`sub_reason=PARENT_APPROVAL_ENVELOPE_MISMATCH`、0 行 admissions、恰 1 条 denied 事件 | `AssertionError: unapproved envelope was admitted` |
| `tests/integration/test_admission.py::test_plan_envelope_mismatch_is_denied`（`postgres`） | plan 的 `envelope_digest` 与 approval 不同时，admitted envelope 也被拒：`sub_reason=PLAN_ENVELOPE_MISMATCH`、0 行 admissions、恰 1 条 denied 事件 | `AssertionError: plan envelope mismatch was admitted` |
| `tests/contract/test_budget_ledger.py::test_concurrent_charge_cannot_overdraw_family_budget` | 两个数据库连接模拟竞争，最多一笔成功，余额不为负 | `AssertionError: remaining_total_seconds is negative` |
| `tests/contract/test_budget_ledger.py::test_recovery_does_not_charge_twice` | 同一 `(job_id, step_key, attempt_no)` 恢复后只扣一次 | `AssertionError: budget charged twice after recovery` |
| `tests/contract/test_budget_ledger.py::test_retry_with_new_attempt_charges_again` | 重试产生新 `attempt_no` 并再次扣费 | `AssertionError: retry was free` |
| `tests/contract/test_budget_ledger.py::test_fuzz_charge_decrements_both_budgets` | fuzz charge 同时扣总预算与 fuzz 子预算，`fuzz_seconds <= seconds` | `AssertionError: fuzz charge only decremented one budget` |
| `tests/contract/test_budget_ledger.py::test_exhaustion_returns_budget_exhausted_terminal` | 预算耗尽进入终态并返回 `BUDGET_EXHAUSTED` | `AssertionError: exhausted family created another round` |
| `tests/contract/test_budget_ledger.py::test_report_budget_includes_fuzz_sub_budget` | report 预算 6 个字段齐全，可由 charge 按 family 重建 | `KeyError: 'remaining_fuzz_seconds'` |
| `tests/integration/test_review_locks.py::test_family_approval_initializes_budget_ledger`（`postgres`） | 真实 `record_review(decision="approve")` 在审批事务内创建 1 行 `budget_ledger`（caps 来自已批准 envelope，remaining=max）；`charge_step_budget` 可扣 1 秒；同参重批幂等、不新增行、不重置 spent | `AssertionError: family approval did not initialize budget_ledger` |
| `tests/contract/test_reuse.py::test_validation_reuses_campaign_build_and_detects_mismatch` | 校验包带 `reuse_origin`；任一版本摘要不符返回 `REUSE_MISMATCH` | `KeyError: 'reuse_origin'` |
| `tests/contract/test_export.py::test_export_family_keeps_campaign_and_rounds` | family 导出含 campaign 与每轮独立 bundle，摘要不变 | `KeyError: 'campaign'` |
| `tests/contract/test_evidence_v2.py::test_family_export_keeps_each_round_independently_verifiable` | family 导出后每轮 bundle 仍能独立 verify | `AssertionError: family export rewrote a round manifest` |
| `tests/contract/test_cli_status.py::test_campaign_status_lists_campaign_and_rounds` | status 返回 family（`AGGREGATING`）、campaign、rounds 与含 fuzz 字段的 budget | `KeyError: 'campaign'` |
| `tests/contract/test_cli_status.py::test_campaign_and_family_terminal_state_completed` | campaign 归档后 `state=COMPLETED`，family 运行中 `AGGREGATING`、归档后 `COMPLETED`，`verdict`/`reason_code` 为 null | `AssertionError: campaign completion used INCONCLUSIVE` |
| `tests/contract/test_cli_status.py::test_family_completed_sets_evidence_path_and_digest` | family 归档后 `state=COMPLETED`、`evidence_status='archived'`，`evidence_path` 指向 `family.json`、`evidence_digest` 为该文件 SHA-256 | `AssertionError: family COMPLETED left the evidence pointer null` |
| `tests/contract/test_cli_status.py::test_family_completed_requires_family_index` | 缺 `family.json` 或摘要不符时归档失败，不得以 `evidence_status=NULL` 绕过归档指针 CHECK | `AssertionError: family COMPLETED without a family index` |
| `tests/contract/test_export.py::test_family_index_is_byte_identical_to_export` | `export --family` 根 `family.json` 与归档件字节一致，单轮 manifest 不被重写 | `AssertionError: export rewrote the family index` |
| `tests/integration/test_family_archive_recovery.py::test_family_archive_recovery_writes_index_and_converges`（`postgres`） | family 仍 `AGGREGATING`、所有 child 已终态且无 pending envelope 时，worker 扫描幂等补落盘 `family.json` 并调用无租约 `complete_family`；重复扫描不改变字节、不重复写 `family_completed` audit | `AssertionError: family stayed AGGREGATING after the recovery scan` |
| `tests/integration/test_family_archive_recovery.py::test_family_archive_recovery_reuses_existing_index_after_crash`（`postgres`） | 崩溃点为索引已落盘但 `complete_family` 未提交：恢复扫描复用既有字节与 `created_at`，只补证据指针 | `AssertionError: recovery rewrote the existing family index` |
| `tests/integration/test_family_archive_recovery.py::test_family_archive_recovery_records_failure_and_retries`（`postgres`） | 归档失败（如缺预算账本）时 family 保持 `AGGREGATING` 并写 `family_archive_failed` 审计；补齐后可重试收敛，不永久滞留也不静默失败 | `KeyError: 'family_archive_failed'` |
| `tests/integration/test_family_archive_recovery.py::test_campaign_only_guided_family_archives_after_no_seed_decision`（`postgres`，改8） | campaign-only guided family（`max_rounds=8`、无 round）在 `after_round_no=0` 记录 `no_next_round(NO_CANDIDATE_SEED, candidate_seed_count=0)` 后经 worker 扫描落 `COMPLETED`：`families_converged=1`、`family.json` 存在、`evidence_path`/`evidence_digest` 非空、`family_completed` 审计恰一条、返回的 `created_at` 为 RFC 3339 字符串；无决策时 `test_campaign_only_guided_family_stays_aggregating` 仍保持 `AGGREGATING` | `AttributeError: module 'datacon.state' has no attribute 'record_family_transition_decision'` |
| `tests/integration/test_family_archive_recovery.py::test_family_transition_decision_is_idempotent_and_rejects_conflict`（`postgres`，改8） | 拒绝且不写事件：非法 decision、`no_next_round` 缺子码/缺计数/计数非 0/子码不属于该决策点（含 `REPRODUCED`、`FOO`）/带 `next_round_no`，`next_round` 带子码/计数缺失或为 0/`next_round_no` 不等于 `after_round_no+1`（含 2、99、布尔、浮点），缺 `after_round_no` 或其为负/布尔，传入已删除的 `now`，另一 family 的真实 `COMPLETED` campaign、未知 campaign、非 family job 或 v1 job 作 family、campaign 未 `COMPLETED`、pending envelope；拒绝后 worker 扫描 family 仍 `AGGREGATING`。同点同参重复调用只有一条 `family_transition_decided` 且返回值一致；同点改决策或改计数/`next_round_no`/子码抛 `StateError` 且事件数不变；`next_round` 且无 round child 时 family 仍 `AGGREGATING`；family 已 `COMPLETED` 后同参重调返回首次记录、异参抛 `StateError`，均不写事件 | `TypeError: record_family_transition_decision() got an unexpected keyword argument 'after_round_no'`（改8 首版为 `AttributeError: module 'datacon.state' has no attribute 'record_family_transition_decision'`） |
| `tests/integration/test_family_archive_recovery.py::test_family_archives_after_seeds_exhausted_mid_family`（`postgres`，改8） | `next_round@0` → round 1 `INCONCLUSIVE` → `no_next_round@1(NO_REMAINING_SEEDS, 0)` → worker 收敛为 `COMPLETED`，`family.json` 的 `rounds` 含 round 1，`family_completed` 恰一条；仅有 `next_round@0` 时连续两次扫描仍 `AGGREGATING`；round 1 仍 `RUNNING` 时 `@1` 决策、`after_round_no=2`、`@1` 用 `NO_CANDIDATE_SEED` 或计数非 0、`@1` 的 `next_round_no` 不为 2 或超过 `max_rounds`、把本 family 的 round child 当 campaign，均拒绝且不写事件 | `TypeError: record_family_transition_decision() got an unexpected keyword argument 'after_round_no'` |
| `tests/integration/test_family_archive_recovery.py::test_campaign_decision_cannot_archive_a_family_with_rounds`（`postgres`，改8） | 已有 round 1 `INCONCLUSIVE`、`max_rounds=8`、预算有余时 campaign 点（`after_round_no=0`）的 `no_next_round`/`next_round` 均拒绝；`next_round_no` 超过有效 `max_rounds` 拒绝；直接写入的过期决策点 `no_next_round@0` 与缺 `after_round_no` 的旧格式事件都不被归档门禁采纳，family 仍 `AGGREGATING` | `AssertionError: a campaign-point no_next_round archived a family with rounds` |
| `tests/integration/test_family_archive_recovery.py::test_family_transition_decision_is_serialized_under_concurrency`（`postgres`，改8） | 4 个线程各用独立连接经 `threading.Barrier` 同时以同参调用：全部成功、返回值一致、只有 1 条事件；另一 family 上 `no_next_round@0` 与 `next_round@0` 各 2 个线程同时调用：恰好一种决策成功、只有 1 条事件 | `AssertionError: assert ['error', 'er...ror', 'error'] == ['ok', 'ok', 'ok', 'ok']` |
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
| `tests/contract/test_evidence_v2.py::test_v2_report_verdict_state_reason_are_bound_to_manifest` | T13a 收尾（B-1）：execution/campaign 包的 `report.verdict`/`state`/`reason_code` 出现时必须等于 manifest（campaign 为 null）；execution 的 `rule.verdict`/`rule.reason_code` 与 manifest 一致，`FAILED` 包的 `rule` 必须为 null；完整包与部分包同样适用 | `Failed: DID NOT RAISE <class 'datacon.evidence.BundleError'>` |
| `tests/contract/test_evidence_v2.py::test_v2_pre_build_failed_bundle_in_writer_shape_verifies` | T13a 收尾（B-1 防误杀）：按 `_finish_failed` 写出形态构造的构建前 `FAILED` 包（无 `build/*`、无 `replay/*`、`rule: null`、带 `missing`/`error` 与 `comparable=false` 的 `build_provenance`）仍能通过验包 | 无：防误杀正向用例，修复前（`cd24d08`、`4255df2`）与修复后均通过，不属于 RED |
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
| `tests/contract/test_safe_http.py::test_send_request_carries_the_exact_body_and_pinned_length` | 带正文的请求：`Content-Length` 按字节计算（调用方值被丢弃）、`Host` 仍钉住、正文作为独立写出逐字节上线 | `TypeError: GuardedConnection.send_request() got an unexpected keyword argument 'body'` |
| `tests/contract/test_net_adapter.py::test_outlet_transport_posts_canonical_bytes_and_parses_strictly` | `OutletHttpTransport` 经守卫连接 POST canonical JSON（与 `request_digest` 同一字节基），响应严格解析为 JSON 对象 | `ModuleNotFoundError: No module named 'datacon.tools.net_adapter'` |
| `tests/contract/test_net_adapter.py::test_outlet_transport_refuses_redirects_without_a_second_dial` | 3xx 一律 `OUTLET_REDIRECTED` 失败关闭，不跟随、不二次拨号（端点是精确白名单，重定向即漂移） | 同上 |
| `tests/contract/test_net_adapter.py::test_outlet_transport_fails_closed_on_non_success_status` | 非 2xx/3xx → `OUTLET_HTTP_STATUS` | 同上 |
| `tests/contract/test_net_adapter.py::test_outlet_transport_fails_closed_on_unframed_or_oversized_bodies` | 无单一 `Content-Length` → `RESPONSE_UNFRAMED`；声明超上限 → `OUTLET_RESPONSE_TOO_LARGE` 且正文流不启动 | 同上 |
| `tests/contract/test_net_adapter.py::test_outlet_transport_surfaces_truncated_and_non_json_bodies` | 截断传播 `CONTENT_TRUNCATED`；非严格 JSON 或非对象 → `OUTLET_BAD_JSON` | 同上 |

T14 实现新增坐标（P3）。下列 38 条不在原计划表内，是实现与自审过程中补上的，与上表同属 T14 验收。标注「自审加固」的坐标来自对 T14 三个模块的逐行自审：先用探针复现缺陷，再写成 RED，修复后转绿。原计划坐标 `test_model_finding_must_be_hypothesis` 已归位到上表登记的 `test_model_outlet.py`。带「†」的失败信息是 P3 用探针对当时的实现直接观察到的行为，不是 pytest 的输出行。

- **两处规范的解释**（已定，写在实现里）：
  - security-design-delta §2.5「脱敏规则命中禁止字段 → 阻止发送」：按「先遮蔽，再对整个请求体扫一遍，仍有密钥类内容才阻止发送并记录原因」执行（`REDACTION_REJECTED`）。可遮蔽的形态遮蔽后照发；只有遮蔽覆盖不到的位置（例如字典的键名）残留密钥时才阻断。
  - §2.3「任何自由文本命令、shell 片段……视为非法输出并阻断」：T14 **不按文本特征阻断**。封闭的 `AgentOutput` 结构里没有命令或工具调用的落点；命令注入类缺陷的假设本身就会含 shell 文本，按文本阻断会误伤。此点已获 Sasuke0723 在 #48 评审中确认（同意以结构封闭为门禁边界）。
- **签名规则与信封一致**：`experiment_spec.validate_signature` 对值与类型的规则跟 `state._envelope_signature_set` 相同（`operation` 为 `READ` 或 `WRITE`，`access_size` 为 1 到 2^31-1），由 `test_signature_rules_agree_with_the_envelope_validator` 防漂移；文本字段另加两条更严的规则（无控制字符、不超过 200 字符）。
- **标注集版本格式**：`b04-annotations-v1`、一个加号、`sha256:` 加 samples 的规范化摘要（`b04_eval.annotation_set_version`），加载时核对摘要。评审修正（#48，Sasuke0723 指出）：实现与本登记曾误写为冒号，ADR-003 第 12 条与 `tasks.md` 冻结的是 `<label>+<digest>`。
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
| `tests/contract/test_b04_hypothesis_quality.py::test_annotation_version_requires_the_canonical_separator`（自审加固） | 版本串只认 `b04-annotations-v1+sha256:…` 一种写法；评审修正后冒号也是被拒的分隔符 | ※ `Failed: DID NOT RAISE B04GateError` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_requires_at_least_one_evidence_ref`（评审加固） | `evidence_refs` 空列表 → `ExperimentSpecError`（非空要求，与 finding 层 `agent_contracts` 一致） | ※ `Failed: DID NOT RAISE ExperimentSpecError` |
| `tests/contract/test_experiment_spec.py::test_experiment_spec_checks_log_reference_grammar`（评审加固） | `log/build:`/`log/fuzz:` 引用按 §11 冻结语法（`contracts.parse_log_evidence_ref`）校验：降序区间、非法 selector、fuzz 带区间被拒，v0.1 形式照常通过 | ※ `Failed: DID NOT RAISE ExperimentSpecError` |
| `tests/contract/test_b04_hypothesis_quality.py::test_a_hit_requires_the_same_case`（评审加固） | 命中要求 `case_id` 一致：同一上游文件被其他 case 复用时不得交叉命中 | ※ `assert 1.0 == 0` |
| `tests/contract/test_model_outlet.py::test_model_audit_document_validates_offline_and_binds_to_the_report`（R2 预备） | 归档的 `model/audit.json` 离线校验为封闭 11 字段，与写出时等价（含 JSON 往返与在线记录）；审计的 `job_id` 必须是所在包的 child job，`report.model_audit` 必须恰为它的 6 字段摘要 | ※ `ImportError: cannot import name 'model_audit_summary' from 'datacon.tools.model_outlet'` |
| `tests/contract/test_model_outlet.py::test_model_audit_document_rejects_shape_and_digest_faults`（R2 预备） | 缺字段、多字段、非对象、`allowed_fields_digest` 不是摘要、离线记录声称版本/摘要/耗时、`job_id` 不是 UUID、`outcome` 越界一律 `AUDIT_INVALID`；`provider` 为空沿用既有的 `PROVIDER_MISSING` | ※ `ImportError: cannot import name 'validate_model_audit_document' from 'datacon.tools.model_outlet'` |

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

T15 实现新增坐标（P3）。下列坐标不在原计划表内，是实现与自审过程中为钉住边界补上的，与上表同属 T15 验收。标注「自审加固」的坐标来自对 #44 与快照 provider 的逐行自审：每条都先用探针复现缺陷，再写成 RED，修复后转绿。

- **归类**沿用 v0.1：固定快照的内容摘要与登记值不符属材料无法校验，归 `MATERIAL_MISSING`；来源登记给了别的案例才属事实矛盾，归 `SOURCE_CONFLICT`。
- **尚未由坐标验证的两点**（要求不变，留待后续）：连接 10s / 读取 30s 超时的施加属于传输适配层，当前坐标以替身抛出的超时验证传播与 60 秒总预算；`test_external_text_does_not_change_routing_or_tools` 现钉住的是 `as_data` 的转义属性，路由与工具授权不读取外部文本这一点由编排图按目标类型路由保证，其断言留到集成阶段。

| 测试坐标 | 断言点 | 首次运行的预期失败信息 |
| --- | --- | --- |
| `tests/contract/test_safe_http.py::test_dns_answers_are_validated_before_any_socket_opens` | 解析结果含私网、回环、元数据、IPv4-mapped、CGNAT 任一即拒；空解析失败关闭；都发生在创建 socket 之前 | `ModuleNotFoundError: No module named 'datacon.tools.safe_http'` |
| `tests/contract/test_safe_http.py::test_rebind_to_metadata_ip_is_aborted_before_http_bytes` | 对端 `getpeername()` 为元数据地址时，在发送任何 HTTP 字节前中止 | 同上 |
| `tests/contract/test_safe_http.py::test_connection_pins_sni_and_host_to_the_hostname` | 直连已校验 IP；TLS SNI 与 HTTP `Host` 钉住原域名，调用方伪造的 `Host` 被覆盖 | 同上 |
| `tests/contract/test_safe_http.py::test_peer_must_match_a_validated_address` | 对端地址必须属于已校验地址集合，公网但未校验同样拒绝 | 同上 |
| `tests/contract/test_safe_http.py::test_each_hop_opens_a_new_validated_connection` | 每跳新建连接，各自解析并校验 | 同上 |
| `tests/contract/test_safe_http.py::test_environment_proxies_are_not_honored` | 设置 `http_proxy` 等环境变量后仍直连已校验 IP | 同上 |
| `tests/contract/test_safe_http.py::test_response_head_is_capped`（自审加固） | 响应头超过 64 KiB 即拒绝，空行未到也拒绝 | `AttributeError: module 'datacon.tools.safe_http' has no attribute 'MAX_RESPONSE_HEAD_BYTES'` |
| `tests/contract/test_safe_http.py::test_duplicate_or_conflicting_content_length_is_rejected`（自审加固） | 取值不一致的重复 `Content-Length` 被拒 | `Failed: DID NOT RAISE SafeHttpError` |
| `tests/contract/test_safe_http.py::test_body_stream_reports_truncation_at_eof`（自审加固） | 正文未传满声明长度就 EOF 时报 `CONTENT_TRUNCATED` | `Failed: DID NOT RAISE SafeHttpError` |
| `tests/contract/test_safe_http.py::test_missing_content_length_leaves_body_unframed_and_empty`（自审加固） | 无 `Content-Length` 的响应不产出任何正文字节 | `AttributeError: 'GuardedResponse' object has no attribute 'content_length'` |
| `tests/contract/test_safe_http.py::test_safe_http_errors_carry_a_reason_code`（自审加固） | 连接层错误携带稳定原因码，拒绝集与非字面量 IP 为 `ADDRESS_DENIED` | `AttributeError: 'SafeHttpError' object has no attribute 'reason'` |
| `tests/contract/test_guarded_transport.py::test_guarded_transport_serves_fetch_intel_end_to_end` | 经真实 safe_http 流完成一次抓取 | `ImportError: cannot import name 'GuardedTransport'` |
| `tests/contract/test_guarded_transport.py::test_guarded_transport_propagates_redirect_location_per_hop` | 每跳新 socket，重定向目标逐跳传递 | 同上 |
| `tests/contract/test_guarded_transport.py::test_guarded_transport_enforces_redirect_limit_through_safe_http` | 第 6 次重定向被拒，第 7 跳从未触达解析器 | 同上 |
| `tests/contract/test_guarded_transport.py::test_guarded_transport_streams_gzip_body_for_budget_counting` | gzip 正文边流边解压并受预算约束 | 同上 |
| `tests/contract/test_guarded_transport.py::test_guarded_transport_elapsed_comes_from_injected_clock` | 耗时取注入时钟的差值，而非绝对值 | 同上 |
| `tests/contract/test_guarded_transport.py::test_guarded_transport_never_leaks_sockets_on_success` | 成功路径上每个连接恰好关闭一次 | 同上 |
| `tests/contract/test_guarded_transport.py::test_guarded_transport_surfaces_safe_http_failures_as_intel_errors`（自审加固） | 连接层失败统一为 `IntelFetchError` 并带原因码，连接零泄漏 | `Failed: DID NOT RAISE IntelFetchError` |
| `tests/contract/test_guarded_transport.py::test_guarded_elapsed_includes_body_streaming`（自审加固） | 正文传输的耗时计入 60 秒总预算 | `Failed: DID NOT RAISE IntelFetchError` |
| `tests/contract/test_intel_fetch.py::test_fetch_rejects_truncated_body`（自审加固） | 线上字节少于声明为 `CONTENT_TRUNCATED`，多于声明为 `RESPONSE_UNFRAMED` | `Failed: DID NOT RAISE IntelFetchError` |
| `tests/contract/test_intel_fetch.py::test_fetch_rejects_response_without_content_length`（自审加固） | 缺 `Content-Length` 或其值非整数为 `RESPONSE_UNFRAMED` | 同上 |
| `tests/contract/test_intel_fetch.py::test_fetch_rejects_non_2xx_status`（自审加固） | 最终状态不在 200–299 为 `HTTP_STATUS_REJECTED`，正文不读 | 同上 |
| `tests/contract/test_intel_fetch.py::test_fetch_rejects_empty_content`（自审加固） | 解码后为空的正文为 `EMPTY_CONTENT` | 同上 |
| `tests/contract/test_intel_fetch.py::test_fetch_rejects_truncated_or_trailing_gzip`（自审加固） | 不完整的 gzip 为 `CONTENT_TRUNCATED`，成员之后带剩余字节为 `RESPONSE_UNFRAMED` | 同上 |
| `tests/contract/test_intel_fetch.py::test_fetch_rejects_corrupt_gzip`（自审加固） | 校验和损坏或并非 gzip 的内容为 `RESPONSE_UNFRAMED`，不得漏出 `zlib.error` | `zlib.error: Error -3 while decompressing data: incorrect data check` |
| `tests/contract/test_intel_fetch.py::test_total_budget_covers_body_streaming`（自审加固） | 正文流式传输的耗时计入总预算 | `Failed: DID NOT RAISE IntelFetchError` |
| `tests/contract/test_intel_fetch.py::test_decompression_output_is_capped_per_inflate_step`（自审加固） | 单次解压的产出不超过 32 MiB + 1 字节 | `AssertionError: assert inf <= (33554432 + 1)` |
| `tests/contract/test_intel_fetch.py::test_license_rejects_non_sequence_permitted_uses`（自审加固） | `permitted_uses` 是字符串时拒绝，防子串误命中 | `Failed: DID NOT RAISE IntelFetchError` |
| `tests/contract/test_intel_fetch.py::test_snapshot_records_source_url_without_credentials`（自审加固） | 快照记录的来源 URL 不含账号口令 | `AssertionError: assert 'https://admi...0001.txt' == 'https://advi...0001.txt'` |
| `tests/contract/test_intel_fetch.py::test_intel_node_ready_snapshot_reaches_version` | 已核验且许可通过的快照经边 #5 到达 `version`，摘要只含快照摘要、许可与来源 | `ModuleNotFoundError: No module named 'datacon.tools.intel_provider'` |
| `tests/contract/test_intel_fetch.py::test_intel_node_rejects_unlicensed_or_unregistered_source` | 缺许可或用途不含复现为 `POLICY_DENIED`；案例无已登记来源时不读快照 | 同上 |
| `tests/contract/test_intel_fetch.py::test_snapshot_provider_maps_failures_to_reason_codes` | 读不到、读取出错、摘要不符、登记摘要格式非法、登记给别的案例各归其原因码与细因；provider 不抛异常 | 同上 |
| `tests/contract/test_intel_fetch.py::test_snapshot_provider_reads_pinned_snapshots_without_network` | 离线案例只读固定快照，不触达抓取、连接层或 socket | 同上 |
| `tests/contract/test_intel_fetch.py::test_snapshot_provider_summary_never_carries_url_credentials`（自审加固） | 就绪摘要里的来源 URL 不含账号口令；URL 缺失或无法解析为 `POLICY_DENIED` | `AssertionError: assert 'https://admi...0001.txt' == 'https://advi...0001.txt'` |
| `tests/contract/test_intel_fetch.py::test_snapshot_provider_source_url_must_name_an_https_origin`（评审加固） | 来源 URL 必须是 https 源:裸词、他 scheme、`javascript:`、无主机、端口不可解析、空白与控制字符都 `SOURCE_URL_INVALID`,且在打开快照前拒绝 | `AssertionError: not-a-url` |
| `tests/contract/test_intel_fetch.py::test_snapshot_provider_rejects_bytes_uses_as_a_license_denial`（评审加固） | `permitted_uses` 为 bytes/bytearray → `POLICY_DENIED`/`LICENSE_REJECTED`(只认 list/tuple/set/frozenset,与 intel_fetch 注册表门对齐),不再误归类为材料不可读 | `assert 'MATERIAL_MISSING' == 'POLICY_DENIED'` |
| `tests/contract/test_intel_fetch.py::test_snapshot_provider_fails_closed_when_a_later_source_is_refused`（评审加固） | 多来源 fail-closed:第二个来源无许可整案阻断并点名来源;全通过时就绪摘要是第一个来源的 | ※ 未触发 RED(既有行为,评审建议加钉) |
| `tests/contract/test_snapshot_store.py::test_snapshot_store_persists_body_and_record_content_addressed` | 七字段封闭记录按 canonical JSON 落盘,正文按 `by-digest/<xx>/<hex>` 内容寻址,返回相对路径与摘要 | `ModuleNotFoundError: No module named 'datacon.tools.snapshot_store'` |
| `tests/contract/test_snapshot_store.py::test_snapshot_store_is_write_once_and_idempotent` | 写后只读:同记录同正文幂等;同正文新记录(新 fetched_at)追加记录文件、正文不动 | 同上 |
| `tests/contract/test_snapshot_store.py::test_snapshot_store_refuses_a_corrupted_body_at_the_digest_path` | 内容寻址路径上既有字节与待存不符(损坏)→ 失败关闭,不覆盖 | 同上 |
| `tests/contract/test_snapshot_store.py::test_snapshot_store_validates_the_closed_record_shape` | 记录键集封闭(缺/多拒),`content_digest` 必须诚实描述正文 | 同上 |
| `tests/contract/test_snapshot_store.py::test_snapshot_files_are_read_only` | 快照与记录文件无写位 | 同上 |
| `tests/contract/test_snapshot_store.py::test_snapshot_loader_reads_pinned_snapshots` | 生产 loader 按登记相对路径读;缺失→None;绝对/穿越/反斜杠路径→None(不越根) | 同上 |
| `tests/contract/test_snapshot_store.py::test_snapshot_store_composes_with_the_snapshot_provider` | 存储写入→登记→`SnapshotIntelProvider`+生产 loader 离线闭环 ready;磁盘篡改→`DIGEST_MISMATCH` | 同上 |
| `tests/contract/test_net_adapter.py::test_production_resolver_dedups_answers_preserving_order` | 生产 DNS 解析器答案去重且保序 | `ModuleNotFoundError: No module named 'datacon.tools.net_adapter'` |
| `tests/contract/test_net_adapter.py::test_production_resolver_fails_closed_when_the_dns_budget_expires` | DNS 预算到期 → `DNS_TIMEOUT`，等待由预算而非查找本身结束 | 同上 |
| `tests/contract/test_net_adapter.py::test_production_resolver_reports_unresolvable_hosts_fail_closed` | 名字不可解析 → `DNS_FAILED` | 同上 |
| `tests/contract/test_net_adapter.py::test_default_tls_context_never_disables_verification` | 默认 TLS 上下文 `check_hostname` 开且 `CERT_REQUIRED`，无任何关闭校验的调用形状 | 同上 |
| `tests/contract/test_net_adapter.py::test_production_socket_pins_sni_and_applies_the_read_timeout` | TLS 挂载钉 SNI 主机名，挂载后施加读取预算 | 同上 |
| `tests/contract/test_net_adapter.py::test_production_socket_refuses_to_mount_tls_without_sni` | 缺 SNI 拒绝挂载 | 同上 |
| `tests/contract/test_net_adapter.py::test_production_socket_applies_the_connect_budget_before_dialing` | 连接预算在拨号前作为 socket 超时施加（真实本地 listener 实测） | 同上 |
| `tests/contract/test_net_adapter.py::test_production_socket_recv_enforces_the_read_timeout` | 真实停摆对端上 `recv` 受读取预算约束（本地哑服务实测超时） | 同上 |
| `tests/contract/test_net_adapter.py::test_production_socket_factory_defaults_match_the_fetch_budgets` | 工厂默认预算与 `intel_fetch` 逐跳预算同源，防配置漂移 | 同上 |
| `tests/contract/test_net_adapter.py::test_production_guarded_transport_wires_the_production_faces` | `production_guarded_transport` 装配生产解析器与生产插座工厂 | 同上 |
| `tests/contract/test_intel_evidence.py::test_snapshot_document_carries_the_record_and_the_exact_bytes`（R2 预备，形状待认可） | 快照文档 = 注册身份 + 采集记录 + 原字节（base64）；正文非 UTF-8 也逐字节保真，`snapshot_digest` 对这些字节求值；JSON 往返后校验等价 | `ModuleNotFoundError: No module named 'datacon.tools.intel_evidence'` |
| `tests/contract/test_intel_evidence.py::test_snapshot_document_without_a_collection_record_keeps_the_gap_visible`（R2 预备，形状待认可） | 无采集记录的固定快照：身份仍取自注册，四个采集字段保持 null，不编造 | 同上 |
| `tests/contract/test_intel_evidence.py::test_snapshot_document_builder_fails_closed_on_a_dishonest_record`（R2 预备，形状待认可） | 记录与注册互相矛盾时失败关闭：摘要描述了别的字节 → `DIGEST_MISMATCH`；来源 URL / 许可不一致 → `SOURCE_CONFLICT`；记录不是封闭七字段、注册身份不可记录 → 各自细因 | 同上 |
| `tests/contract/test_intel_evidence.py::test_snapshot_document_builder_refuses_an_unattributable_source`（R2 预备，形状待认可） | 来源 URL 无法归因（空、裸词、非 https、`javascript:`、端口不可解析、含空白）→ `POLICY_DENIED`/`SOURCE_URL_INVALID`，与 provider 同一规则 | 同上 |
| `tests/contract/test_intel_evidence.py::test_intel_documents_strip_url_credentials`（R2 预备，形状待认可） | 带凭据的注册 URL 被接受：两份文档与记录都以去掉凭据的 URL 落档，任何写出的内容都不含凭据 | 同上 |
| `tests/contract/test_intel_evidence.py::test_snapshot_document_validation_fails_closed`（R2 预备，形状待认可） | 归档快照文档的失败关闭：键集封闭、身份文本、采集事实三者同有同无、`http_status` 取整且在 100–599、时间戳 RFC 3339 并归一为 UTC、base64 规范拼写与尺寸上限；URL 问题归 `POLICY_DENIED` | 同上 |
| `tests/contract/test_intel_evidence.py::test_snapshot_body_refuses_to_decode_an_unverified_document`（R2 预备，形状待认可） | 字节只对校验通过的文档交出：摘要不符的文档读不出正文 | 同上 |
| `tests/contract/test_intel_evidence.py::test_license_document_records_the_grant_and_its_verdict`（R2 预备，形状待认可） | 许可文档记录授予；`license_verdict` 仅凭文档离线重推许可判定（无许可、未授予系统用途、什么都没授予均拒绝），且只对合规文档给出判定 | 同上 |
| `tests/contract/test_intel_evidence.py::test_license_document_builder_fails_closed_on_a_malformed_grant`（R2 预备，形状待认可） | 授予不是互异用途名的序列（裸字符串、bytes、重复、空名、非文本）→ 不写许可文档（`LICENSE_DOCUMENT_INVALID`） | 同上 |
| `tests/contract/test_intel_evidence.py::test_license_document_validation_fails_closed`（R2 预备，形状待认可） | 归档许可文档的失败关闭：键集封闭、用途必须是数组且互异、身份与摘要合法；什么都没授予仍是合规记录 | 同上 |
| `tests/contract/test_intel_evidence.py::test_intel_documents_bind_to_each_other_and_to_the_report`（R2 预备，形状待认可） | 两份文档互相一致、与 `report.intel` 三字段摘要一致；给出 `plan.intel` 时与 `content_digest`、`collected_at` 一致（等价时区写法视为相同） | 同上 |
| `tests/contract/test_intel_evidence.py::test_intel_documents_refuse_every_binding_mismatch`（R2 预备，形状待认可） | 任何一处失配均拒绝（`INTEL_BINDING_MISMATCH`）：两份文档的身份/摘要/许可、`report.intel` 的封闭三字段与取值、`plan.intel` 的 `content_digest`/`collected_at`/`sources` | 同上 |
| `tests/contract/test_intel_evidence.py::test_intel_documents_refuse_a_license_that_does_not_permit_the_use`（R2 预备，形状待认可） | 归档的许可授予不覆盖系统用途（或根本没有许可）→ `POLICY_DENIED`/`LICENSE_REJECTED`：证据包不能声称材料是被允许的 | 同上 |
| `tests/contract/test_intel_evidence.py::test_intel_documents_survive_the_archive_round_trip`（R2 预备，形状待认可） | 文档与两份摘要经 JSON 落盘再读回后，校验结论不变 | 同上 |
| `tests/contract/test_intel_evidence.py::test_intel_documents_anchor_the_case`（评审加固） | 两份文档互相一致不足够:`case_id` 必须与所在包一致,换一个 case 的材料被拒(`SOURCE_CONFLICT`/`SOURCE_CASE_MISMATCH`);`source_id` 无离线锚点,docstring 注明仅供展示 | ※ `TypeError: verify_intel_documents() got an unexpected keyword argument 'case_id'` |
| `tests/contract/test_intel_evidence.py::test_intel_documents_require_their_anchors`（评审加固） | `case_id`/`plan_intel`/`job_id` 均为必填:调用方忘了传必须响亮失败,不静默少一道检查;blocked 包不调用 | ※ `Failed: DID NOT RAISE TypeError` |
| `tests/contract/test_intel_evidence.py::test_plan_intel_follows_the_frozen_shape`（评审加固） | `plan.intel` 复用 `contracts._intel` 的封闭规则:四字段、`sources` 非空且全 https、快照路径安全、无未知键 | ※ `Failed: DID NOT RAISE IntelEvidenceError` |
| `tests/contract/test_intel_evidence.py::test_plan_sources_must_include_the_snapshot_source_url`（评审加固） | `plan.intel.sources`(本次分析采信的来源)必须包含快照的 `source_url`,两侧去凭据后比较(带凭据拼写可匹配) | ※ `Failed: DID NOT RAISE IntelEvidenceError` |
| `tests/contract/test_intel_evidence.py::test_snapshot_redirect_requires_a_collection`（评审加固） | 没有采集记录时 `redirect_chain_digest` 必须为 null(四者同组的例外写清为不变量) | ※ `Failed: DID NOT RAISE IntelEvidenceError` |
| `tests/contract/test_intel_evidence.py::test_license_document_builder_accepts_sets`（评审加固） | 构造器接受 tuple/set/frozenset 形式的授予(与 provider 的 `IntelSource` 对齐),归档为确定性排序的数组 | ※ `IntelEvidenceError: permitted_uses must be a JSON array of use names` |
| `tests/contract/test_intel_evidence.py::test_intel_evidence_imports_without_the_execution_graph`（R2 预备） | 该模块被导入时不牵入 orchestration、intel_provider、execution、evidence、model_outlet（`evidence.py` 可安全导入它做验包） | ※ `subprocess.CalledProcessError`（子进程内为 `ModuleNotFoundError`） |

**T14/T15 证据文档（R2 预备；两个情报文档的形状待规范 owner 认可）**：§8 已为 `model/audit.json` 定了完整的 11 字段 schema，本 PR 补它的离线校验器，以及它与所在包 `job_id`、`report.model_audit` 6 字段摘要的绑定。`intel/snapshot.json` 与 `intel/license.json` 在 §8 只有路径与角色、没有内容 schema，本 PR 按下列形状实现并提请认可：快照文档 = 注册身份（`case_id`、`source_id`、`snapshot_digest`、`source_url`、`license`）+ 采集事实（`fetched_at`、`http_status`、`tool_version` 三者同有同无，`redirect_chain_digest` 可为 null）+ `body_base64`（正文原字节的规范 base64：快照是来源给出的任意字节，`snapshot_digest` 必须恰好对这些字节求值）；许可文档 = 同一注册身份 + `permitted_uses`。`verify_intel_documents` 把两份文档互相绑定，并绑定到 `report.intel`（封闭三字段）与 `plan.intel`（`content_digest`、`collected_at`），再由归档的许可授予离线重推许可判定（不覆盖系统用途 → `POLICY_DENIED`/`LICENSE_REJECTED`）。来源 URL 的规则与许可判定的规则下沉到 `intel_fetch`（`public_source_url`、`license_rejection`），provider 与证据校验器用同一份。尚待确认的三点：①正文以 base64 封装（字节精确，体积约 +33%）还是另存原始字节文件；②`plan.intel.sources` 是否要求包含快照的 `source_url`；③四个细因记号 `INTEL_REGISTRATION_INVALID`、`INTEL_BINDING_MISMATCH`、`SNAPSHOT_DOCUMENT_INVALID`、`LICENSE_DOCUMENT_INVALID`。三个角色翻成 v2 必需角色（R2 本体）不在本 PR：`evidence.py` 的必需集与 `execution.py` 的写包器分别归 P1、P2。
**传输适配层（T14/T15 共用，本 PR 落地）**：生产侧适配器 `datacon.tools.net_adapter` 补上 #44/#48 冻结的两个注入面的生产实现——`ProductionResolver`（真实 getaddrinfo，5s DNS 预算，超时 `DNS_TIMEOUT`、不可解析 `DNS_FAILED` 均失败关闭）与 `ProductionSocketFactory`（连接预算在拨号前作为 socket 超时施加、TLS 挂载强制 SNI 且只经 `ssl.create_default_context()`，无关闭校验的调用形状）；`OutletHttpTransport` 经 `connect_guarded` 以 canonical JSON 为字节基 POST 模型请求，不跟随重定向（`OUTLET_REDIRECTED`），响应须有单一 `Content-Length`、在 32 MiB 上限内、严格解析为 JSON 对象。预算口径说明：`SocketFactory` 面无逐调用参数，生产装配（`production_guarded_transport`）与 fetch 循环逐跳预算同源于 `intel_fetch` 的常量，由 `test_production_socket_factory_defaults_match_the_fetch_budgets` 防漂移。适配层尚未接任何调用方（workflow/execution 接入另立任务）。

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
