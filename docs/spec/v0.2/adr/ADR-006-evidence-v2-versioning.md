# ADR-006 证据 v2 版本分派

**Status** Accepted  
**Date** 2026-11-21

## Context

v0.1 证据包以 `manifest.schema_version=1` 固定结构，离线校验器按该结构读取 plan、report 与文件角色。v0.2 需要新增 family、轮次、信封、`build_ref`、admission、预算、campaign 与复用指针。直接升级校验器会让既有 v1 证据无法读取；把 v1 证据在线迁移成 v2 又会改写已封存内容，破坏“证据不可变”与旧任务的可追溯性。

同时，v2 validation 包需要复用 campaign 的构建制品，但必须能脱离 campaign 独立校验；campaign 本身不产 verdict，却要供 family 审计。两者不能混成一个包。

版本分派还影响审计工具：v1 包中的引用语法、文件角色与判定字段都按旧规则解释，v2 包允许新角色与新引用。若校验器先按 v2 读取 v1 包，再“回退”到 v1，缺失字段与未知字段的区分会失效，旧包可能被误判为损坏或被悄悄补字段。因此版本判断必须先于任何结构解析。

回滚后还存在跨代读取问题：v1 控制面不认识 v2 的 plan/evidence 字段。规范必须写死“v1 只读 v1 时代数据”，并为 v2 终态证据保留一个只读的 v2 verifier/export，而不是让 v1 代码临时学会解析 v2。

## Decision

1. **双版本常量**。保留 `SCHEMA_VERSION_V1 = 1`，新增 v2 生产常量 `SCHEMA_VERSION_V2 = 2`。v1 常量与旧结构不删除、不改名。
2. **先读版本再分派**。`verify_bundle` 先读取 `manifest.schema_version`，再选择 v1 冻结分支或 v2 分支；不得先按 v2 解析再回退 v1。未知版本直接失败关闭。
3. **v1 冻结分支**。v1 分支复制旧 `_extract_compile_args` 的实现，不调用新实现、不引用新 plan 字段、不解释 v2 文件角色。v1 校验器的行为与 T09 前保持一致；它继续要求构建 `staged_materials` 包含 `inputs/normal.txt` 与 `inputs/candidate.txt`。v2 校验器不要求这两个别名，并拒绝把它们写入 v2 构建记录。
4. **v1 只读兼容**。既有 v1 job/plan 可以 export、可以 verify、不可 re-run，不做在线回填。v1 证据包不被改写；family 导出只读取并复制单轮包，不重新生成 manifest。
5. **v1 读取边界**。v1 控制面只承诺读取 v1 时代数据；回滚后 v2 终态证据由保留的 v2 只读 verifier/export 服务读取。不在 v1 代码中增加 v2 plan/evidence 解析，也不把 v2 字段塞进 v1 分支的“兼容字段”。
6. **v2 bundle kinds**。v2 `bundle_kind` 支持 `execution`、`blocked` 与 `campaign`。campaign 包记录双版本构建与 fuzz 搜索观测，`verdict` 与 `reason_code` 为 null，`build_ref` 与 `reuse_origin` 为 null；fixed 普通 execution 仍是 `execution`，`envelope_digest` 非空，但 `build_ref` 与 `reuse_origin` 为 null；只有复用 campaign 的 validation execution 才要求 `build_ref` 与 `reuse_origin` 非空。campaign child 归档后经 `finish_execution` 落 `state=COMPLETED`，family 运行中 `AGGREGATING`、归档落盘 `family.json` 后经无执行租约的 `complete_family` 落 `COMPLETED`；`COMPLETED` 是 v2 终态（`verdict`/`reason_code` 为 null、`evidence_status='archived'`），不写入证据 `verdict`，`INCONCLUSIVE` 继续只表示复现判定未成结论。（D43 补充）`family.json`（`kind="family_index"`）独立于 `bundle_kind`，不新增 `bundle_kind=family` 或 `family_index` 角色；family 的 `jobs.evidence_path` 指向它、`evidence_digest` 为其 SHA-256、`evidence_status='archived'`，满足 007 `jobs_archived_evidence_check`；T10 落地两条收敛接口与 007 兼容，`family.json` 落盘、`status` 展示与 `export --family` 字节一致归 T12。
7. **validation 自包含**。validation 包嵌入两版构建记录、构建日志、核对面原文（`build_provenance`）、信封（`envelope`）与预算快照（`budget_snapshot`），并带 `reuse_origin` 指针（来源 job、generation、campaign bundle digest，以及两版 artifact digest 与 build log digest）。包内沿用 v1 固定路径：`metadata/execution.json`、`metadata/probe.json`、`metadata/case.json`、`build/{version}/metadata.json`、`build/{version}/build.log`、`build/{version}/parser` 与 `replay/{version}/{phase}/{stdout.log,stderr.log,metadata.json}`；不得改写成 `build_metadata.json`、`output.txt` 等变体。`reuse_origin.artifacts` 必须与 plan `build_ref.artifacts` 逐字段相等；不一致返回 `REUSE_MISMATCH`。即使 campaign 目录不可用，validation 包仍能独立校验构建来源、准入与六次回放。

固定路径（与实现一致，不得改名）：

| 逻辑内容 | 角色 | 路径 |
| --- | --- | --- |
| 执行元数据 / 探针 / 案例 | `execution_metadata` / `probe` / `case_config` | `metadata/execution.json`、`metadata/probe.json`、`metadata/case.json` |
| 构建 | `build_log` / `build_metadata` / `build_artifact` / `build_provenance` | `build/{version}/build.log`、`build/{version}/metadata.json`、`build/{version}/parser`（默认单产物名）、`build/{version}/build_provenance/{compile_commands.json,cc-shim.log,shell-face.log}` |
| 回放（六组） | `replay_stdout`/`normal_output`、`replay_stderr`/`normal_error`/`asan_log`、`replay_metadata` | `replay/{version}/{phase}/{stdout.log,stderr.log,metadata.json}` |
| 计划 / 人批 / 准入 | `plan` / `review` / `admission` | `plan.json`、`review.json`、`admission.json` |
| 信封 / 预算 | `envelope` / `budget_snapshot` / `budget_ledger` / `budget_charge` | `envelope.json`、`budget/{snapshot,ledger,charges}.json` |
| 实验 / 模型 / 情报 | `experiment_spec` / `model_audit` / `intel_snapshot` / `license_record` | `experiments/*.json`、`model/audit.json`、`intel/{snapshot,license}.json` |

8. **campaign 单独归档**。campaign bundle 进入 family 归档的独立目录，供 family 审计、预算对账与复用来源核验；它不要求 verdict，也不替代 validation 包。family 导出不得把 campaign 的观测拼进某轮 report。
9. **family 导出**。`export --family` 聚合导出 `family.json`、`campaign/` 与 `rounds/<round_no>/`；每个轮次目录仍是独立 bundle，manifest 与摘要不变。聚合层只做索引与复制，不做重新签名或重新计算。（D43 补充）根 `family.json` 与 family 归档件字节一致；它按 family index schema 单独校验，不是 v2 evidence bundle，不参与 `verify_bundle` 的 execution/blocked/campaign 分派，也不重写单轮 manifest。落盘、`status` 展示与根 `family.json` 字节一致归 T12；T10 只保证它不被当作 `bundle_kind`。
10. **新引用语法**。v2 支持 `log/build:<version>#Lx-y` 与 `log/fuzz:<round>#Lx`，引用前校验日志摘要与行号范围；v1 校验器不解释新语法，避免旧包被新语义误读。
11. **新建而非原地升级**。v2 包从新任务产生；不把 v1 包转换为 v2，也不在 v1 job 上追加 v2 证据。需要 v2 证据的案例必须新建 v2 任务。
12. **完整角色表**。v2 角色表 = v0.1 完整角色集 + v0.2 新增角色集，不是只写“继承 v1”。v0.1 的 27 个角色全部保留：`report_json`、`report_markdown`、`plan`、`review`、`execution_metadata`、`probe`、`build_log`、`build_metadata`、`build_artifact`、`normal_output`、`normal_error`、`asan_log`、`replay_stdout`、`replay_stderr`、`replay_metadata`、`material_harness`、`material_build_recipe`、`material_dependencies`、`material_input_normal`、`material_input_candidate`、`material_source_vulnerable`、`material_source_fixed`、`material_patch`、`material_repository_bundle`、`material_advisory`、`case_config`、`symbolizer_log`。v0.2 新增 13 个：`envelope`、`budget_snapshot`、`build_provenance`、`admission`、`budget_ledger`、`budget_charge`、`experiment_spec`、`model_audit`、`fuzz_log`、`crash_seed`、`fuzz_provenance`、`intel_snapshot`、`license_record`。
13. **必需角色**（完整定义与分阶段生效以[接口契约增量](../interface-contract-delta.md)第 8 节为准）。v2 `execution` 必需：`report_json`、`report_markdown`、`plan`、`envelope`、`budget_snapshot`、`execution_metadata`、`probe`、`case_config`、六组回放的 18 个 `stdout.log`/`stderr.log`/`metadata.json` 与两版 `build_metadata`/`build_log`/`build_artifact`/`build_provenance`，并恰好包含 `review`（人批轮次）或 `admission`（policy 轮次）之一；v2 `campaign` 独立必需：`report_json`、`report_markdown`、`plan`、`review`（family 人批决议副本）、`execution_metadata`、`probe`、`case_config`、`envelope`、`budget_snapshot`、两版 `build_metadata`/`build_log`/`build_artifact`/`build_provenance`、`fuzz_log`、`fuzz_provenance`，并在记录 ≥1 条候选 crash seed 时必需 `crash_seed`（0 crash 允许缺失），**不含 18 个回放文件**；`blocked` 只需 `report_json` 与 `report_markdown`。files 列表不得只放 report 与单个 `build.log`。
14. **条件校验与 blocked 豁免**。`blocked` 不要求 `family_id`、`parent_job_id`、`round_no`、`envelope_digest`、`plan_digest`、`experiment_digest`、`build_provenance_rules_version`、`build_ref`、`reuse_origin`；但仍要求 report、`verdict=BLOCKED`、属于 `BLOCKED` 集合的 `reason_code` 与 `created_at`。`execution` 且 `reuse_origin=null` 时 `build_ref`/`reuse_origin` 必须为 null；`execution` 且 `reuse_origin!=null` 时两者必填；`campaign` 两者必须为 null。缺少条件必填字段、出现不允许字段、campaign 出现 verdict，或 family 导出的单轮摘要与源包不一致时失败关闭。
15. **预留角色与分阶段生效**。`intel_snapshot`、`license_record` 与 `model_audit` 由 T10 定义角色枚举；T15/T14 只填充这些角色并定义各自快照 schema，不修改已有 v1/v2 结构。分阶段生效：T13 落地后 `build_provenance` 成为 `execution`/`campaign` 必需角色；T14 落地后 `model_audit` 成为 `execution`/`campaign` 必需角色（11 字段完整 schema 见[接口契约增量](../interface-contract-delta.md)第 8 节，`report.model_audit` 为其 6 字段摘要）；T15 落地后 `intel_snapshot`、`license_record` 成为必需角色；此前允许缺失，但出现时必须使用对应角色。report 的 `intel` 是摘要对象，原始快照与许可正文分别以 `intel_snapshot`、`license_record` 文件角色归档。
16. **发布边界**。本轮 release smoke 与 B03 继续走 v1 兼容路径，发布 manifest 的 `contract_version` 固定为 `1`；`release.CONTRACT_VERSION` 使用字面量或独立常量，不依赖 `contracts.SCHEMA_VERSION`。回滚排空门禁扩展为 v2 非终态集合并在 smoke 前后各执行一次；v2 发布 smoke 另立后续任务，不在本轮静默混入。

## Alternatives considered

- **把 v1 包在线迁移为 v2**。会让旧摘要失效，且迁移过程本身需要可信执行；与“证据不可变”冲突。
- **只保留一个校验器，按字段存在性猜测版本**。字段缺失与旧包无法区分，容易把 v1 包误读为不完整 v2 包。
- **让 validation 复用 campaign 目录而不复制构建记录**。包更小，但 campaign 缺失或被移动后 validation 无法独立校验，违反自包含要求。
- **family 导出只产出聚合 manifest**。实现简单，但丢失单轮独立校验能力；审计无法定位具体轮次的原始文件。
- **campaign 也产出 verdict**。会把搜索观测误当复现结论，违反六次回放判据。
- **回滚后让 v1 代码兼容读取 v2 证据**。会把未验证的 v2 解析逻辑塞进冻结分支，破坏 v1 的字节级行为，也让回滚 gate 失去意义。

## Consequences

- 校验器需要维护两个分支，并长期冻结 v1 的旧实现；这是兼容成本，但避免改写历史证据。
- v2 validation 包体积增加（构建记录、日志、核对面与信封副本），换取脱离 campaign 的独立校验。
- family 导出需要处理路径、摘要与索引的一致性；任何复制错误都必须失败关闭。
- 新引用语法只在 v2 解释，跨版本引用会被拒绝；审计工具需要按包版本选择解析器。
- 双分支意味着测试必须同时覆盖 v1 冻结行为与 v2 新行为；只跑 v2 测试不能证明兼容。
- 长期保留 v1 分支会增加维护面，但相比改写历史证据或让旧包不可读，这是更小的风险。
- v2 必需角色比 v1 多，缺少 `envelope`、`budget_snapshot` 或 `build_provenance` 的包会直接失败；离线重算准入必须依赖这些文件。
- 回滚后仍需部署 v2 只读 verifier/export；这是回滚方案的一部分，不是可选运维项。
- 版本分派函数只读取 manifest 的版本字段，不读取 report 或文件角色来猜测版本。
- 旧 v1 校验器的测试向量要作为冻结回归保留，防止 v2 改动意外改变旧行为。
- family 导出的索引记录每轮 manifest 摘要，导入方可据此发现目录被替换。

## 对应 REQ

- [REQ-16 证据 v2 与 family 导出](../srs-delta.md)
- 修改后的 [REQ-08 报告与证据导出](../srs-delta.md)（v2 字段与 family 导出）
- [REQ-11 计划身份与 family](../srs-delta.md)（轮次与 family 身份进入 manifest/report）

## 测试坐标

- 版本分派：`tests/contract/test_evidence_v2.py::test_verify_bundle_dispatches_v1_and_v2_by_manifest_schema`
- v1 只读：`tests/contract/test_evidence_v2.py::test_v1_job_cannot_be_rerun_with_v2_semantics`
- v1 角色全集：`tests/contract/test_evidence_v2.py::test_v2_role_table_contains_v01_roles`
- 必需角色：`tests/contract/test_evidence_v2.py::test_validation_bundle_requires_envelope_and_budget_snapshot`
- campaign 无 verdict：`tests/contract/test_evidence_v2.py::test_campaign_bundle_has_no_verdict`
- 固定版本条件：`tests/contract/test_evidence_v2.py::test_fixed_execution_has_envelope_but_no_reuse_origin`
- 复用条件：`tests/contract/test_evidence_v2.py::test_reuse_validation_requires_build_ref_and_reuse_origin`
- 复用指针：`tests/contract/test_reuse.py::test_validation_reuses_campaign_build_and_detects_mismatch`
- family 导出：`tests/contract/test_evidence_v2.py::test_family_export_keeps_each_round_independently_verifiable`
- 回滚读取边界：`tests/integration/test_worker_fence.py::test_rolled_back_v1_reads_only_v1_era_evidence`
- 固定证据路径：`tests/contract/test_evidence_v2.py::test_manifest_uses_fixed_evidence_paths`
- `COMPLETED` 终态：`tests/contract/test_cli_status.py::test_campaign_and_family_terminal_state_completed`
- family 证据指针：`tests/contract/test_cli_status.py::test_family_completed_sets_evidence_path_and_digest`
- family index 必需：`tests/contract/test_cli_status.py::test_family_completed_requires_family_index`
- 导出字节一致：`tests/contract/test_export.py::test_family_index_is_byte_identical_to_export`
- 007 归档 CHECK：`tests/integration/test_migrations.py::test_family_completed_satisfies_archived_evidence_check`
- 发布版本解耦：`tests/contract/test_release.py::test_release_contract_version_is_not_derived_from_contracts_schema`
- 用例映射：[TC-16](../test-plan-delta.md)、[TC-08](../test-plan-delta.md)

以上坐标为 T10/T12 计划测试，T09 不创建代码。实现须先看到对应断言失败，再补最小行为。
