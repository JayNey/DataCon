# ADR-003 假设到 ExperimentSpec

**Status** Accepted  
**Date** 2026-11-21

## Context

v0.1 允许分析 Agent 输出 `fact` 或 `hypothesis`，但 hypothesis 只进入计划摘要，没有可执行的实验载体。v0.2 引入 guided 探索后，模型会提出“某个符号在某个输入族下可能触发某类 sanitizer”。如果让模型直接生成命令、脚本或 harness，模型就从“建议者”变成了“执行者”，违反确定性授权边界；如果只保留自由文本，又无法把假设纳入信封、预算与证据链。

需要一种受约束的中间结构：它足以描述实验意图，但不包含可执行代码；它必须由确定性检查转换为实验，而不是由模型直接执行。该结构还必须能落进计划与证据，而不只是提示词的一部分，否则同一段 hypothesis 在不同轮次可能被解释成不同实验。

模型来源的“事实”还有另一个问题：确定性工具已经产出的事实不应由模型转述后再进入证据链，否则无法区分“工具观测”与“模型声称”。v0.2 因此收窄模型出口，只允许 hypothesis。质量评估同样需要区分：v0.1 的 B04 覆盖六类 Agent 场景与路由/越权指标，是发布门禁；v0.2 新增的 hypothesis 质量指标不能替换它。

## Decision

1. **AgentOutput v2 只允许 hypothesis**。模型来源的 `finding` 只允许 `kind=hypothesis`，附 `statement`、`confidence` 与 `evidence_refs`；出现 `kind=fact` 视为非法输出并阻断。确定性工具产生的事实不通过模型 `AgentOutput` 的 `fact` 输出，另走 `ToolResult` 结果与证据引用。该规则覆盖 v0.1 的 `fact|hypothesis`；v1 `AgentOutput` 记录只读兼容，可查询、可导出、不重跑。
2. **ExperimentSpec 九字段**。可执行假设必须落成 `ExperimentSpec`，字段固定为 `target_symbol`、`target_path`、`target_line`、`input_family`、`mutation_constraints`、`expected_signature`、`rationale`、`evidence_refs` 与 `confidence`。字段集合封闭，未知字段拒绝；不接受自由命令或额外可执行材料。
3. **统一签名结构**。`ExperimentSpec.expected_signature`、plan `asan_signature` 与信封 `accepted_signature_set` 使用同一结构：`error`、`function`、`source` 必填，`operation`、`access_size` 可选（例如 `SEGV`、`stack-overflow`、`double-free` 没有 READ/WRITE 大小）。匹配时做全字段严格相等：字段存在性、值、可选字段缺失/存在都要比较；不允许只比较 sanitizer 字符串或 error 类别。
4. **确定性转换**。由规划器把 hypothesis 转成 ExperimentSpec；规划器只读取已冻结的源码范围、信封、签名集合与案例材料。实验的执行方式仍由已注册的 harness 与 build recipe 决定，ExperimentSpec 只描述目标与输入约束。
5. **信封内实验**。`input_family` 必须属于 `allowed_mutation_families`；`mutation_constraints` 必须逐项是信封 `mutation_limits` 的子集（`allowed_ops` ⊆ 信封集合，`max_input_bytes <=` 信封上限）；`expected_signature` 必须与 `accepted_signature_set` 中某一项全字段相等；`target_path`、`target_line` 必须落在计划固定的版本与源码范围内。越界即 `ENVELOPE_VIOLATION`，不得进入 build/replay。
6. **证据引用可解析**。`evidence_refs` 至少有一项可解析，支持补丁、源码、构建日志（`log/build`）与 fuzz 日志（`log/fuzz`）引用。引用不可解析的 hypothesis 保留为未验证线索，不生成 ExperimentSpec；不得把“模型说相关”当作证据。
7. **假设不改变判定**。ExperimentSpec 只影响下一轮选什么输入、跑什么实验；`REPRODUCED`、`NOT_REPRODUCED`、`INCONCLUSIVE` 仍只由六次回放与确定性规则产生。删除、改写或新增 hypothesis 后，只要回放观测相同，判定必须相同。
8. **模型出口审计**。模型送出的字段、脱敏规则、endpoint、模型版本与 prompt 版本都进入 `model_audit`；默认离线，且 offline 时也必须写 `provider=offline`、`outcome=offline` 与版本字段为 null，不得省略该对象。模型失败回退离线路径或阻断，不通过放宽实验范围来补偿。
9. **fuzz harness 不是模型产物**。harness 是经审核的冻结材料，与 build recipe 同级；模型不得合成、改写或替换 harness。任何未审核 harness 在执行前返回 `HARNESS_REJECTED`。
10. **实验身份与排序**。ExperimentSpec 的规范化摘要作为 plan 的 `experiment_digest` 进入轮次计划摘要（fixed 与 campaign 为 null 但仍参与规范化）；多个候选实验按预算、置信度与证据强度确定性排序，排序规则不读取模型自由文本。同一摘要的实验不得重复执行。
11. **B04 双基准**。v0.1 的 **B04-A** 保持原样：覆盖材料齐全、冲突、补丁歧义、二进制目标、提示注入与缺证六类 Agent 场景，记录结构合规率、路由准确率、可追溯事实比例与越权尝试数；三轮评测零实际越权工具调用、进入下游结果全部通过契约校验是 v0.1 的发布门禁。新增 **B04-H** hypothesis quality 子基准，报告 end-to-end precision（主指标，被拒/越界条目也进分母）、accepted precision（辅助）、recall、rejection_rate 与样本量。B04-H 是新的质量报告与门槛，不能覆盖、替换或放宽 B04-A。
12. **标注集版本**。`annotation_version` 形如 `b04-annotations-v1`，由版本标签加标注集摘要组成；格式为 `<label>+<摘要>`，摘要使用带 `sha256` 前缀的 64 位小写十六进制，例如 `b04-annotations-v1+sha256:0000000000000000000000000000000000000000000000000000000000000014`。标注集来源是人工在公开补丁与对应源码上的标注，写入后冻结；新增或修改标注必须产生新版本，旧版本保留以便复现历史报告。
13. **拒绝语义**。字段非法、证据不可解析、family 越界或签名不在集合内时，实验不进入准入；父 job 保留被拒条目与原因，供 B04-H 评估。被拒条目不能进入 accepted precision，但必须进入 end-to-end precision 的分母；不得通过让 policy 拒绝来抬高主指标。

## Alternatives considered

- **让模型直接生成并执行 fuzz 脚本**。最灵活，但无法审计、无法保证容器边界，且模型输出会被当作代码执行，直接违反 v0.1 的“外部文本只作数据”原则。
- **只保留自由文本 hypothesis**。安全，但无法把假设纳入预算、信封与证据，guided 模式退化为人工逐条转写。
- **允许模型提供任意字节生成器**。比脚本窄，但仍可生成超大输入、绕过 mutation family 或触发未审核路径；`mutation_constraints` 必须是信封内的受限操作。
- **用 hypothesis 作为判定依据**。会让模型间接决定复现结论，违反 v0.1 REQ-07 的确定性判据。
- **用 B04-H 替换 B04-A**。会把发布门禁从“越权与路由”降级为“模型质量分数”，丢掉 v0.1 已冻结的安全断言。

## Consequences

- 模型能力被限制在“提出目标与输入约束”，不能直接提高实验吞吐；这是刻意的安全取舍。
- 每条进入下游的 hypothesis 都必须有可解析证据，低质量 hypothesis 会被拒绝或留在线索层；B04 同时报告端到端 precision 与 accepted precision。
- ExperimentSpec 成为 plan 与证据的一部分，需要新的契约校验、准入检查与 B04 质量指标。
- fuzz harness 的审核流程与 build recipe 合并，材料注册表需要同时冻结两者。
- 实验排序与去重必须确定，不能依赖模型返回顺序；同一 case 重跑应得到相同实验顺序。
- 被拒 hypothesis 仍有审计价值：它们说明模型在哪些方向越界，必须进入端到端 precision 分母，但不能进入 accepted precision，也不能影响判定。
- 实验排序规则与信封版本绑定；规则变化只影响新轮次，不重排已归档实验。
- 证据引用解析失败时保留原始 hypothesis 文本，但不把文本当作事实或判定依据。
- B04 质量报告按标注集统计；主指标包含被拒/越界条目，辅助指标只统计通过准入的条目。标注集版本必须随报告冻结，否则跨版本数字不可比。
- 模型出口与实验规划共用同一份允许字段与脱敏规则，避免两处配置漂移。
- B04-H 与 B04-A 的报告分开呈现，发布门禁只认 B04-A 的既有硬门槛，避免新指标稀释旧断言。

## 对应 REQ

- [REQ-13 假设到实验](../srs-delta.md)
- 修改后的 [REQ-09 Agent 决策可审计](../srs-delta.md)（模型出口与审计）
- 修改后的 [REQ-03 可审核的分析与计划](../srs-delta.md)（实验落在计划与信封内）

## 测试坐标

- 字段封闭：`tests/contract/test_experiment_spec.py::test_experiment_spec_has_closed_nine_fields`
- 签名匹配：`tests/contract/test_experiment_spec.py::test_expected_signature_matches_full_accepted_signature`
- 引用不可解析：`tests/contract/test_experiment_spec.py::test_unresolvable_evidence_refs_block_experiment_spec`
- 计划绑定：`tests/contract/test_plan_family.py::test_plan_digest_binds_experiment_and_provenance_version`
- 越界实验：`tests/contract/test_envelope.py::test_out_of_envelope_experiment_is_denied_before_build`
- 假设不改判定：`tests/contract/test_hypothesis_verdict.py::test_hypothesis_does_not_change_deterministic_verdict`
- 模型出口：`tests/contract/test_model_outlet.py::test_offline_default_makes_no_external_request`
- 模型不出 fact：`tests/contract/test_model_outlet.py::test_model_finding_must_be_hypothesis`
- harness 冻结：`tests/contract/test_fuzz.py::test_frozen_harness_rejects_model_generated_material`
- B04 版本：`tests/contract/test_b04_hypothesis_quality.py::test_b04_annotation_set_is_versioned`
- B04 指标：`tests/contract/test_b04_hypothesis_quality.py::test_b04_reports_end_to_end_and_accepted_precision`
- B04-A 保留：`tests/contract/test_b04_hypothesis_quality.py::test_b04_agent_scenarios_remain_release_gate`
- 用例映射：[TC-13](../test-plan-delta.md)、[TC-09](../test-plan-delta.md)

以上坐标为 T12/T14 计划测试，T09 不创建代码。实现须先看到对应断言失败，再补最小行为。
