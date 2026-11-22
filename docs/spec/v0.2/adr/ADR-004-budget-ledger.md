# ADR-004 family 预算账本

**Status** Accepted  
**Date** 2026-11-21

## Context

v0.1 的预算绑定单个 job：执行阶段有总时长，回放有单次上限，恢复时预算持续有效。v0.2 的 family 会在同一父任务下创建多个 child job。若每个 child 各拿一份预算，family 总消耗会被放大；若由应用层先读余额再写回，并发轮次会同时看到“还有余额”并各自扣减，产生透支。

`max_rounds` 也有同样的并发问题：两个 worker 可能同时判断“还可以再建一轮”，然后各自创建 child。需要数据库层面的确定性约束，而不是依赖调度器恰好串行。但“需要数据库防御”不等于“生产上并发跑 child”：v0.2 不解除 v0.1 的单执行槽位，family 的多个 child 仍然串行执行，数据库层只是为未来多 worker 预留正确性。

预算还必须能解释“钱花在哪一轮”。只保留一个剩余数无法审计多轮探索；账本行保存汇总，扣费表保存每个 attempt 的明细，两者相加可对账。恢复时的幂等判断也需要稳定键：同一 attempt 恢复不得重复扣费，重试产生新 attempt 才新扣费。

## Decision

1. **family 级原子行**。每个 family 有一行预算账本，记录 `max_total_seconds`、`max_fuzz_seconds`、`remaining_total_seconds`（对应 JSON 字段 `remaining_seconds`）、`remaining_fuzz_seconds` 与 `updated_at`。表上约束 `max_total_seconds > 0`、`max_fuzz_seconds >= 0`、`max_fuzz_seconds <= max_total_seconds`、`remaining_total_seconds >= 0`、`remaining_total_seconds <= max_total_seconds`、`remaining_fuzz_seconds >= 0`、`remaining_fuzz_seconds <= max_fuzz_seconds`，**不**对两个剩余余额增加 `remaining_fuzz_seconds <= remaining_total_seconds` 的交叉 CHECK：`charge_kind='general'` 的 build/replay 只扣总预算，正常运行时 fuzz 余额大于总余额是合法状态（完整 DDL 见[接口契约增量](../interface-contract-delta.md)第 7 节）。
2. **唯一执行与原子扣减协议**。**启动前**先校验总余额 `remaining_total_seconds >= 1` 与（fuzz 时的）`min(remaining_total_seconds, remaining_fuzz_seconds) >= 1`，并将该最小值下发为容器硬超时上限；**容器退出后**在独立短事务内按 `charged_seconds = min(ceil(elapsed), remaining_total_seconds)`（fuzz 时 `charged_fuzz = min(max(1, ceil(elapsed_fuzz)), remaining_fuzz_seconds, charged_seconds)`）执行单条原子条件 `UPDATE ... WHERE remaining >= x` 并写入 `budget_charges`，禁止先 `SELECT` 再 `UPDATE` 的应用层读改写；若实耗触达或超过余额则同时触发 `BUDGET_EXHAUSTED`。
3. **单执行槽位**。v0.2 不解除 v0.1 的单执行槽位：family 的多个 child 串行执行，同一时刻只有一个执行者。`UNIQUE(parent_job_id, round_no)` 与条件更新是数据库层对未来多 worker 的防御，不代表生产会并行跑 child。并发预算测试只用两个数据库连接模拟竞争，验证 SQL 原子性，不虚构多 worker 运行时。
4. **轮次上限**。`max_rounds` 由准入 predicate 检查 `round_no <= max_rounds`；`UNIQUE(parent_job_id, round_no)` 只防重复轮次，不能写成“防超限”。创建 child 前 predicate 还需校验账本余额。
5. **幂等扣费**。`budget_charges` 增加 `family_id`、`attempt_no`、`fuzz_seconds` 与 `charge_kind`；幂等键为 `(job_id, step_key, attempt_no)`。恢复同一 attempt 返回既有记录，不重复扣费；重试产生新 `attempt_no`，按新 attempt 扣费。`0 <= fuzz_seconds <= seconds`。
6. **恢复不重复记账**。worker 重启或租约接管后，已完成的 build/replay 步骤从持久化记录读取；对应 attempt 的 charge 已存在则跳过。无法确认扣费是否提交时，按幂等键重试，不以“可能扣过”为由重复扣减。
7. **fuzz 子预算**。`max_fuzz_seconds` 是 `max_total_seconds` 内的子预算；fuzz 消耗同时扣总预算与 fuzz 子预算，实际可执行 fuzz 上限为 `min(remaining_total_seconds, remaining_fuzz_seconds)`（JSON 对应 `min(remaining_seconds, remaining_fuzz_seconds)`），任一不足即拒绝启动并返回 `BUDGET_EXHAUSTED`，不以单一余额判断。build 与 replay 只扣总预算，`charge_kind='general'` 且 `fuzz_seconds=0`，因此不扣 fuzz 余额。不足 1 秒的 fuzz 步按 1 秒向上取整后落账（`charge_kind='fuzz'` 的 `fuzz_seconds >= 1`），未真正启动则不落 charge。
8. **耗尽终态**。预算不足以启动下一轮或下一步时，不再创建 child；当前 child 按已有回放归档，证据判定为 `INCONCLUSIVE` 或 `FAILED`，并给出 `BUDGET_EXHAUSTED`。campaign 与 family 在预算耗尽后完成归档，job 终态即 `COMPLETED`（`verdict`/`reason_code` 为 null、`evidence_status='archived'`）。若已完成的六次回放足以形成结论，则保留结论，不因剩余预算不足改写判定。
9. **可对账**。预算行、charge 记录与证据中的预算汇总必须能离线相加对账。report 的 `budget` 必须同时含 `max_total_seconds`、`max_fuzz_seconds`、`spent_seconds`、`spent_fuzz_seconds`、`remaining_seconds`、`remaining_fuzz_seconds`，并能仅凭 `budget_charges` 按 `family_id` 重建 `spent_seconds` 与 `spent_fuzz_seconds`。账本时间使用数据库时钟或注入的假时钟，测试不依赖宿主墙钟。
10. **不回收已耗预算**。轮次失败、证据归档失败或任务阻断都不退还已消耗时间；重试消耗新预算，除非该步骤同一 attempt 的 charge 幂等键证明它从未真正开始。这样“恢复”不会变成免费重跑。
11. **失败语义**。条件更新影响 0 行时，根据剩余总预算与 fuzz 子预算分别返回 `BUDGET_EXHAUSTED`；约束冲突与幂等键冲突分开处理，后者返回既有扣费记录而不是报错。

## Alternatives considered

- **每个 child 独立预算**。实现简单，但 family 总消耗不可控，无法防止多轮叠加超出操作者授权。
- **应用层互斥锁或 advisory lock**。能串行化扣减，但锁的范围、持有时长与恢复行为难以验证；数据库条件更新本身已经提供原子性，锁是额外故障点。
- **只用 `max_rounds` 限制，不记时间预算**。轮次有上界，但单轮可以耗尽全部时间，仍无法防止总量超支。
- **无启动前门禁的事后补扣**。允许无启动前余额校验与硬超时下发就先执行后记账，会在透支发生后才发现；违反“预算不足时拒绝启动”的边界。
- **让 family 多 child 并行执行**。能缩短墙钟时间，但违反 v0.1 单执行槽位、放大容器与镜像争用，也不是本轮安全边界要解决的问题。

## Consequences

- 预算从 job 级变为 family 级，父 job 必须持有账本；child 不再拥有独立总预算。
- 每次 build/replay/fuzz 都需要一个幂等 `step_key` 与 `attempt_no`；重复执行与恢复路径必须共享同一键，重试必须换 attempt。
- 透支会在数据库层直接失败，而不是被业务逻辑“修正”；错误路径需要把约束冲突转换为 `BUDGET_EXHAUSTED` 或明确的内部错误。
- fuzz 子预算与总预算的双重扣减增加测试矩阵，但能分别回答“总时长还剩多少”和“还能 fuzz 多久”。
- 账本成为 family 级共享写热点；单行条件更新会短暂串行化扣费，但这是可接受的代价，避免透支。
- 不退还已耗预算意味着失败轮次也会消耗 family 额度；操作者需要在信封中预留失败与重试空间。
- 预算账本按 family 建行，父 job 创建时初始化；child 只持有引用，不复制余额。
- 扣费落账与步骤结果记录在同一短事务内提交，容器执行本身在事务外进行；若步骤失败但扣费已提交，保留扣费并记录失败原因。
- 账本对账以 charge 表为准，汇总行可由 charge 重建；两者不一致时任务失败关闭。
- 测试中的并发使用真实数据库连接，不用进程内锁模拟，否则无法验证条件更新；这只证明 SQL 原子性，不证明存在并行执行者。
- 单执行槽位意味着 family 的墙钟时间是各 child 之和；这是本轮接受的吞吐代价。
- v0.2 沿用 v0.1 `limits.execute_seconds` 1200 秒上限，真实多轮案例如需更长预算另立配置调整。

## 对应 REQ

- [REQ-14 family 预算账本](../srs-delta.md)
- 修改后的 [REQ-07 证据驱动的结论](../srs-delta.md)（预算耗尽与结论的关系）
- [REQ-12 探索信封与自动准入](../srs-delta.md)（预算作为准入 predicate 的输入）

## 测试坐标

- 并发扣减：`tests/contract/test_budget_ledger.py::test_concurrent_charge_cannot_overdraw_family_budget`
- 恢复幂等：`tests/contract/test_budget_ledger.py::test_recovery_does_not_charge_twice`
- 新 attempt 新扣费：`tests/contract/test_budget_ledger.py::test_retry_with_new_attempt_charges_again`
- fuzz 子预算：`tests/contract/test_budget_ledger.py::test_fuzz_charge_decrements_both_budgets`
- fuzz 上限取两者最小值：`tests/contract/test_budget_ledger.py::test_fuzz_cap_uses_min_of_both_budgets`
- 不设剩余余额交叉 CHECK：`tests/integration/test_migrations.py::test_budget_ledger_has_no_cross_remaining_check`
- 耗尽终态：`tests/contract/test_budget_ledger.py::test_exhaustion_returns_budget_exhausted_terminal`
- 账本对账：`tests/contract/test_budget_ledger.py::test_report_budget_includes_fuzz_sub_budget`
- 轮次唯一：`tests/integration/test_migrations.py::test_jobs_parent_round_unique_rejects_duplicate`
- 轮次上限：`tests/contract/test_admission.py::test_round_beyond_max_rounds_is_denied`
- 单槽位：`tests/unit/test_orchestration_graph.py::test_family_children_execute_serially`
- 用例映射：[TC-14](../test-plan-delta.md)、[TC-12](../test-plan-delta.md)

以上坐标为 T12 计划测试，T09 不创建代码。实现须先看到对应断言失败，再补最小行为。
