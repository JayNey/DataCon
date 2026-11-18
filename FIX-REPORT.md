# DataCon PR #7 修复报告（B-1 & S-1…S-11）

- **审查基线**：`60a63f9d20415bb26fe8df53a12c538a3bcad0f2`（base `main @ fdba080`）
- **修复提交**：`fe4fb6dbec322d6f0a93ce7a5c69242f6063a2fc`（分支 `feat/mvp-ci-release`）
- **CI Run ID（代码/测试提交 `fe4fb6d`）**：[`44264821558`](https://github.com/JayNey/DataCon/actions/runs/44264821558) — `status=completed`, `conclusion=success`（`image` 与 `test` 均通过）
- **`release.yml` 真实 dispatch 状态**：**未运行 / 无法验证**（`gh run list --repo JayNey/DataCon --workflow=release.yml --limit 5` 返回 HTTP 404，`origin/main` 尚无 `.github/workflows/release.yml`）

---

## 逐项修复总表

| ID | 状态 | 文件:行 | 修复摘要 | 新增/修改测试 | 修复前红证据（`60a63f9`） | 修复后验证 |
| --- | --- | --- | --- | --- | --- | --- |
| B-1 | 已修复 | `src/datacon/release.py:1025-1088` | `rollback_release` 在 `smoke_checks` 前及事务内重读 `latest` 后分别用 `_same_release` 拒绝 `target == active`，抛出 `ReleaseGateError`，不写 `switch` 与 `release_events`。 | `tests/contract/test_release.py::test_rollback_release_rejects_target_equal_to_active`; `tests/integration/test_release_rollback.py::test_rollback_release_rejects_target_equal_to_active_in_postgres` | `test_rollback_release_rejects_target_equal_to_active` -> `Failed: DID NOT RAISE ReleaseGateError`（在 `60a63f9` 上返回 `rolled_back`） | 本地 contract 122 passed；CI `44264821558` `postgres=210`、`contract=797` 零 skip 零失败 |
| S-1 | 已修复 | `.github/workflows/release.yml:28-44,330-353,466-515` | 移除 tag push 自动 promote 死路径；`promote-internal`/`rollback-internal`/`b03-internal` 仅允许 `workflow_dispatch` + `refs/heads/main`，移除 `needs.build-candidate.outputs.manifest_digest` 与非 dispatch 下载死步骤；`build-candidate` 保留 `main`/`v*` tag 构建及双祖先校验。 | `tests/contract/test_release_workflow.py::test_secret_jobs_only_run_on_main_workflow_dispatch_never_tags`（含结构化 `_eval_gha_condition`）；更新 `test_promote_job_requires_test_report_and_build_candidate_without_always` 与 `test_internal_jobs_are_restricted_to_main_or_a_release_tag` | `test_secret_jobs_only_run_on_main_workflow_dispatch_never_tags` 在 `60a63f9` 上红：`promote-internal` `if:` 含 `refs/tags/v` 且 `EXPECTED_MANIFEST_DIGEST` 含 `needs.build-candidate.outputs.manifest_digest` | 本地 `test_release_workflow.py` 全绿；`ci_gates --root .` `ok: true`；`release.yml` 未真实 dispatch |
| S-2 | **部分修复 / 阻塞待设置（需维护者完成）** | `.github/workflows/release.yml:60-64,330-353,782-807,1105-1130`; `docs/release-settings.md`; `README.md:350-395` | 代码侧：将 secret job 收窄到 `main` `workflow_dispatch`，`test-report` 增加 `main`/`v*` 的 `push`/`workflow_dispatch` ref guard；文档侧：新增 `docs/release-settings.md` 写明旧提交（如 `04f45b8`）可被历史 tag 召回的风险及 `internal-lab` 环境 / `v*` tag protection 设置步骤。**仓库设置仍待维护者确认**（`gh api repos/JayNey/DataCon/environments/internal-lab` 返回 404）。 | `tests/contract/test_release_workflow.py::test_secret_jobs_only_run_on_main_workflow_dispatch_never_tags`, `test_test_report_has_main_and_tag_ref_guard` | `60a63f9` 上 `test-report` 无 `if:`、`secret` job 允许 `refs/tags/v*`；`gh api .../environments/internal-lab` 返回 404 | 代码/测试/文档已验证；**仓库 Environment 规则与 tag protection 需维护者在合入前人工设置并验证** |
| S-3 | 已修复 | `src/datacon/state.py:1881-1953`; `src/datacon/release.py:816-995,1146-1220`; `.github/workflows/release.yml:340-348,735-770` | `ReleaseStore.latest_evidence_bundle` 增加 `strict: bool = False`（`strict=True` 时 active root 下无合法 bundle 抛 `ReleaseStateError`）；新增 `release.archived_bundle_preflight` 与 `promote_and_smoke(..., audit_metadata=...)`，默认 fail closed 要求挂载证据卷且存在真实 bundle；仅显式 `require_archived_bundle=false` + 非空 `archived_bundle_skip_reason` 允许跳过并在 `promotion-result.json` 与 `release_events` 记录审计字段；`promote-internal` 改为 `[self-hosted, linux, x64, datacon-internal]`。 | `tests/contract/test_release.py::test_promote_requires_real_archived_bundle_when_strict`; `tests/integration/test_release_rollback.py::test_latest_evidence_bundle_strict_requires_active_root_bundle`; `tests/contract/test_release_workflow.py::test_promote_archived_bundle_is_fail_closed_by_default_and_audited_when_skipped` | `test_promote_requires_real_archived_bundle_when_strict` -> `AttributeError: module 'datacon.release' has no attribute 'archived_bundle_preflight'`；`60a63f9` workflow 含 `skipping archived_real_bundle` 静默分支 | 本地 contract 全绿；CI `44264821558` `postgres=210` 含新集成测试全绿 |
| S-4 | 已修复 | `src/datacon/state.py:1482-1535`; `src/datacon/cli.py:343-370` | 抽取 `ReleaseStore._ensure_release_tables(connection)` 检查 `schema_migrations`/`release_state`/`release_events`，在 `_connection()` 打开新连接与 `transaction()` 均调用；`cli.py` `_release_slots` 先捕获 `(state.StateError, ValueError)` 返回退出码 2 `INVALID_RELEASE_STATE`，`psycopg.Error` 仅用于连接/权限故障（退出码 1）。 | `tests/contract/test_release.py::test_release_store_connection_ensures_release_tables_and_cli_slots_exits_2`; `tests/integration/test_release_rollback.py::test_all_release_store_entrypoints_and_slots_cli_fail_closed_on_unmigrated_db` | `60a63f9` 上 `test_release_store_connection_ensures_release_tables_and_cli_slots_exits_2` 在 `active_slots()` 处失败（未查 `to_regclass` 直接查询 `jobs`） | 本地 fake connection + CLI 退出码 2 测试通过；CI `44264821558` `postgres=210` 真实空 schema 集成测试通过 |
| S-5 | 已修复 | `src/datacon/ci_gates.py:115,325-365,446-475` | `check_workflow_security` 拒绝任意 `secrets: inherit` 及外部 reusable workflow 的任意 `secrets`（保留本地 `./` reusable workflow 的 `secrets:` mapping）；`_check_with_expressions` 校验 `with:` key 必须为静态标识符（拒绝 `${{`、`$`, 非 `_STATIC_WITH_KEY`），不误杀 `env` 中 `secrets.X`。 | `tests/contract/test_ci_gates.py::test_workflow_security_rejects_secrets_inherit_external_secrets_and_with_key_expressions` | `60a63f9` 上 `check_workflow_security([ext_inherit])` 返回 `[]`（`AssertionError: []`） | 本地 `test_ci_gates.py`、`ci_gates --root .` 与恶意 YAML 探针均通过 |
| S-6 | 已修复 | `src/datacon/ci_gates.py:114,211-306` | 为 `_walk_yaml` 与 `_iter_yaml_strings` 增加每次顶层调用 150,000 节点预算（`_bump_yaml_budget`），保留环检测；超预算立即抛 `GateError`，`check_workflow_security` 捕获并快速返回错误。 | `tests/contract/test_ci_gates.py::test_workflow_security_rejects_yaml_alias_bomb_within_budget` | `60a63f9` 上 `n=21` 耗时 `3.88s` 且返回 `[]`，`n=30` 子进程 `1.5s` 超时（`TIMED OUT after 1.5s`） | 本地 `n=30` 探针 `<0.05s` 返回 `GateError` / 错误列表；真实 `ci.yml`/`release.yml` 均 `ok` |
| S-7 | 已修复 | `tests/contract/test_release_workflow.py:372-699`; `.github/workflows/release.yml:466-475,548-558,912-920` | 将 secret 收窄与 timeout 检查升级为结构化 `_assert_secrets_scoped`、Python `ast.parse`（检查所有 `subprocess.run` 的 `timeout=` keyword）与 `shlex` token 解析；补齐 `git merge-base` 的 `timeout=30`；新增 negative-control 测试验证 mutant（approval 前插入 secret、注释/删除 `timeout`）必红。 | `tests/contract/test_release_workflow.py::test_no_secret_in_any_step_before_approval`, `test_smoke_subprocess_calls_have_timeout`, `test_secret_scoping_helper_rejects_secret_inserted_before_approval`, `test_timeout_helper_rejects_commented_or_removed_timeout` | `60a63f9` 上 `test_smoke_subprocess_calls_have_timeout` 捕获到 `promote-internal` `subprocess.run` 缺失 `timeout=` | 本地 4 个结构化/negative-control 测试全绿；CI `44264821558` 通过 |
| S-8 | 已修复（代码/workflow 就绪；需 runner 配置 `DATACON_B03_EVIDENCE_DIR`） | `src/datacon/release.py:2722-2785`; `.github/workflows/release.yml:1180-1260` | 新增 `release.persist_b03_evidence_bundle` 使用 `evidence.export_bundle` + `evidence.verify_bundle` 持久化并复验到 `<DATACON_B03_EVIDENCE_DIR>/<job_id>/`；`b03-internal` 要求 `DATACON_B03_EVIDENCE_DIR` 非空（fail closed），在 `finally` 删除临时 `bundle_out` 前持久化并把 `bundle_path`、`bundle_manifest_digest`、`bundle_verified` 写入 summary，不上传完整 bundle 到 artifact。 | `tests/contract/test_release.py::test_persist_b03_evidence_bundle_copies_verifies_and_detects_tampering`; `tests/contract/test_release_workflow.py::test_b03_persists_bundle_before_cleanup_and_fails_closed_without_dir` | `test_persist_b03_evidence_bundle_...` -> `AttributeError: module 'datacon.release' has no attribute 'persist_b03_evidence_bundle'`；`60a63f9` workflow 缺 `DATACON_B03_EVIDENCE_DIR` | 本地 contract 与篡改测试全绿；**维护者需在 GitHub Variables 配置 runner 的 `DATACON_B03_EVIDENCE_DIR` 持久目录** |
| S-9 | 已修复 | `.github/workflows/release.yml:1044-1102` | 在 `rollback_release` 的 `smoke_checks`（切换前）新增 `release_slots` 兼容性检查（exit 0、合法 JSON、含 `active_release`/`active_slots`，不断言 target 已 active）；保留事务内 `post_switch_checks["active_release_restored"]`；移除提交后 gating `release slots` 步骤。 | `tests/contract/test_release.py::test_rollback_pre_switch_container_check_failure_leaves_active_unchanged`; `tests/contract/test_release_workflow.py::test_rollback_runs_release_slots_compatibility_in_pre_switch_smoke_not_post_commit` | `60a63f9` 上 `test_rollback_runs_release_slots_compatibility_in_pre_switch_smoke_not_post_commit` 失败：`AssertionError: post-commit release slots gating step must not exist` | 本地 contract 与 workflow AST 检查全绿；real Docker 回滚仍待 `release.yml` dispatch 验证 |
| S-10 | 已修复 | `scripts/run_suite.sh:1-34`; `.github/workflows/ci.yml:292-295`; `.github/workflows/release.yml:60-64,115-118` | 抽取共享脚本 `scripts/run_suite.sh` 同时捕获 `pytest_rc` 与 `junit_rc`，任一非零即退出 1；`ci.yml` 与 `release.yml` 均调用之并保留 `status=0; ... || status=1` 聚合；`test-report` 增加 `main`/`v*` ref guard。 | `tests/contract/test_release_workflow.py::test_run_suite_script_respects_both_pytest_and_junit_exit_codes`, `test_workflows_use_shared_run_suite_script`, `test_test_report_has_main_and_tag_ref_guard` | `60a63f9` 上 `test_run_suite_script_respects_both_pytest_and_junit_exit_codes` 失败（`scripts/run_suite.sh` 不存在），旧内联 `run_suite` 在 `pytest_rc=1` + 合法 XML 时返回 `old_run_suite_rc=0` | fake `uv` 三组用例全部按预期退出；CI `44264821558` 实际通过 `scripts/run_suite.sh` 完成四组零 skip 运行 |
| S-11 | 已修复 | `src/datacon/release.py:1803-1812` | `_validate_b03_checks` 对 `status == "pass"` 强制要求 `entry["evidence"]` 为 strip 后非空字符串，否则抛 `ReleaseGateError`。 | `tests/contract/test_release.py::test_b03_pass_checks_require_nonempty_evidence` | `test_b03_pass_checks_require_nonempty_evidence` -> `Failed: DID NOT RAISE ReleaseGateError` | 本地 contract 与既有 B03 用例全绿 |

---

## 1. 变更文件清单与范围确认（`git diff --stat 60a63f9..fe4fb6d`）

```text
 .github/workflows/ci.yml                   |  26 +-
 .github/workflows/release.yml              | 218 +++++++------
 README.md                                  |  27 +-
 docs/release-settings.md                   |  42 +++
 scripts/run_suite.sh                       |  34 ++
 src/datacon/ci_gates.py                    |  73 ++++-
 src/datacon/cli.py                         |   8 +-
 src/datacon/release.py                     | 171 ++++++++++
 src/datacon/state.py                       |  48 ++-
 tests/contract/test_ci_gates.py            | 144 +++++++++
 tests/contract/test_release.py             | 233 ++++++++++++++
 tests/contract/test_release_workflow.py    | 494 +++++++++++++++++++++++++++--
 tests/integration/test_release_rollback.py | 120 +++++++
 13 files changed, 1443 insertions(+), 195 deletions(-)
```

确认未修改 T01–T06 无关路径（`contracts.py`、`cases.py`、`agents/`、`execution.py`、`tools/sandbox.py`、`verdict.py`、`asan.py`、`evidence.py`、`migrations/` 均未改动）。

---

## 2. CI 结果（新 head `fe4fb6d`）

- **Workflow**: CI (`.github/workflows/ci.yml`)
- **Run ID**: `44264821558`（`status=completed`, `conclusion=success`）
  - `image` job (`134666612556`): `success`
  - `test` job (`134666612805`): `success`
- **四组 JUnit 统计**（`total = 1031`，与 `pytest --collect-only` 分区总数一致，全部 `skipped=0 failures=0 errors=0`）：
  - `postgres`: `total=210 skipped=0 failures=0 errors=0`
  - `docker`: `total=18 skipped=0 failures=0 errors=0`
  - `asan`: `total=6 skipped=0 failures=0 errors=0`
  - `contract`: `total=797 skipped=0 failures=0 errors=0`

---

## 3. `release.yml` 真实 dispatch 状态

- **状态**：**未运行 / 无法验证**
- **命令输出**：`gh run list --repo JayNey/DataCon --workflow=release.yml --limit 5` 返回 `HTTP 404: workflow release.yml not found on the default branch`。

---

## 4. 修复前红证据汇总（基线 `60a63f9`）

- **B-1**: `PYTHONPATH=src .venv/bin/python -m pytest -q tests/contract/test_release.py -k test_rollback_release_rejects_target_equal_to_active` → `Failed: DID NOT RAISE ReleaseGateError`
- **S-3**: `test_promote_requires_real_archived_bundle_when_strict` → `AttributeError: module 'datacon.release' has no attribute 'archived_bundle_preflight'`
- **S-4**: `test_release_store_connection_ensures_release_tables_and_cli_slots_exits_2` → 在 `store_handle.active_slots()` 处未查 `to_regclass` 直接执行 `SELECT COUNT(*) ... FROM jobs` 而触发测试断言失败
- **S-5**: `test_workflow_security_rejects_secrets_inherit_external_secrets_and_with_key_expressions` → `AssertionError: []`（外部 reusable workflow + `secrets: inherit` 返回空错误列表）
- **S-6**: `60a63f9` 上 `n=21` YAML alias 耗时 `3.88s`（`errors=[]`）；`n=30` 子进程 `1.5s` 超时（`TIMED OUT after 1.5s`）
- **S-7**: `test_smoke_subprocess_calls_have_timeout` → `AssertionError: promote-internal: subprocess.run missing timeout= keyword`
- **S-8**: `test_persist_b03_evidence_bundle_copies_verifies_and_detects_tampering` → `AttributeError: module 'datacon.release' has no attribute 'persist_b03_evidence_bundle'`
- **S-9**: `test_rollback_runs_release_slots_compatibility_in_pre_switch_smoke_not_post_commit` → `AssertionError: post-commit release slots gating step must not exist`
- **S-10**: `test_run_suite_script_respects_both_pytest_and_junit_exit_codes` → `AssertionError: scripts/run_suite.sh is_file() == False`；且旧内联 `run_suite` 在 `pytest_rc=1` + 合法 XML 下返回 `old_run_suite_rc=0`
- **S-11**: `test_b03_pass_checks_require_nonempty_evidence` → `Failed: DID NOT RAISE ReleaseGateError`

---

## 5. 尚未完全闭环 / 需维护者设置的阻塞项

1. **S-2（部分修复 / 阻塞待设置）**：
   - **阻塞原因**：`gh api repos/JayNey/DataCon/environments/internal-lab` 返回 `HTTP 404`。历史 PR 提交（如 `04f45b8`）中的旧版 `release.yml` 无法通过修改当前 head 来追溯修改；若无 Environment 保护，指向旧提交的 `v*` tag 仍会触发旧版 job 级 secret 路径。
   - **需要维护者完成**（详参 [docs/release-settings.md](docs/release-settings.md)）：
     1. 创建 Environment `internal-lab`，配置 **Deployment branches and tags = Selected branches and tags（仅 `main`）**；
     2. 开启 **Required reviewers**；
     3. 在 Rulesets 开启 **`v*` Tag Protection**（禁止非维护者创建/指向未合入提交的 `v*` tag）；
     4. 配置 environment secrets：`DATACON_DATABASE_URL`、`DATACON_RELEASE_APPROVAL`、`DATACON_B03_CASE_ROOT`、`DATACON_B03_ADMISSION`、`DATACON_B03_REVIEW`。
   - **验证方法**：维护者执行 `gh api repos/JayNey/DataCon/environments/internal-lab/deployment-branch-policies` 与 `gh api repos/JayNey/DataCon/rulesets` 确认仅 `main` 允许部署且 `v*` tag 受保护。
2. **S-8（存储配置待维护者设置）**：
   - 维护者需在 GitHub Repository/Environment Variables 配置非 secret 变量 `DATACON_B03_EVIDENCE_DIR`（指向 `datacon-internal` runner 上的持久化目录路径）；未配置时 `b03-internal` 会 fail closed，不会假称 `bundle_verified: true`。

---

## 6. 未在本机验证的内容声明

- **本机未运行/无环境**：本地没有 Docker daemon、没有 `llvm-symbolizer`、无 `55432` PostgreSQL 凭据；`tests/contract/test_wheel.py`（4 个用例）因本地 `.venv` 为 Python 3.14.7 + `uv 0.13.8`（而 `pyproject.toml` 锁定 `uv==0.12.7`）未在本机纳入全量通过判定。上述 `postgres`/`docker`/`asan`/`test_wheel` 全部由 CI run `44264821558` 在 Ubuntu runner 上实际执行并通过。
- **`release.yml` 实测**：未实际触发 `release.yml` 的 `build` / `promote` / `rollback` / `b03` dispatch（`release.yml` 尚未合入 `main`，且无 `internal-lab` 授权 runner/environment），故 `release.yml` 本身、Trivy 镜像扫描与 action pin 在 `release.yml` 中的运行时行为均**未实测**。

---

## 7. 验证命令清单执行结果

1. **代码来源**：`git rev-parse HEAD` = `fe4fb6dbec322d6f0a93ce7a5c69242f6063a2fc`（在 `60a63f9` 之上提交）。
2. **契约 + 静态门**：
   - `PYTHONPATH=src .venv/bin/python -m pytest -q tests/contract/test_release.py tests/contract/test_release_workflow.py tests/contract/test_ci_gates.py tests/contract/test_b04_eval.py` → `122 passed`
   - `PYTHONPATH=src .venv/bin/python -m pytest -q --ignore=tests/contract/test_wheel.py -m "not postgres and not asan"` → `793 passed, 234 deselected`
   - `PYTHONPATH=src .venv/bin/python -m datacon.ci_gates --root .` → `{"ok": true, "errors": [], "checked_markdown": 2, "checked_workflows": 2, "scanned_files": 235}`
   - 分区校验：`total: 1031 groups: {'postgres': 210, 'docker': 18, 'asan': 6, 'contract': 797} errors: []`
3. **postgres 集成测试**：本地无 `DATACON_TEST_DATABASE_URL`；已由 CI run `44264821558` 执行 `postgres: total=210 skipped=0 failures=0 errors=0`。
4. **修复前红**：已于修改生产代码前在 `60a63f9` 直接运行新测试与超时/script 探针记录（见第 4 节）。
5. **gate 探针**：3 个恶意 YAML（`secrets: inherit`、`with:` key 表达式、30 层 alias bomb）在 `0.043s` 内全部被 `check_workflow_security` 拦截。
6. **`run_suite` 脚本**：通过 `test_run_suite_script_respects_both_pytest_and_junit_exit_codes`（fake `uv` 在 `PATH`）验证 `pytest_rc=1` + 合法 XML 退出非零、`pytest_rc=0` + 失败 XML 退出非零、`pytest_rc=0` + 合法 XML 退出 `0`。
7. **CI**：`gh run view 44264821558 --repo JayNey/DataCon` → `status=completed, conclusion=success`；`gh run list --repo JayNey/DataCon --workflow=release.yml --limit 5` → HTTP 404。
