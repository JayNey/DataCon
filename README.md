# DataCon

DataCon 是面向授权实验环境的 CVE 复现平台项目。它的目标是让团队在隔离环境中对照运行缺陷版与修复版，并用可离线校验的证据包复核结论。

**项目状态**：MVP 第一批 T01–T02、第二批 T03–T04 已合入 `main`；第三批 T05–T06 在 `feat/mvp-sandbox-evidence` 分支实现，并以 PR 审阅。当前提供本地 CLI 的任务提交、查询、Supervisor 计划生成、人工审核与恢复，PostgreSQL 业务记录与 LangGraph 持久化检查点，离线情报 / Git / Tree-sitter 分析，一次性 Linux Docker 隔离构建与 ASan 回放，六次回放判定、可离线校验的证据包和合成案例端到端 CI。B03 公开案例仍只完成准入，真实案例执行与发布验收属于 T07–T08。

## 首版范围

1. 通过本地 CLI 提交已登记的 C/C++ 案例，查询任务状态。
2. 从离线公告快照、固定 Git 提交、补丁和源码生成可审核的复现计划。
3. 操作者审核计划后，系统进入 `READY`；T05 在一次性 Docker 容器中用相同 ASan 工具链和测试输入对照运行两个版本。
4. 导出报告和证据包，记录版本、构建环境、输入摘要、运行日志和判定依据。

首版验收包括一个合成双版本案例和一个公开 CVE 案例。真实案例在获授权的实验环境中运行。

## 当前实现（T01–T06）

- **T01 案例与测试基线**：`src/datacon/data/cases/` 随 wheel 发布 B01/B02 的缺陷版、修复版、正常与候选输入、构建配方、依赖快照、预期退出码和预期 ASan 签名；`tests/fixtures/cases/` 保留同一套测试基线。`manifest.json` 固定全部材料摘要；`fixture-repo.bundle` 是包含两个固定提交的只读 Git bundle；`advisory.json` 是离线公告快照；`registry.json` 把案例、材料、仓库和公告关联起来。
- **T02 任务入口**：`src/datacon/contracts.py` 校验请求并计算稳定计划摘要；`src/datacon/cli.py` 实现 `submit`、`status`、`review` 和 `worker`；`migrations/001_create_jobs.sql` 创建任务表并为旧表补列。
- **T03 持久化、Supervisor 与审核**：`migrations/002_workflow.sql` 增量增加计划、审核、尝试、审计和恢复字段，保留既有任务；`003_attempts_generation.sql` 安全升级旧 `attempts` 唯一键；`004_legacy_binary_sync.sql` 回填旧 binary 任务的 `workflow_synced`。`src/datacon/state.py` 以 PostgreSQL 业务记录决定状态、审核、代次与租约；`src/datacon/workflow.py` 用 LangGraph 编译 Supervisor，以 `thread_id=job_id` 保存检查点。`worker` 领取 `QUEUED`，生成并冻结计划，置为 `AWAITING_REVIEW`；`review` 在任务、计划摘要、操作者和 24 小时审核时限绑定下写入 `approve|reject`。批准原子地进入 `READY`，拒绝或过期进入 `BLOCKED`，恢复时从业务记录路由。审核和过期提交增加 `generation`，旧 worker 无法把 `workflow_synced` 覆盖为 `true`；`freeze_plan`、`ensure_awaiting_review`、`block_job`、`expire_review`、`record_attempt` 和 `finalize_workflow` 只在 generation 与数据库有效租约同时匹配时写入；操作者 `record_review`（批准 / 拒绝 / 过期）不使用 worker 租约，由任务状态、计划摘要和审核时限围栏；成功决议在同一事务内增加 generation 并清空租约。分析或检查点的瞬时基础设施错误按逻辑步骤最多重试一次；`attempts` 在分析执行前先写入 `started` 占位，随后更新为 `completed` 或 `infra_error`；准备时限过期时直接阻断。
- **T04 情报、版本与源码分析**：`src/datacon/cases.py` 读取本地案例注册表；`src/datacon/agents/analysis.py` 读取离线公告、校验来源与摘要、解析固定 Git 提交、生成 diff、事实 / 假设和证据引用，并计算稳定计划摘要；根因 hypothesis 由实际 ASan 签名、源码路径和函数派生，不硬编码 B01 文本；`src/datacon/tools/source.py` 用受限 Git 命令和 Tree-sitter 提取目标函数与调用点。模型是可选的类型化端口，默认离线运行，真实 LLM 调用不是本批验收条件。
- 合法 source 请求返回唯一 `job_id` 和 `QUEUED`。结构合法的 binary 请求在提交时归档为 `BLOCKED`，原因码 `UNSUPPORTED_TARGET`，不会进入 Supervisor。省略预算时应用 SRS 默认值。
- 非法 CVE 格式、超出上限的预算、未知字段、重复 JSON 键和其他结构错误返回退出码 `2`，并在连接数据库前拒绝，不产生任务。
- **T05 隔离执行、构建和测试材料**：`migrations/005_execution_evidence.sql` 增加判定与证据字段；`src/datacon/execution.py` 在 `READY` 后代次领取、复用既有尝试并编排预检 / 探针 / 双版本构建 / 六次回放；`src/datacon/tools/sandbox.py` 以固定镜像构建一次性的非 root、断网、只读根、cap-drop、no-new-privileges、显式固定 seccomp profile 容器，验证并记录 CPU / 内存 / PID / 可写空间 / 超时 / 清理；`started` / `completed` / `infra_error` 尝试、磁盘工具日志和旧代次写回围栏支持工具结束、结果入库前退出的恢复。
- **T06 验证、报告与证据**：`src/datacon/asan.py` 解析原始 ASan 日志与签名；`src/datacon/verdict.py` 按 SRS 优先级返回 `REPRODUCED`、`NOT_REPRODUCED` 或 `INCONCLUSIVE`；`src/datacon/evidence.py` 写出 `manifest.json`、`report.json`、`report.md`、计划、审核快照、构建产物 / 日志、原始诊断和元数据，并实现 `datacon export` 与离线 `datacon verify-bundle`。`status` 返回 `verdict`、`verdict_reason`、`verdict_current` 和证据可用性 / 归档错误。
- **B03 准入**：`B03-admission.json` / `B03-admission.md` 记录公开候选 `CVE-2019-13224` 的公告、修复提交、许可、离线构建、共享 harness 和 ASan 计划。状态为 `conditional_admission`；真实案例执行与发布验收按任务顺序留到 T08。

## 快速开始

### 依赖

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) 0.12.7（仓库锁定依赖，提交了 `uv.lock`；`pyproject.toml` 的 `required-version` 与 `uv_build==0.12.7` 同 CI 固定的 uv 版本一致）
- PostgreSQL 17
- Docker（T05/T06 用一次性 Linux/amd64 容器构建与回放；容器内断网，宿主只需拉取固定镜像）
- `git`（读取固定提交与 diff）
- `silkeh/clang:19-bookworm@sha256:f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f`（clang 19.1.7；镜像内置 `llvm-symbolizer`，ASan 日志带函数 / 源码帧）。本地 Docker 测试在守护进程不可用时显式跳过；CI 缺少 Docker 或镜像时在 pytest 前失败，不允许把隔离门禁换成 skip。
- 宿主 `clang` + `llvm-symbolizer`（仅 `-m asan` 的 B01/B02 材料 smoke 需要；T05/T06 的正式回放使用上述固定容器）。本地缺少时相关用例显式跳过，`CI=true` 时失败。

### 1. 启动 PostgreSQL

已有 PostgreSQL 时直接设置连接串即可；没有时可用 Docker：

```bash
# 本地测试口令必须由环境变量显式提供；未设置时下面的命令会直接失败。
: "${DATACON_DB_PASSWORD:?export DATACON_DB_PASSWORD with a local-only password}"

docker run --rm -d --name datacon-pg \
  -e POSTGRES_USER=datacon \
  -e POSTGRES_PASSWORD="$DATACON_DB_PASSWORD" \
  -e POSTGRES_DB=datacon \
  -p 55432:5432 \
  postgres:17-bookworm@sha256:665dc7b37ac52a17e298511414c21d23ffa4e6a6ef6225b3e5d59c7afb35e994

export DATACON_DATABASE_URL="postgresql://datacon:${DATACON_DB_PASSWORD}@127.0.0.1:55432/datacon"
```

### 2. 安装依赖并按顺序建表

```bash
uv sync
set -euo pipefail
for migration in migrations/*.sql; do
  docker exec -i datacon-pg psql -v ON_ERROR_STOP=1 \
    -U datacon -d datacon < "$migration"
done
```

本机有 `psql` 时也可以逐个执行 `psql -v ON_ERROR_STOP=1 "$DATACON_DATABASE_URL" -f "$migration"`。七个迁移都可重复执行，但任一语句失败会立即中止并返回非 0；`001`、`002` 只增量加列和表，不删除 T01/T02 的任务；`003` 在不丢数据的前提下把旧 `002` 的 `attempts` 唯一键升级为包含 `generation` 的形状；`004` 只把旧 binary 任务的 `workflow_synced` 回填为 `true`；`005` 只增加 `verdict`、`verdict_reason` 和证据归档字段及约束；`006` 只增加可为空的 `attempts.attempt_token` 与索引，旧任务保持有效且不会被复用为无 provenance 的 journal；`007` 先把违反“归档证据不变量”（`evidence_status = 'archived'` 但缺 `evidence_path` / `evidence_digest`，或非 `'archived'` 却残留 `verdict` / `verdict_reason` / `evidence_path` / `evidence_digest`）的旧行清理为 `evidence_status = 'failed'` 且相关列置空，再添加 `jobs_archived_evidence_check` 与 `jobs_failed_evidence_no_verdict_check` 约束。`005` / `006` / `007` 在事务开头取 `pg_advisory_xact_lock(hashtext('datacon:migrations'))`，并发执行同一迁移会串行等待，不会因 `ADD CONSTRAINT` 竞态失败。

发布说明（迁移锁）：`002` 的 `CREATE INDEX` 会短暂阻塞写入，`003` 的 `ADD CONSTRAINT ... UNIQUE` 需要扫描并重写 `attempts` 的索引，在大型表上会持有强锁。对已有大量数据的部署应在维护窗口执行，或先评估“`CREATE UNIQUE INDEX CONCURRENTLY` + 以现有唯一索引挂接约束”的方案；`CONCURRENTLY` 不能在事务块内运行，也不能与当前按文件整段执行的迁移脚本混用。本仓库的合成数据集很小，不在迁移中自动切换，以免改变可审计的建表顺序。

### 3. 提交、生成计划、审核、执行并导出证据

```bash
export DATACON_OPERATOR_ID=local-reviewer
export DATACON_RUN_ROOT="$PWD/.datacon/runs"
export DATACON_EVIDENCE_ROOT="$PWD/.datacon/evidence"
# 当 DATACON_EVIDENCE_ROOT 位于当前工作目录（$PWD）内时，默认兄弟密钥会落在 CWD 内并被安全检查拒绝，
# 因此必须显式把 DATACON_JOURNAL_SECRET_FILE 指到 $PWD 之外（或将 RUN_ROOT / EVIDENCE_ROOT 放在 $PWD 之外）。
export DATACON_JOURNAL_SECRET_FILE="$HOME/.config/datacon/journal-secret"
# 首次运行会按 manifest 中的摘要拉取固定镜像。
docker pull silkeh/clang:19-bookworm@sha256:f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f

job=$(uv run datacon submit --request examples/request.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
# {"job_id": "<uuid>", "state": "QUEUED"}

uv run datacon worker --once
# {"processed": 1, "job_id": "<uuid>", "state": "AWAITING_REVIEW", "workflow": "interrupted"}

uv run datacon status "$job"
# 输出 pending_plan：plan_digest、summary、完整 plan、created_at

digest=$(uv run datacon status "$job" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pending_plan"]["plan_digest"])')
uv run datacon review "$job" --plan-digest "$digest" --decision approve
# {"job_id": "<uuid>", "state": "READY", ..., "idempotent": false}

uv run datacon worker --once
# 恢复审核中断的图、领取 READY、执行隔离构建与六次回放：
# {"processed": 1, "state": "REPRODUCED", "verdict": "REPRODUCED", ...}
uv run datacon status "$job"
# verdict=REPRODUCED；evidence.available=true；evidence.digest=sha256:...

uv run datacon export "$job" --out ./evidence-export
uv run datacon verify-bundle ./evidence-export
```

`submit`、`worker`、`review`、`status`、`export` 和 `verify-bundle` 都是独立进程；状态、计划、审核、判定和证据摘要从 PostgreSQL 读取，检查点只标记调度位置。`datacon worker` 不带 `--once` 时按 `--poll-seconds` 轮询队列；带 `--prepare-only` 时只做工作流 / 审核同步，不领取 `READY` 执行（供 T03/T04 回归和运维检查）。执行器在每次启动容器前重新核对批准、计划摘要、实际材料、策略版本和预算；漂移时阻断而不运行目标。

拒绝、摘要不符和过期的可复制命令见[审核与恢复](#审核与恢复)。

## CLI 与退出码

| 命令 | 行为 |
| --- | --- |
| `datacon submit --request request.json` | 校验并提交，输出 `job_id` 和初始 `state` |
| `datacon status JOB_ID` | 输出状态、阶段、`pending_plan`、`review_state`、原因码、错误和证据引用 |
| `datacon review JOB_ID --plan-digest DIGEST --decision approve\|reject` | 以当前操作者身份写入决议；同一决议幂等，冲突决议返回错误 |
| `datacon worker [--once] [--poll-seconds N] [--prepare-only]` | 领取队列 / 待审 / 已决任务，领取 `READY` 执行或恢复 `RUNNING` / `ARCHIVING`；重启后读取持久化记录。`--prepare-only` 只同步工作流，不执行目标 |
| `datacon export JOB_ID --out DIR` | 校验并复制已归档证据包；不覆盖非空目录 |
| `datacon verify-bundle DIR [--expected-digest SHA256]` | 离线校验清单、文件摘要、路径与符号链接；不访问数据库或网络 |

| 退出码 | 含义 |
| ---: | --- |
| `0` | 命令成功；复现结论通过状态字段返回 |
| `2` | 参数或契约错误；非法请求未写入数据库 |
| `3` | 任务不存在、当前状态 / 权限 / 审核时限阻断操作，或证据不存在 / 校验失败 |
| `1` | 数据库未配置或数据库操作失败 |

审核命令的失败原因码包括 `PLAN_MISMATCH`、`REVIEW_CONFLICT`、`REVIEW_EXPIRED`、`INVALID_STATE` 和 `JOB_NOT_FOUND`；内部一致性错误使用 `REVIEW_ERROR`（退出码 `3`），数据库错误仍使用 `DATABASE_ERROR`（退出码 `1`）。Supervisor 阻断原因包括 `MATERIAL_MISSING`、`SOURCE_CONFLICT`、`EVIDENCE_INVALID`、`UNSUPPORTED_TARGET`、`DEADLINE_EXCEEDED`、`REVIEW_REJECTED`、`REVIEW_EXPIRED`、`PLAN_MISMATCH` 和 `INVALID_REQUEST`（提交后已登记的 case 不再可用或与请求不一致，非分析失败）；分析失败使用 `FAILED/ANALYSIS_ERROR`。

## 请求契约

请求字段为 `schema_version`、`cve_id`、`target`，可选 `limits`。示例见 `examples/request.json`。

- `schema_version` 必须为整数 `1`。
- `cve_id` 必须匹配 `CVE-YYYY-NNNN`；`target.kind` 枚举为 `source|binary`。
- `target.case_id` 必须关联案例注册表中登记的合成案例。源码树中的 `src/datacon/data/cases/registry.json` 会作为 wheel 内的 `datacon/data/cases/registry.json` 发布；`tests/fixtures/cases/registry.json` 是同一测试基线。当前登记 `fixture-c-parser` 和 `fixture-c-parser-clean`，两者都关联 `CVE-2099-0001`。设置 `DATACON_CASE_ROOT` 可覆盖默认目录。
- 预算字段可省略；省略时使用下列 SRS 默认值。每个字段必须是正整数且不得超过对应默认值；`replay_seconds` 不得大于 `execute_seconds`。

| 字段 | 默认值/上限 |
| --- | ---: |
| `prepare_seconds` | 600 |
| `execute_seconds` | 1200 |
| `replay_seconds` | 10 |
| `cpu` | 2 |
| `memory_mib` | 2048 |
| `pids` | 128 |
| `scratch_mib` | 512 |

请求拒绝未知字段、重复 JSON 键、`NaN`/`Infinity`、非法 UTF-8 和非对象顶层值。合法的 `binary` 请求结构上通过校验，但超出 MVP 范围，提交时直接归档为 `BLOCKED`，原因码 `UNSUPPORTED_TARGET`；不进入 Supervisor。

## 计划与审核契约

`status` 的 `pending_plan` 是冻结计划本身，包含：

- `plan_digest`：对规范化字段计算的 `sha256`；`summary`：案例、双版本、修改路径、事实 / 假设数量、输入、预期退出码、`platform`、`toolchain`、`asan_options`、ASan 签名、预算、隔离策略和情报摘要；`plan`：完整计划；`created_at`。`case_config_digest` 绑定案例注册项、材料摘要、镜像、`platform`、`toolchain` 与 `asan_options`，任一变化都会改变计划摘要。
- 双版本完整 Git 对象 ID、仓库来源、bundle 与补丁摘要、依赖锁、镜像摘要、`platform`、`toolchain`、`asan_options`、构建配方、harness、候选与正常输入。T05 从计划的这些字段读取执行环境参数，不需要依赖可变的注册表状态。
- `expected_exit`、目标 ASan 签名（`error`、`operation`、`access_size`、`function`、`source`；`operation` / `access_size` 可选，存在时原样进入计划与摘要）、请求预算、隔离策略（`network=none`、只读根文件系统、`cap_drop=ALL`、`no_new_privileges`）。`user` 只接受非 root 的数字 `uid` 或 `uid:gid`（拒绝 `uid=0`、`gid=0`、`root`、带符号或前导零的形式）；`seccomp` 只接受 `runtime/default` 或 `docker/default`，`unconfined` 和空值都会被拒绝；注册表还必须提供固定 profile 的 `seccomp_profile_digest`，缺失时分析层阻断为 `BLOCKED/MATERIAL_MISSING`，旧计划缺少该字段时执行器以 `POLICY_DENIED` 阻断。计划摘要固定这些规范化后的值，非法 isolation 让计划校验失败并由分析层阻断。
- 情报来源、采集时间、内容摘要与来源 URL 列表。
- `analysis`：diff 摘要、修改路径、Tree-sitter 符号 / 调用点、逐条 `fact|hypothesis`、置信级别和证据引用；`analysis_digest` 绑定该分析。

计划摘要的规范化规则固定为：只包含契约字段；Git 完整对象 ID、`sha256` 摘要、预算、隔离策略、情报和分析摘要均校验；按 key 排序、无多余空白、UTF-8 编码。`tests/contract/test_plan.py` 用固定向量锁定字节串和摘要。

审核记录绑定 `job_id`、`plan_digest`、`reviewer_id`、`decision` 与 `decided_at`；审核时限为计划挂起后的 24 小时。时限按“审核决定实际处理/落库”的数据库时间 `clock_timestamp()` 判断，而不是事务开始时间 `now()`：审核事务即使早于 deadline 启动，只要拿到任务行锁时已经超过 deadline，也会返回 `REVIEW_EXPIRED`，不会进入 `READY`；deadline 恰好等于决定时间时同样按过期处理。`decided_at`、批准时的 `approved_at` 以及 `review_recorded` / `review_expired` 审计的 `created_at` 都显式写入实际数据库时间，不依赖表默认值。同一操作者对同一计划重复提交同一决议幂等；不同决议或不同操作者返回 `REVIEW_CONFLICT`；摘要不符返回 `PLAN_MISMATCH`，原待审计划保持不变。过期检查先于摘要比对，因此“过期 + 错误摘要”仍迁移到 `BLOCKED/REVIEW_EXPIRED`；超时在审核请求或 worker 中记录 `BLOCKED/REVIEW_EXPIRED`。

## Supervisor、恢复与租约

- LangGraph 图是 `prepare → await_review → END`，检查点表由 `langgraph-checkpoint-postgres` 管理，`thread_id` 为 `job_id`。PostgreSQL 业务记录是状态与审核结果的唯一依据；检查点只表示调度位置。
- `worker` 用 `SELECT ... FOR UPDATE SKIP LOCKED` 领取 `QUEUED`、过期 `PREPARING`、未同步的 `AWAITING_REVIEW` / `READY` / `BLOCKED` 任务（`BLOCKED/UNSUPPORTED_TARGET` 除外），增加 `generation` 并写入有期限的租约。默认租约为 600 秒，不小于请求允许的最大 `prepare_seconds`，避免一次合法分析尚未结束就被另一 worker 接管。T05 的 `READY` 执行领取和 `RUNNING` / `ARCHIVING` 接管把租约延长到至少该任务的 `execute_seconds`（接管时按剩余执行期限 + 60 秒），因此 20 分钟执行预算内不会被正常接管；执行器不依赖进程时钟续租。计划冻结前被 `block_job` 阻断的任务，即使还没有 plan，只要 `workflow_synced=false` 且租约过期也会被重新领取并同步；binary 任务在提交时即为 `workflow_synced=true`，`004` 回填旧 binary 的同一标志，且 `claim_next` 排除 `BLOCKED/UNSUPPORTED_TARGET`，因此 binary 不会被领取。`freeze_plan`、`ensure_awaiting_review`、`block_job`、`expire_review`、`record_attempt` 和 `finalize_workflow` 只在 `generation` 与数据库 `clock_timestamp()` 判定仍有效的租约同时匹配时写入；租约比较在取得任务行锁之后进行，因此等待行锁跨过租约/审核/准备 deadline 时不会误用事务开始时间。租约过期后旧 worker 的写回被拒绝，`finalize_workflow` 返回 `False` 且不清空租约。`await_review` 在 `interrupt()` 恢复后仍使用本次领取的 claimed generation；重读到的任务代次已经变化时直接抛出 `StaleGeneration`，不写检查点或业务状态。
- 审核批准 / 拒绝或审核过期在同一事务中增加 `generation` 并清空租约。因此在 `await_review` 读取 `review=None` 后提交的审核会使旧 worker 的 finalize 失败：`workflow_synced` 保持 `false`，下一次 `worker` 以新代次恢复检查点后才置为 `true`。`block_job` 故意保留租约，由同代次的 `finalize_workflow` 清空，保证 `BLOCKED` 任务也能同步。审核冲突、摘要不符、非法状态和过期后的重复尝试以 `review_refused` 追加审计事件，不改变业务状态；首次过期以 `review_expired` 记录，审计 detail 同时保存调用方请求的摘要与冻结计划摘要。
- 准备阶段固定 `prepare_deadline_at`；计划冻结时由数据库 `clock_timestamp() + interval '24 hours'` 固定 `review_deadline_at`，不使用 worker 进程时钟或事务开始时间；执行期限在 T05 首次执行领取时固定，归档预留一成且最多 60 秒。`freeze_plan` 在锁定任务后再次用取得行锁后的数据库实际时间检查准备期限，分析期间或等锁期间过期则不写计划并阻断为 `BLOCKED/DEADLINE_EXCEEDED`。旧数据中 `AWAITING_REVIEW` 但 `review_deadline_at` 为空的记录按“已过期”处理：审核请求返回 `REVIEW_EXPIRED`，worker 可领取并将其置为 `BLOCKED/REVIEW_EXPIRED`，不会因 NULL 参数类型错误或无法领取而永久停住。
- 待审时进程退出：检查点停在 `await_review` 中断，重新启动只读取既有计划，不会生成第二份。
- 审核决议已入库但工作流尚未恢复：`review` 与任务状态在同一事务提交（`READY` 或 `BLOCKED`），检查点仍停在中断；下一次 `worker` 用 `Command(resume=...)` 恢复并同步检查点。计划与审核各只有一份有效记录。resume 不再重复携带 `generation`/`stage`/`state_version` 更新：领取代次经运行配置传入图节点，节点只在成功完成时把代次写回检查点，因此一次 resume 即使重试也只写一次。
- 图在冻结计划后、`finalize_workflow` 前退出且重启时仍待审：恢复的 worker 结束本次调度而不叠加第二个中断，任务保持 `AWAITING_REVIEW` 并完成同步；之后的批准、拒绝或审核过期由业务记录重新置为未同步，下一次 worker 正常收敛，不会出现 `InvalidUpdateError` 或误判 `FAILED`。
- 恢复路径中的可重试数据库/检查点错误最多重试一次；业务记录是权威：已提交的 `READY`、`BLOCKED` 和待审计划不会因为调度或检查点异常被改写为 `FAILED`。重试仍失败的 `READY`/`BLOCKED` 任务保持原状态与 `workflow_synced=false`，租约到期后由新代次收敛；只有 `prepare` 节点内部的分析异常（含分析重试耗尽、分析步骤抛出未预期异常）或草稿/终态 block 写入耗尽才进入 `FAILED/ANALYSIS_ERROR`，`AnalysisBlocked` 按对应原因码进入 `BLOCKED`。逃逸到 `_process_claim` 的检查点、数据库或调度错误不是分析失败：任务保持 `PREPARING`、`workflow_synced=false` 并保留租约，由租约到期后的新代次重试，不会把已经成功并持久化的分析草稿写成终态 `FAILED`。旧数据中 `AWAITING_REVIEW` 但 `review_deadline_at` 为空的记录按已过期处理，审核请求和 worker 都能收敛。`FAILED` 是终态，不参与 `claim_next` 收敛：若进程在 `block_job(FAILED)` 已提交、`finalize_workflow` 之前退出，任务保持 `FAILED` 且 `workflow_synced=false`，但状态、`last_error` 和审计已经是权威结果；不会重新分析，需运维确认后显式重新提交。分析期材料/证据错误走 `AnalysisBlocked` 而不是 `FAILED`。
- 工具尝试按 `job_id/stage/step_key/attempt_no/generation` 记录；同一代次重复执行只更新该代次的行，旧代次不能覆盖新代次，审计事件只追加。`analysis` 步骤在调用 `analyze_case` 前先写入 `status=started` 占位，成功后就地用同一行更新为 `completed` 并保存 plan、plan_digest、summary，失败后更新为 `infra_error`。已提交的 `completed` 行是终态：后续任何非幂等的 `completed` 写入（包括 `infra_error`、`started`、未知状态，或 `completed` 但结果不同）都不能覆盖它，只有相同结果的 `completed` 重写仍幂等；未知状态直接作为契约错误拒绝。状态无法写入时 `record_attempt` 返回 `False`，调用方必须停止该步骤，不能当成成功继续分析或冻结计划。`record_tool` 在工具审计行被拒绝时立即抛 `StaleGeneration`，分析在第一次失败的写回处停止；`plan` 步骤被拒绝时停止审核挂起；workflow 重试标记被拒绝时不记录 `completed` 并跳过 `finalize_workflow`，失败标记被拒绝时不再重试。`AnalysisBlocked` 或租约失效导致的提前停止不会把 `started` 行伪造成 `blocked` / `completed`；该行仍作为可审计的已消费尝试保留。
- 可恢复基础设施错误使用类型化异常，不靠消息字符串匹配：`TransientSourceToolError`（Git 超时、子进程启动/终止或可恢复 I/O）转换为 `RetryableAnalysisError`，Supervisor / 检查点的瞬时错误使用 `RetryableWorkflowError`、`psycopg.OperationalError` / `InterfaceError` 等类型。缺件、摘要不符、来源冲突、契约错误、`AnalysisBlocked`、`StaleGeneration` 和 `PlanConflict` 不重试。
- 每个逻辑步骤最多额外重试一次（attempt 1 → attempt 2），同一执行代次内 `analyze_case` 实际执行最多两次。attempt 序号由已持久化记录（含 `started`）推导；即使记录失败状态的数据库写入本身失败，workflow 级重试也不会把该次执行当作没发生，更不会执行第三次分析。`prepare` 在 `max_attempt >= 2` 或存在 `phase=analysis_draft` 的失败记录时直接 fail closed（`FAILED/ANALYSIS_ERROR`），而不是只靠“没有 completed 草稿”判断。重试前用数据库 `clock_timestamp()` 检查 `prepare_deadline_at`；已过期直接 `BLOCKED/DEADLINE_EXCEEDED`。分析成功后的计划草稿随 `attempts` 持久化；草稿写入失败先做一次有界重试，仍失败则写 `infra_error`（`phase=analysis_draft`）并以 `FAILED/ANALYSIS_ERROR` 关闭；终态 `block_job` 同样做一次有界重试，仍写不进去时保留 `PREPARING` 交给 workflow 重试，重试依靠已持久化的 attempt / draft 标记 fail closed，不会再次执行分析。若服务端已提交 `completed` 草稿而客户端只收到连接错误，重试会读取并复用该草稿，绝不会用 `infra_error` 降级覆盖已提交的 `completed`。workflow 重试成功时补记 `completed`；检查点 `get_state` / `invoke` 的瞬时错误同样最多重试一次。

### 审核与恢复

```bash
# 为每个场景提交独立任务，避免复用上面已批准的 $job / $digest。
review_job=$(uv run datacon submit --request examples/request.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
uv run datacon worker --once
review_digest=$(uv run datacon status "$review_job" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pending_plan"]["plan_digest"])')

# 拒绝：BLOCKED / REVIEW_REJECTED，不产生任何 sandbox 工具尝试
uv run datacon review "$review_job" --plan-digest "$review_digest" --decision reject

# 摘要不符：使用另一个待审任务；退出码 3，PLAN_MISMATCH，原待审计划保持
mismatch_job=$(uv run datacon submit --request examples/request.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
uv run datacon worker --once
uv run datacon review "$mismatch_job" --plan-digest "sha256:$(printf '0%.0s' {1..64})" --decision approve

# 过期：把待审任务时限调到过去后，审核或 worker 记录 BLOCKED / REVIEW_EXPIRED
# 过期检查先于摘要比对，因此这里即使摘要错误也返回 REVIEW_EXPIRED。
expire_job=$(uv run datacon submit --request examples/request.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
uv run datacon worker --once
docker exec -i datacon-pg psql -U datacon -d datacon \
  -c "UPDATE jobs SET review_deadline_at = clock_timestamp() - interval '1 second' WHERE job_id = '$expire_job'"
uv run datacon review "$expire_job" --plan-digest "sha256:$(printf '0%.0s' {1..64})" --decision approve
# 或 uv run datacon worker --once
uv run datacon status "$expire_job"
```

## 隔离构建、回放与恢复（T05）

- `READY` 任务由 `worker` 领取并进入 `RUNNING`；审核记录必须为 `approve` 且计划摘要一致，冻结计划重新计算摘要，案例注册表、实际材料、Git 提交、bundle / patch / 依赖 / harness / 输入摘要、镜像摘要、`platform`、工具链、ASan 选项和策略版本逐项核对。任何漂移在启动容器前阻断为 `PLAN_MISMATCH`、`MATERIAL_MISSING` 或 `POLICY_DENIED`；执行预算不足（含归档预留）阻断为 `DEADLINE_EXCEEDED`。
- 执行器先从获批计划物化只读材料：`build.sh`、`harness.c`、双版本源码、依赖锁、补丁、正常 / 候选输入；每个文件写出后重新校验 SHA-256。容器实际挂载的不是 run root 中的原路径：每次构建 / 回放尝试都会把已校验的整棵材料树、`parser` 和输入复制到 `DATACON_RUN_ROOT` 之外的 staging 目录，复制后再次按计划摘要校验，`sandbox.build` / `sandbox.replay` 只接收 staging 路径；回放还会在创建容器前校验输入摘要。构建结果记录 `staged_materials`（精确等于案例材料键并上两个稳定输入别名，见 T06），归档材料使用本次执行开始时验证过的内存快照，而不是运行结束后重新读取案例目录。物化目录与 staging 都以随机尝试目录隔离，staging 在 `finally` 中删除；物化目录、构建日志、parser 和回放日志都位于 `run/generation-<generation>/...`（journal 位于 `run/steps/<key>/generation-<generation>/...`），写入从受信任的 run root 逐级以 `O_DIRECTORY|O_NOFOLLOW` 打开父目录，open / replace / unlink / chmod 全部相对目录 fd，父目录 fstat 与 lstat 身份必须一致；检查前 symlink、检查后父目录 swap、跨 generation symlink 都会 fail closed（同 UID 并发 rename 的绝对安全仍不在承诺范围内）；回放前还会重新校验 `parser` 字节等于构建记录的 `artifact_digest`，并把该摘要写入回放结果，供离线校验器绑定回构建。构建与回放命令均由固定模板生成，目标代码从不在宿主执行。
- run root 内的 journal / 日志 / parser / 材料一律走有界读取器：以 `os.open(O_RDONLY|O_NOFOLLOW|O_NONBLOCK)` 打开后用 `fstat` 校验普通文件与大小上限（日志 16 MiB、构建产物 128 MiB、材料 64 MiB），再按声明大小读取并检测增长；FIFO、符号链接、特殊文件和超限文件在读取正文前返回 `MATERIAL_MISSING` / `PLAN_MISMATCH` / `RUN_INCOMPLETE` / `EVIDENCE_WRITE_FAILED`。同一逻辑由 `src/datacon/fileio.py` 同时提供给执行器与离线校验器。journal 中的 `files.*` 只接受相对路径，解析后必须仍位于 run root 内；绝对路径、`..` 和解析到 run root 之外的路径一律拒绝。
- run root 的写入路径同样拒绝符号链接：探针使用一次性随机目录（不再使用稳定的 `probe` 名；旧 `probe` 为符号链接时直接 `POLICY_DENIED`），marker 以 `O_NOFOLLOW` 打开后 `fchmod`；`_write_run_file` 以 `O_WRONLY|O_CREAT|O_NOFOLLOW` 打开目标（**不**在 open 时 `O_TRUNC`），`fstat` 确认普通文件且 `st_nlink == 1` 后才 `ftruncate` 并用描述符 `fchmod`/写入；硬链接（`st_nlink != 1`）在截断/写入前以 `HARDLINK` 拒绝，0555 旧文件通过只读描述符 `fchmod` 后重试，不再先 `unlink` 再写；`_write_run_file` / `_write_journal` 在 `mkdir` 之前先解析父目录并做 device/inode containment 检查，`mkdir` 后再复核，父目录符号链接在创建前即被拒绝；`_write_journal` 的临时文件以 `O_CREAT|O_EXCL|O_NOFOLLOW` 创建后 `os.replace`。journal HMAC 密钥（显式 `DATACON_JOURNAL_SECRET_FILE` 或默认兄弟路径）还必须在 `DATACON_EVIDENCE_ROOT` 和 staging root 之外。遇到 `ELOOP`、硬链接、目录或非普通文件一律 fail closed。这些措施消除“检查后替换为符号链接”的写入逃逸，但**不**声称对同 UID 的并发 rename / 竞态绝对安全：同一 UID 仍可写整个 run root，也能替换 run root 内的普通文件；本仓库只保证写入/读取不会跟随符号链接、不会跟随 FIFO 阻塞、且超限前不读取正文。
- 探针容器使用与目标相同的隔离参数，检查：非 root UID、`network=none` 且无可路由的 IPv4 / IPv6 默认路由、无可用的非 loopback 接口、只读根、只读材料、可写 `/work` + 有上限 `/tmp`、PID / 内存 / CPU cgroup 限制（v2 优先，缺失时显式读取 v1；`max` / `unknown` 一律阻断）、`NoNewPrivs=1`、`CapEff=0`、`Seccomp=2` 且 filter 数可证、无宿主 Docker socket。Docker inspect 还核对 `NetworkMode`、`ReadonlyRootfs`、`CapDrop=ALL`、`no-new-privileges`、安全选项中的显式 seccomp profile、PID / 内存 / CPU / tmpfs 总量和**恰好声明过的**只读 bind。任一条件无法落实时阻断，不运行目标。
- seccomp 不依赖 daemon 默认值：仓库内固定 `src/datacon/data/seccomp/default.json`（来自 moby `v27.3.1` 的 Docker 默认 profile，出处与许可见同目录 README），注册表 / 计划记录其 canonical JSON 摘要 `seccomp_profile_digest`；create 命令显式传 `--security-opt seccomp=<profile path>`，inspect 输出中的 profile 重新计算摘要并必须与计划一致。旧计划缺少该摘要时以 `POLICY_DENIED` 阻断，不回退到“默认 profile”。
- 双版本各用新的 `silkeh/clang:19-bookworm@sha256:...` 容器构建；同一镜像、编译器参数（从审核过的构建配方提取）、ASan 选项和依赖摘要。构建产物、构建日志、命令和摘要写入证据；两次构建的镜像、配方和参数不一致时判定为不可比。
- 每个版本先跑一次正常对照，再用同一候选输入分别回放两次，共六次；每次都是新的容器。记录退出码、超时、OOM / 配额事件、原始 stdout / stderr（含 ASan）和解析后的签名；容器停止后显式 `docker rm -f`。容器带 `datacon.job_id` 和 `datacon.generation` label；启动新代次前只回收同 job 中 generation 严格小于当前代次的容器，绝不删除当前或更新代次。回放把 target 作为 PID 1 `exec`，退出码以 `docker wait` 为权威，仅当 `wait` 失败或输出非整数且容器 `State.Running is False`、`State.Status in ("exited", "dead")` 时才使用 `State.ExitCode` 兜底（运行中容器的默认 `ExitCode=0` 绝不采纳，否则置 `exit_code=None`、`status="infra_error"` 并记录 `capture_error`）；stdout / stderr 来自 Docker 的有界 `json-file` 日志，`docker logs` 非零退出时记录显式 `capture_error`、置 `status="infra_error"` 与 `log_truncated=True`，不会把空字节当成干净完成。target 写 `/work/done`、`/work/exit_code` 或 `/work/stdout` 不再缩短采集窗口或决定证据，提前写 `done` 只会让构建产物的 size / digest 与 wrapper 在目标退出后报告的值不符而判 `build_failed`。容器日志使用 `--log-driver json-file --log-opt max-size=32MiB --log-opt max-file=2`（单容器磁盘上限约 64 MiB，证据单流读取上限 `MAX_LOG_BYTES=16 MiB`）：`docker logs` 只读取当前日志，但运行后 `inspect` 会检查 `.LogPath` 的文件大小与 `.1` 轮转兄弟文件（`<LogPath>.1` / `.json.1`），存在 `.1`、当前文件达到 `max-size` 或 `.LogPath` 不可验证时一律置 `log_truncated=True`，防止日志轮转把真实 ASan 诊断挤出观察窗口后仍声称完整。缺失 / 非整数 generation label 的容器只记录 `cleanup_errors` 并停止自动清理，`reclaim_job()` 在 `generation=None` 时直接拒绝，避免误删全部代次；`docker rm -f` 非零退出会重试、上报，并且只有真正删除成功才计数。探针 / 构建 / 回放的 `finally` 清理失败会进入结果 `metadata.cleanup_errors` 或异常 note，不会被静默吞掉。
- 尝试按 `(job_id, stage='execute', step_key, attempt_no, generation)` 记录。**每个逻辑步骤跨 generation 最多启动两次**（journal 复用不计入新启动，见下）；超过上限时不再执行目标，以 `RUN_INCOMPLETE` 收敛。工具完成后先把日志、产物和摘要原子写入 `DATACON_RUN_ROOT` 日志，再写 `completed` 尝试。进程在工具结束、结果入库前退出时，新代次只有在以下条件全部满足后才复用旧日志：存在同 `job_id/step/attempt_no/generation` 的数据库 `started`/`completed` 行、journal 的 job/generation/attempt/plan/input/container 字段与该行一致、一次性 `attempt_token` 一致、且 journal HMAC 用 `DATACON_RUN_ROOT` 之外的密钥验证通过；仅凭 run_root 文件不能决定复用。旧代次的 `record_attempt` 仍因 generation 围栏失败。`DATACON_FAULT_AFTER_TOOL=build:vulnerable` 只在 `DATACON_TEST_MODE=1` 时可用，否则 worker 在领取任务前以配置错误退出。

## 判定、报告与证据包（T06）

- `src/datacon/asan.py` 从原始 ASan 日志提取错误类别、`READ/WRITE`、访问大小、故障函数和源码路径；源码匹配只接受规范化后的精确路径、绝对 frame 路径对已审核相对路径的后缀，或明确的 basename 规则（basename 只匹配裸 basename / 绝对 frame 路径），`totally/elsewhere/parser.c` 这类伪造相对前缀不会匹配。缺帧、截断或不可符号化记录不会晋升为事实。ASan 文本匹配是**可观察行为**的比对，不是作者身份或 sanitizer 真实性证明：能写 stdout/stderr 的目标仍可打印任意文本。
- `src/datacon/verdict.py` 严格按 SRS 优先级判定（README 与代码共用这一顺序）：必要回放缺失 / 不可比 / 日志截断 -> `INCONCLUSIVE`；超时 / 资源耗尽（包括正常对照本身没跑完）-> `INCONCLUSIVE/TIMEOUT|RESOURCE_LIMITED|EVIDENCE_INCOMPLETE`；已完成但退出码 / stdout / ASan 异常的正常对照 -> `INCONCLUSIVE/CONTROL_FAILED`；间歇触发、其他崩溃、修复版仍命中 -> `INCONCLUSIVE`；缺陷版两次命中审核签署名且修复版两次干净 -> `REPRODUCED`；两者候选均干净 -> `NOT_REPRODUCED`；其余完整组合 -> `INCONCLUSIVE`。退出码、信号或模型建议本身不构成复现证据。离线校验器直接调用 `decide_verdict` 重新推导，不再维护第二套优先级。
- `report.json` 记录目标、状态、原因、双版本提交、镜像 / 工具链 / 编译参数、预算、种子摘要、逐次回放、判定规则与证据引用；`report.md` 是 `report.json` 的渲染，不是独立证据。`report.json` 在序列化前写入 `report_markdown_sha256`；生产方 `write_bundle` 与离线校验器都会解析 `report.md` 中恰好一行 `- Verdict: **...**` 和一行 `- Reason: \`...\``，并要求它们与 `report.json.verdict` / `reason_code` 逐字一致。缺行、多行、大小写 / 空格变体、非 UTF-8 或伪造值都会被拒绝；同时更新 `report.md`、`report.json.report_markdown_sha256` 和 manifest 也不能把另一个结论变成合法证据。`report.state` 必须存在且等于 `report.verdict`；`missing` 必须为字符串列表、`error` 必须为文本或 null，`REPRODUCED` / `NOT_REPRODUCED` 要求 `missing` 为空且 `error` 为 null；`schema_version` 必须是整数 `1`。旧包缺少这些字段时以 `INVALID_MANIFEST` fail closed。证据目录还包含 `manifest.json`、计划、审核快照、探针、构建产物 / 日志、原始 stdout / stderr 和元数据。原始日志只保存为文件；`report.json`、`metadata/execution.json` 和数据库尝试行只保存摘要、字节数、截断标志与短预览，避免重复放大日志。`REPRODUCED` / `NOT_REPRODUCED` 要求 `report.rule` 存在、`evidence_complete=true`（若提供），且其 verdict / reason 与顶层一致；`INCONCLUSIVE` 在完整六次回放时同样重推导判定，在中途失败路径（如 `TIMEOUT`、`RUN_INCOMPLETE`、`NOT_COMPARABLE` 尚未集齐探针 / 双构建 / 六回放）允许以 partial `INCONCLUSIVE` 归档（此时 `report.rule` 为 `null`、`missing` 或 `error` 非空、`evidence_complete=false`，校验器不要求完整探针 / 两套构建 / 六组回放，但仍强制核验 `manifest` / `report` / `report.md` 结论绑定、`plan` / `review` 绑定及所有已归档材料、探针、构建或回放摘要）；`BLOCKED` / `FAILED` 允许没有 rule。
- 清单逐个文件记录相对路径、角色、字节数和 SHA-256；校验器拒绝缺失、额外文件、摘要不符、重复条目、绝对路径、父路径、反斜杠、Windows drive / UNC 路径、符号链接和特殊文件。读取前先 `lstat`，只读普通文件，并要求实际大小等于清单声明且不超过单文件 / 总大小上限；超限或增长时不读取正文。`verify_bundle` 还重新计算计划摘要、要求审核为 `approve` 且绑定同一计划，并从 `metadata/case.json` 重算 `case_config_digest`，把每个 `materials/*`（harness、构建配方、依赖、补丁、输入、双版本源码）绑定回计划与物化摘要。对 `REPRODUCED` / `NOT_REPRODUCED` / `INCONCLUSIVE`，它要求恰好两套 `completed` 构建和六组回放，逐项核对 `image_digest`、`build_recipe_digest`、`compile_args`、`artifact_digest`、`log_digest`、`input_digest`、stdout / stderr 的 SHA-256 与字节数、`file_digests`；`staged_materials` 必须精确等于案例材料键并上 `inputs/normal.txt` / `inputs/candidate.txt` 两个稳定别名，别名值必须等于计划输入摘要，缺少、额外或值不符都以 `DIGEST_MISMATCH` 拒绝；每条 replay 的 `artifact_digest` 必须等于对应版本构建产物摘要，缺失为 `INVALID_MANIFEST`、不符为 `DIGEST_MISMATCH`；`metadata/probe.json` 必须是对象、`status` 为 `completed`，`job_id` / `plan_digest` 与 `metadata/execution.json` 一致，`image_digest` 等于计划镜像（否则 `DIGEST_MISMATCH`），`limits` 精确包含 `cpu` / `memory_mib` / `pids` / `scratch_mib` 且等于计划对应值，`checks` 为非空对象并至少包含 `uid` / `seccomp` / `no_new_privs` / `cap_eff` / `cgroup_version`，且分别校验为计划 UID、seccomp 模式 2、`NoNewPrivs=1`、空 capabilities 和 cgroup v1/v2（若存在 `errors` 必须为空），`report.environment.isolation` 必须等于计划 `isolation`，`metadata/execution.json` 中若带 `probe` 则必须与 `metadata/probe.json` 完全一致；完整证据的 `metadata/execution.json` 必须包含 `builds` 和 `replays` 列表，且与 `report` 中的对应列表完全一致，整体省略即拒绝；`completed` build 必须记录 `type(exit_code) is int` 且等于 `0`，字符串 / `True` / 非零都拒绝。`BLOCKED` / `FAILED` 的最小证据集不要求 probe。离线遍历把文件与目录预算分开：`MAX_FILES` 只统计普通文件（不含 `manifest.json`），目录用独立的 `MAX_DIRECTORIES`，总条目上限为两者之和加 manifest；任一独立上限超限立即以 `INVALID_MANIFEST` 中止，不会先遍历完整棵树。并从 `stderr.log` 重新执行 `parse_asan()` 得到签名。verdict / reason 使用 `verdict.py` 中的同一封闭集合，退出码使用与 `verdict.py` 一致的严格整数谓词（`type(value) is int`，`true` / `0.0` / 字符串不算整数），`REPRODUCED` 的两条 vulnerable candidate 必须是计划签名命中、fixed candidate 必须无 ASan 诊断，`NOT_REPRODUCED` 的四条候选必须干净；对完整证据，校验器还用 `plan`、`metadata/case.json`、`builds` 和六组 replay 调用 `decide_verdict` 重新推导，要求与 `report.verdict` / `reason_code` 完全一致，因此与六组回放矛盾的 `OTHER_CRASH` / `INTERMITTENT` / `FIXED_STILL_VULNERABLE` 等 `INCONCLUSIVE` reason 也会被拒绝；`normal` 与 clean candidate 还必须精确匹配 `metadata/case.json` 的 `expected_stdout`。`REPRODUCED` / `NOT_REPRODUCED` 拒绝任何截断日志；只有 `INCONCLUSIVE` 且 reason 为 `NOT_COMPARABLE` / `EVIDENCE_INCOMPLETE` 时允许截断标志，但仍校验文件摘要、字节数、元数据和从截断后 stderr 重新解析的签名。`TIMEOUT` / `RESOURCE_LIMITED` / `EVIDENCE_INCOMPLETE` 的正常对照允许对应的 timeout / resource_limited / infra_error 状态；`CONTROL_FAILED` 要求至少一个正常对照确实异常。`BLOCKED` / `FAILED` 允许最小证据集，`BLOCKED` 的封闭 reason 集合包含 `MATERIAL_IO_ERROR`。归档前会先对暂存目录执行同一校验，未通过时任务以 `FAILED/EVIDENCE_WRITE_FAILED` 收敛且不发布证据。
- 注意：上述校验证明的是**证据包内部一致性、完整性和与计划 / 审核的绑定**，不是作者身份、真实性或数字签名。能重写整个证据目录和数据库记录的一方仍可伪造一套自洽材料；本仓库当前不提供签名或外部时间戳。`export` 先校验归档包和数据库中的清单摘要，再复制到新目录并再次校验，不覆盖非空目标。归档写入失败时任务进入 `FAILED/EVIDENCE_WRITE_FAILED`，`status.evidence.error` 保留原因；计算出的 verdict 不会写入权威字段。数据库保证 `evidence_status == "archived"` ⇔ `evidence_path` 非空且 `evidence_digest` 非空（migration 007 会先清理违反该不变量的旧行，再加 CHECK）；非归档终态显式把 `verdict` / `verdict_reason` / `evidence_path` / `evidence_digest` 清空并写 `evidence_status=failed`，不再用逐列 `COALESCE` 保留旧值。`status()` 只在 `archived AND verdict IS NOT NULL AND evidence_path AND evidence_digest` 时返回 `verdict` / `verdict_reason` 和 `verdict_current=true`，`evidence.available` 使用同一 archived + path + digest 判据；`export` 继续要求 archived + path + digest + manifest digest。归档发布前会再次确认当前 generation / lease，失去租约时返回 `STALE`。证据包按 `DATACON_EVIDENCE_ROOT/<job_id>/generation-<generation>/` 发布，数据库 `evidence_path` 指向该 generation 目录；写路径按 generation scope 打开父目录，跨 generation symlink 会 fail closed。**残余风险**：同一 UID 可在检查与使用之间并发 rename；目录 fd 写不会跟随 swap 后的 symlink，且写入后会再次核对父目录身份，但本仓库不宣称对这类同 UID 并发 rename 绝对安全，也不宣称旧代次在任何竞态下都绝不会影响新代次。发布后若 `finish_execution` 返回 `False` 或抛 `StaleGeneration` / `StateError`，不写终态、尽力删除本代次刚发布的目录（失败只记录、不影响其他 generation），数据库也不会引用它。历史 `evidence/<job_id>` 布局仍可被 export 校验，新增归档只使用 generation 布局。完整证据还会把 `report.case_id` / `cve_id` 绑定到计划，把 `report.budget` 绑定到计划 `limits`，把 `report.review` 绑定到 `review.json`，把 `report.environment.probe` 绑定到 `metadata/probe.json`，并要求完整证据的 `metadata/execution.json` 必须带与 `report` 完全一致的 `builds` / `replays`。阻断或中途失败也会尽量保存已有材料。旧版完整证据包（没有 `metadata/case.json` / `material_patch`、缺少 `report.rule`，或回放记录没有 `artifact_digest` 绑定）在新校验器下会因无法绑定材料和计划 / 构建 / 判定而被拒绝；这是有意的 fail closed，不是兼容性缺陷。
- 证据包默认写入私有 `DATACON_EVIDENCE_ROOT`（默认 `.datacon/evidence`）；运行日志与工作目录默认在 `DATACON_RUN_ROOT`（默认 `.datacon/runs`）。二者已由 `.gitignore` 排除，不应提交真实案例输入、诊断或证据。journal HMAC 密钥（显式 `DATACON_JOURNAL_SECRET_FILE`，或在 `DATACON_EVIDENCE_ROOT` 为 CWD 之外的绝对路径时默认取 `DATACON_EVIDENCE_ROOT` 的父目录下的 `.datacon-journal-secret`）、`DATACON_EVIDENCE_ROOT`、staging 根以及**当前工作目录（CWD）**都必须在 run root 之外：相对 `DATACON_EVIDENCE_ROOT`（或指向 `$PWD/...` 的路径）不再推导默认兄弟密钥，而是直接 `EVIDENCE_WRITE_FAILED`，因为默认兄弟密钥 `<EVIDENCE_ROOT>/../.datacon-journal-secret` 会落在 CWD 内，同 UID 的 CWD 写者可以读取该密钥并伪造 journal；显式或默认密钥路径落在 CWD 内同样拒绝，创建后还会重新检查最终 inode 的位置 / 普通文件 / 所有者 / 权限。当 `CWD="/"`（文件系统根）时，任何绝对路径都位于 CWD 之下，无法定义 CWD 之外的密钥路径，系统会拒绝并给出专门的修复提示（要求切换到非根工作目录并将 `DATACON_JOURNAL_SECRET_FILE` 设在该目录之外）。生产或本地快速开始若把证据目录放在 `$PWD` 下，必须显式设置 CWD 之外的 `DATACON_JOURNAL_SECRET_FILE`（例如 `$HOME/.config/datacon/journal-secret`），或把 `DATACON_EVIDENCE_ROOT` 指到 CWD 之外的绝对路径。检查对目标路径已存在的最深祖先用 `os.stat` 的 `(st_dev, st_ino)` 与 run root 比较，因此 `target == run_root`、run root 是 target 的祖先、以及仅大小写或 NFC/NFD 不同的同一目录都会被拒绝；目标尚不存在时向上找到最深存在祖先再比较，并额外做大小写折叠 + NFC 规范化的分量比较，覆盖尚未创建的大小写变体。`os.stat` 解析失败或祖先不可读时 fail closed。在 Linux 上还会解析 `/proc/self/mountinfo`：对 target 与 run root 找到包含它们的 mount，按 mount root + 相对路径重建同一设备上的物理路径并比较；若 target 的 mount root 位于 run root 物理路径之下（例如 `/mnt/bind` 绑定自 `/data/runs/child`，而 evidence root 为 `/mnt/bind/evidence`）则拒绝；设备号不同**不**构成证明：若 run root 下存在同设备号的 mount（例如嵌套的 different-device bind），或 target mount 的 source 位于 run root 之下，仍拒绝，只有不同设备且 run root 下没有该设备 mount 的无关文件系统才允许。同一 mount point 的 overmount 通过 `parent_id` 链确定最上层（唯一根、唯一叶、覆盖全部条目），不再使用 `max(mount_id)`；重复 `mount_id`、链分叉 / 环 / 不完整或行序歧义时 `_mount_point_for` 返回 `None`，调用方 fail closed。仍检查 target 祖先 mount point 上的每一条 overmount entry，不依赖 mountinfo 行序。mountinfo 无法解析或无法证明时 fail closed；Linux 上 `/proc/self/mountinfo` 缺失直接 fail closed，只有非 Linux 平台才跳过该检查。伪文件系统（例如 `nsfs` 的 root 为 `net:[...]`）没有可比较的路径：不作为 target 祖先时忽略，作为祖先时 fail closed。**限制**：在非 Linux 平台没有 mountinfo，只能使用上述用户态路径 / 身份检查；在既不做大小写折叠也不做 Unicode 规范化、且调用者使用不同字符串的文件系统上，只能依赖保守的规范化字符串比较；同一 UID 的并发 rename / 竞态仍可能在检查与使用之间改变路径含义，因此本仓库不宣称对该类并发或异常文件系统绝对安全，也不宣称 mountinfo 检查等价于内核级 mount namespace。staging 根默认是 `DATACON_EVIDENCE_ROOT` 父目录下的 `.datacon-staging`，也可用 `DATACON_STAGING_ROOT` 显式指定；它必须是真实目录（拒绝符号链接），根目录保持 0700，每次尝试的子目录才允许非 root 容器读取。违反时在探针 / 构建 / 回放前以 `FAILED/EVIDENCE_WRITE_FAILED` 失败，不创建任何目标容器。

## 情报、版本与源码分析

- 默认案例注册表来自 `src/datacon/data/cases/registry.json`，以 wheel 内的 `datacon/data/cases/registry.json` 发布，并指向同目录的 `manifest.json`、`fixture-repo.bundle` 和 `advisory.json`；`tests/fixtures/cases/` 是测试基线镜像。部署时可用 `DATACON_CASE_ROOT` 指向自己的注册目录；安装后的 wheel 不设置该变量也能使用默认合成案例。
- 情报只读离线快照：记录 `collected_at`、来源 URL 和快照 SHA-256。快照与注册表 / Git 提交不一致时阻断为 `SOURCE_CONFLICT`；缺失、篡改或摘要不符阻断为 `MATERIAL_MISSING`。清单结构错误（缺少或类型错误的 `cases`、`versions`、`harness`、`asan_signature`、`materials`、`inputs`、`expected_exit` 等）也由 `cases.py` 在选定案例时校验并阻断为 `MATERIAL_MISSING`，不会落到不可领取的 `FAILED/ANALYSIS_ERROR`；已提交任务仍按“任务 → `BLOCKED`”收敛。`registry.json` / `manifest.json` / `advisory.json` 的 `schema_version` 必须是整数 `1`，`true`、`1.0` 和字符串 `"1"` 都被拒绝。
- 案例材料路径统一按 POSIX 相对路径校验：拒绝反斜杠、绝对路径、`..`、任何空白（空格 / tab / CR / LF）和控制字符；`harness`、`build_recipe`、`dependencies`、`versions`、`materials`、`inputs`、`repository`（bundle / source_path / patch）和 `advisory.path` 走同一规则。`asan_signature.error` / `function` / `source` 各有 512 字符上限；可选的 `operation` 只接受 `READ` / `WRITE`（大小写敏感），`access_size` 只接受 1..2^31-1 的整数，超限或类型错误阻断为 `MATERIAL_MISSING`。符号链接循环、解析时的 `RuntimeError` / `OSError` 和权限错误同样映射为 `MATERIAL_MISSING`；只有真正的瞬时 I/O 才分类为可重试错误。读取前会检查 registry / manifest / advisory 的 1 MiB 上限、单材料的 64 MiB 上限，Git blob 先用 `cat-file -s` 查大小再读取。
- Git 通过只读 bare 仓库和固定命令模板读取：禁用全局 / 系统 Git 配置、hooks、外部 diff、textconv、子模块拉取和自由 shell；执行前清空 `GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_*`、`GIT_CONFIG_VALUE_*`、`GIT_OBJECT_DIRECTORY`、`GIT_ALTERNATE_OBJECT_DIRECTORIES`、`GIT_SSH_COMMAND`、`GIT_ASKPASS`、`GIT_DIR`、`GIT_WORK_TREE` 和 `GIT_INDEX_FILE`，并设置 `GIT_ATTR_NOSYSTEM=1`。解析 `refs/heads/vulnerable` 与 `refs/heads/fixed` 的完整对象 ID；`manifest["versions"]` 指向的缺陷版 / 修复版源码材料也会按材料清单读取和校验摘要，并与 Git blob 逐字节比对，删除或篡改任一源码文件立即阻断。diff 只保留修改路径和摘要；固定的 `fix.patch` 去掉传输头后必须与 Git diff 逐字节一致，仅有相同增删行数但内容不同的补丁阻断为 `SOURCE_CONFLICT`。
- Tree-sitter C 解析器提取目标函数定义（两版）和 `manifest["harness"]` 指向的实际 harness 文件中的候选调用点，记录真实路径与行号。
- 分析结果的每条 `fact` 和 `hypothesis` 都必须有可解析的证据引用，`hypothesis` 另需置信级别；证据引用会按 `git:commit`、`git:blob`、`git:diff`、`intel`、`material` 和 `source/<文件路径>#L<行号>` 逐项解析，而不是只做白名单成员检查：`git:blob` 必须存在于该提交的树中，`git:diff` 必须指向两个固定提交间的实际修改路径，`source/` 必须对应案例目录中存在的文件且行号在文件范围内，`material/` 与 `intel/` 必须绑定已读取的材料摘要。harness 的证据引用使用 `manifest["harness"]` 的实际路径。伪造引用、任一 finding 缺证据或模型输出类型不符阻断为 `EVIDENCE_INVALID`。
- 确定性 finding 只陈述可测量事实：diff 增删行数、两版函数定义行号、harness 实际调用行和公告提交。根因 hypothesis 由实际 `asan_signature.error`、`source_path` 和 `function` 派生，不再包含只适用于 B01 的 `string terminator` / `four-byte allocation` / 固定 `heap-buffer-overflow` 文本；换案例或修改签名会改变或移除该 hypothesis。
- 计划自身携带 `asan_options`、`platform` 和 `toolchain`，并由 `case_config_digest` 与计划摘要绑定；修改任一固定字段都会改变计划摘要，批准后不能静默漂移。
- 公告文本、源码注释、diff 和工具输出都只作为数据；分析器只调用 `git.resolve`、`git.diff`、`tree_sitter.extract`，不会因外部文本触发执行工具。
- 模型是可选端口（`AnalysisModel` / `ModelSuggestion`）；默认离线替身不产生建议。模型只能提出 `hypothesis`，`fact` 只能由确定性分析产生：即使证据引用合法，模型返回 `fact` 也会被拒绝并阻断为 `EVIDENCE_INVALID`。模型 findings 最多 64 条、总字符数最多 64 KiB，单条 statement / evidence ref 仍受 2000 / 512 字符上限约束。真实 LLM 调用不属于本批验收条件，接入前必须保持该边界。

## 合成案例与 B03

`src/datacon/data/cases/manifest.json` 是随 wheel 发布的默认清单，`tests/fixtures/cases/manifest.json` 是测试基线镜像。两者记录：

- B01 合成正例：缺陷版对 `inputs/candidate.txt` 触发 `heap-buffer-overflow`（`parse_token`，退出码 `86`），修复版正常；正常输入在两版均输出 `OK`。
- B02 合成反例：`inputs/clean.txt` 未越界，两版均正常退出，预期 `NOT_REPRODUCED`。
- 双版本源码、patch、harness、构建脚本、依赖锁和输入都带 SHA-256 摘要；CI 验证缺失和篡改会被发现。
- `fix.patch` 是 vulnerable 到 fixed 的完整 diff；契约测试会把 patch 应用到 vulnerable 副本，并与 fixed 逐字节比对。
- `registry.json` 额外固定 Git bundle、两个提交、公告快照和隔离策略；`advisory.json` 只含合成公告和 `.invalid` 域名，不会发起网络请求。

B03 只提交公开元数据，不提交真实案例输入、构建日志、诊断或证据包。准入记录明确 `asan_replay` 仍由 T05 执行并冻结签名；T08 才能做发布验收。

## 测试

```bash
export DATACON_TEST_DATABASE_URL="$DATACON_DATABASE_URL"
uv run pytest -q
```

分层命令：

```bash
uv run pytest -q tests/contract
uv run pytest -q tests/integration/test_cli.py
uv run pytest -q tests/integration/test_cli_operational.py
uv run pytest -q tests/integration/test_migrations.py
uv run pytest -q tests/integration/test_workflow_migrations.py
uv run pytest -q tests/integration/test_worker_and_review.py
uv run pytest -q tests/integration/test_recovery.py
uv run pytest -q tests/integration/test_audit.py
uv run pytest -q tests/integration/test_finalize_crash_recovery.py
uv run pytest -q tests/integration/test_resume_retry.py
uv run pytest -q tests/integration/test_prepare_deadlines.py
uv run pytest -q tests/integration/test_retry.py
uv run pytest -q tests/integration/test_fixture_replay.py
uv run pytest -q tests/contract/test_wheel.py
uv run pytest -q tests/integration/test_execution.py
uv run pytest -q -m docker tests/e2e/test_mvp_docker.py
```

T05/T06 的真实 Linux 门禁是 `-m docker`：使用固定 clang 镜像、真实隔离探针、双版本构建、六次 ASan 回放、故障注入恢复、导出与篡改校验。没有 Docker 时该组显式跳过；`CI=true` 时缺少 Docker 直接失败。

- `tests/contract/test_request.py`、`test_plan.py`、`test_fixtures.py`：请求、计划摘要、案例材料与 B03 记录。
- `test_agent_contracts.py`：`AgentInput` / `AgentOutput` / `Finding` 的字段、枚举、时间戳、事实与假设的证据要求、可解析引用和错误码。
- `test_analysis.py`：从真实合成材料生成冻结计划、稳定摘要、事实 / 假设、Tree-sitter 提取、缺件 / 冲突 / 篡改 / 二进制 / 伪造引用 / 外部文本注入 / 可选模型替身；并覆盖源码材料删除与篡改、harness 改名后的实际证据路径、签名变化后的 hypothesis、`asan_options` / `platform` / `toolchain` 摘要绑定、不可解析 ref（缺文件、越界行、缺失 Git 路径、未知材料 / 情报摘要）、文件范围内有效源码行、缺证据假设、Git 超时分类、删除 `versions` / `harness` / `asan_signature` 以及错误类型的 `cases` / `versions` / `materials` / `inputs` / `expected_exit`、非 UTF-8 的 registry / manifest / Git 路径、非对象 `isolation` 时阻断为 `AnalysisBlocked(MATERIAL_MISSING)`，以及公告、源码注释、diff 和模型上下文的注入不改变 deterministic facts。
- `tests/contract/test_source_limits.py`：Git 子进程的硬上限回归。真实生成超过 `MAX_DIFF_BYTES` 的临时仓库并断言 `GitRepository.diff` 快速抛出 `SourceToolError`；用小上限验证 `ls-tree` 与 `git diff --name-only` 的字节上限、`analyze_case` 将超限映射为 `MATERIAL_MISSING`；并通过 fake `Popen` 断言 stdout 超限会 kill 进程、停止读取，超时仍分类为 `TransientSourceToolError`。不存在“先 capture 全部 stdout 再检查上限”的路径。
- `tests/contract/test_wheel.py`：`uv build --wheel` 后既解压检查默认 / 自定义案例注册表与全部打包数据，也在临时 venv 中真实安装 wheel（依赖由锁定项目环境通过 `PYTHONPATH` 提供），断言 `datacon --help`、`importlib.metadata` 的版本 / 依赖 / `datacon = datacon.cli:main` entry point，并从安装后的 wheel 解析默认案例、真实调用 `analyze_case` 生成计划与 findings。构建配置漏掉 bundle、entry point 或 METADATA 被破坏时，测试会失败；解压 + `PYTHONPATH` 不再被当作“安装成功”。
- `tests/integration/test_worker_and_review.py`：真实 PostgreSQL 中的计划冻结、待审查询、批准 / 拒绝 / 摘要不符 / 过期（含“过期 + 错误摘要”）、重复与冲突决议、worker 领取、binary 不被领取、过期后下一次 worker 同步；错误类型的 `manifest["cases"]` 在 `submit` 阶段 exit 2、在 worker 阶段阻断为 `MATERIAL_MISSING`；`review_deadline_at` 为空的旧 `AWAITING_REVIEW` 记录由审核请求或 worker 收敛为 `BLOCKED/REVIEW_EXPIRED`。
- `tests/integration/test_audit.py`：断言 claim、plan_frozen、review_recorded、review_expired、workflow_synchronized 审计事件及其 detail；摘要不符/冲突审核追加 `review_refused` 且不改变待审计划，过期审核审计同时记录请求摘要和冻结计划摘要。
- `tests/integration/test_recovery.py`：待审退出后重启、审核已入库但图未恢复、审核在 `await_review` 窗口提交时旧 worker 不能 finalize、租约过期 / 新代次接管后的写回拒绝（含 `expire_review` 必须有当前代次的有效租约，操作者审核过期路径不受租约影响）、`attempts` 按代次保留历史、阻断后 finalize、计划冻结前 `BLOCKED` 且在 finalize 前退出后的领取与同步、双连接单领取、两个完整 worker 的租约接管收敛（一个计划、无 `FAILED` / `InvalidUpdateError`、检查点仍对应新代次的待审状态）、检查点 `thread_id=job_id`、计划与审核各一份。
- `tests/integration/test_finalize_crash_recovery.py`：冻结计划后、finalize 前退出时，重启仍待审以及随后批准 / 拒绝 / 审核过期的收敛；检查点可读、无第二个中断、无 `FAILED`，旧代次 finalize 仍被拒绝。
- `tests/integration/test_resume_retry.py`：待审、已批准、已拒绝和 B1 crash-before-finalize 后夹一次可重试 DB 读取错误恢复；连续两次失败时 `READY`/`BLOCKED` 不被覆盖为 `FAILED`、保持 `workflow_synced=false` 并由租约过期后的新代次收敛；断言无 `InvalidUpdateError`、检查点可读且代次与业务记录一致。
- `tests/integration/test_prepare_deadlines.py`：`freeze_plan` 与 `ensure_awaiting_review` 的 `review_deadline_at - now()` 都由 SQL 级断言验证约为 24 小时，并有静态 AST 防护断言 deadline SQL 使用数据库实际时间 `clock_timestamp()`（拒绝事务开始 `now()`），且 `state.py` 不调用 `datetime.now()` / `time.time` / `time.monotonic`；同时检查 `INSERT INTO reviews`、批准更新和审计插入显式写入 `clock_timestamp()`。实现若改回进程时钟或事务时钟，静态防护会失败。另有默认租约不小于最大 `prepare_seconds` 的断言，以及分析期间准备期限过期时不写计划并阻断。
- `tests/integration/test_review_deadline_race.py`：真实双连接并发回归。一个连接持有任务行锁，审核 / 过期 / 计划冻结在 deadline 前启动并在行锁上等待；持锁方在等待期间把 deadline 移到现在之后，跨过 deadline 后释放。断言审核返回 `REVIEW_EXPIRED`、任务为 `BLOCKED/REVIEW_EXPIRED`、`reviews` 为 0；批准时 `decided_at`、`approved_at` 和 `review_recorded` 审计时间都不早于锁释放时间；deadline 等于决定时间按过期处理；`expire_review` 和 `freeze_plan` 在等锁跨过各自 deadline 时也不会误判为未过期。`expire_review` 的租约 / 代次围栏仍由 `test_recovery.py` 覆盖。
- `tests/integration/test_retry.py`：瞬时分析错误重试一次后成功、持续瞬时错误只重试一次后 `FAILED`、非瞬时 `AnalysisBlocked` 不重试、重试前准备时限过期直接 `DEADLINE_EXCEEDED`、检查点瞬时错误重试一次；workflow 级重试复用已持久化分析草稿且保留 `infra_error` 审计记录；草稿写入失败一次时有界重试并复用草稿、连续失败时 fail closed 且不出现第三次分析；分析前 `started` 占位使 `infra_error` 写入失败后仍按 attempt 2 重试、两次失败即 fail closed，草稿与 `block_job` 同时失败、或 `block_job` 始终写不进去时也不会出现第三次分析（后者保留 `PREPARING`）；服务端已提交的 `completed` 草稿不会被 `infra_error` 覆盖；`record_attempt` 返回 `False` 时停止分析（工具审计行、计划行、workflow 成功 / 失败标记分别覆盖）、不 finalize 且不把任务改写成 `FAILED`；plan 行被拒绝时计划已经冻结，但不再挂起审核，下一代次复用该计划并收敛；已提交 `completed` 行拒绝降级、不同结果的 completed 重写和未知状态；analysis 后 freeze 前退出时旧代次 `attempts` 保留、旧代次写回被拒绝、新代次重新分析并冻结唯一计划；逃逸到 `_process_claim` 的持续 freeze / checkpoint 读取错误保持 `PREPARING`、保留租约且不写 `FAILED`，下一代次恢复并冻结计划。
- `tests/integration/test_state_fence.py`：真实 PostgreSQL 上的 generation/lease 围栏：`begin_execution` 在活动代次上延长租约、旧代次与过期租约抛 `StaleGeneration`；`mark_archiving` 延长归档租约，`assert_archive_fence` 对当前代次成功并再次延长、对 `generation + 1` 与过期租约拒绝且不复活过期租约。
- `tests/integration/test_workflow_migrations.py`：001 旧任务在 002 增量迁移后保留，新表 / 列 / 索引存在，计划与审核每任务唯一，迁移可重复执行；003 在不丢数据的前提下把旧 `attempts` 唯一键升级为包含 `generation`；004 把旧 binary 的 `workflow_synced` 回填为 `true` 且可重复执行，worker 的 claim 查询排除 `UNSUPPORTED_TARGET`。
- `tests/contract/test_verdict.py`：ASan 签名解析与 SRS 判定优先级的表驱动用例：正例、正常候选、修复版仍命中、间歇、缺回放、超时 / 资源限制、对照失败、其他崩溃、不可比和日志截断。
- `tests/contract/test_evidence.py`：清单往返、缺失 / 额外 / 改写 / 符号链接 / 绝对、父路径、反斜杠、Windows drive / UNC 路径 / 重复条目 / 畸形清单；语义校验覆盖 manifest / report verdict 与 reason、重新计算计划摘要、审核决定与计划绑定、0/5 与未知 / 重复回放、完整六次回放、`BLOCKED` / `FAILED` 最小证据、probe 的镜像 / 预算 / 安全项 / 执行元数据绑定、report isolation 绑定；读取硬化覆盖 FIFO 快速失败、禁止 `Path.open` / `read_bytes` 的 monkeypatch 以及目录项上限；导出覆盖 expected digest、源目录在 verify 与 copy 之间被替换、空目标目录、bundle 内目标和复制后复验。
- `tests/contract/test_sandbox_policy.py`：Docker create 参数和 inspect 校验；非 root、断网、只读根、cap-drop、no-new-privileges、显式 seccomp profile 与摘要、CPU / 内存 / PID / tmpfs、bind 白名单，以及 cgroup v1/v2、`max` / `unknown`、网络 links / IPv6 路由和 `NoNewPrivs` / `CapEff` 探针判定；还覆盖 create 后 inspect / 校验失败时删除容器、探针拒绝旧 `probe` 符号链接且不写外部目录、`_write_run_file` / `_write_journal` 的符号链接拒绝与 0555 旧文件替换，以及 fake mountinfo 的 bind-mount 后代 containment 判定。
- `tests/integration/test_execution.py`：PostgreSQL + 类型化 fake sandbox 分支：`REPRODUCED` / `NOT_REPRODUCED`、探针失败、计划 / 材料漂移、超时和缺证 `INCONCLUSIVE`、归档前校验与失败可见且首次归档失败时 verdict 为空、归档失败后 `status.verdict` 为 `None`、`verdict_current=false`，数据库行也清空旧 verdict / path / digest 并写 `evidence_status=failed`、`finish_execution` 返回 `False` 时所有恢复/失败分支返回 `STALE` 且不写终态、BLOCKED reload 复用调用方 `run_root` 而不把 bundle 写进可写 run root、大日志不重复入库、journal 无 DB provenance / 错误 token / 错误 generation 时拒绝复用、completed attempt 输入摘要不匹配时重跑、跨 generation 尝试上限、ARCHIVING 崩溃后 archive-only 恢复且不启动容器、archive-only 拒绝输入摘要或计划不匹配的 completed result、构建配方 / parser 物化后篡改被阻断、代次化工作路径、journal 密钥位于 run root 内或证据目录嵌套时在容器前失败、`material_root` 子目录、旧计划缺 seccomp 摘要阻断、staging 根位于 run root 内 / 是符号链接时在容器前失败、构建与回放只挂载 run root 之外的 staging 副本、两个 worker 并发 claim READY 只有一个成功、fault 注入的生产保护，以及 `export` / `verify-bundle`。
- `tests/e2e/test_mvp_docker.py`：真实 Linux Docker 的 MVP-01 正例六次回放与证据导出、MVP-02 正常候选、MVP-03 拒绝 / 恢复（工具结束、结果入库前退出）、MVP-04 单控制漂移负例（缺只读根 / root 用户 / bridge 网络 / 缺 no-new-privileges / 缺或 unconfined seccomp / 缺 PID、内存、CPU、tmpfs 上限）、容器清理、篡改和额外文件验包失败；另以真实 `DockerSandbox(..., generation=...)` 创建三个代次的容器，用 `docker inspect` 断言 `datacon.job_id` / `datacon.generation` label，并验证 `reclaim_job()` 只删除严格更旧的代次、保留当前 / 更新代次。每个负例都断言按 label 无遗留容器。
- `tests/integration/test_fixture_replay.py`：宿主 clang + ASan 的 B01/B02 合成回放，仍是 T01 材料回归，不是 T05 容器隔离验收。

本地未设置 `DATACON_TEST_DATABASE_URL` 时，PostgreSQL 用例显式跳过；契约、Agent 和分析用例仍离线运行。`CI=true` 时缺少数据库会直接失败，而不是跳过。

## 目录

```text
src/datacon/
  cli.py                submit / status / review / worker / export / verify-bundle
  contracts.py          请求、分析与计划契约
  cases.py              本地案例注册表与材料校验
  store.py              提交与状态查询入口
  state.py              PostgreSQL 业务状态、审核、租约、执行、尝试、审计
  workflow.py           LangGraph Supervisor、恢复与 READY 执行入口
  execution.py          T05 预检、物化、构建 / 回放编排、恢复与归档
  verdict.py            SRS 判定优先级
  asan.py               原始 ASan 日志解析与签名匹配
  evidence.py           证据包写入、离线校验与导出
  agent_contracts.py    AgentInput / AgentOutput / Finding
  agents/analysis.py    离线情报、版本、diff、事实 / 假设与计划冻结
  tools/source.py       受限 Git 与 Tree-sitter
  tools/sandbox.py      一次性 Docker 隔离探针、构建与回放
  data/cases/           wheel 默认案例注册表与合成材料
  data/seccomp/         固定 seccomp profile（计划记录其 canonical 摘要）
migrations/             001 任务表、002 工作流增量、003 attempts 代次键升级、004 旧 binary 回填、005 判定 / 证据、006 journal provenance token、007 归档证据不变量修复与 CHECK
examples/               示例请求
tests/contract/         请求、计划、Agent、分析、判定、证据、沙箱策略、wheel 与案例材料 / B03
tests/integration/      真实 PostgreSQL CLI / 审核 / 恢复 / 重试 / 迁移 / 执行 / ASan 回放
tests/e2e/              真实 Docker 的 MVP-01 至 MVP-04
tests/fixtures/cases/   测试基线镜像（合成材料、Git bundle、公告、注册表与 B03）
.github/workflows/      PR CI
```

## 范围外

T07–T08 仍不包含在本批：真实公开 CVE 的发布验收、控制面镜像 / 工具链镜像发布、SBOM 与镜像扫描、按摘要晋级与回滚演练留在后续任务。本批也不实现二进制逆向、CodeQL、AFL++ / libFuzzer 搜索和 Web 界面。真实案例只在授权实验环境执行。

## 安全与数据

- `.datacon/`、`.env`、运行产物和证据目录由 `.gitignore` 排除。
- 仓库不包含数据库凭证、真实案例输入、完整诊断或实验日志。CI 的 PostgreSQL service 只在隔离的 runner 上以 `POSTGRES_HOST_AUTH_METHOD=trust` 启动，连接串不含口令；该 trust 配置不得复用于共享或生产数据库。本地 Docker 示例也不提供默认口令，必须显式设置 `DATACON_DB_PASSWORD`。
- 合成案例只用于离线回归；真实案例的准入与使用边界见 B03 记录。公告、源码、diff 和工具输出按不可信输入处理。
- 目标容器使用 `--network none`、非 root、只读根、`cap-drop ALL`、`no-new-privileges`、显式固定 seccomp profile，仅挂载计划声明的只读材料和有上限的 tmpfs；凭证、控制面数据库连接和 Docker socket 不进入容器。探针失败时不执行目标，任务以 `POLICY_DENIED` 阻断。
- `DATACON_RUN_ROOT` 下的文件按不可信输入处理：`run_root` 目录仍以 0700 创建并校验所有者，但仅凭其中的 journal / 日志不能触发复用或决定最终 verdict。目标容器挂载的字节来自 run root 之外的 staging 副本，因此“只能写 run root”的攻击者无法在摘要检查后替换实际执行的源码、配方、parser 或输入。残余风险仍然存在：与执行器同一 UID、可写整个文件系统的一方可以篡改 staging（以及数据库中同 UID 可写的内容）；本仓库没有对 staging 使用单独 UID、mount namespace 或内核级只读句柄，因此不宣称对该场景绝对安全。复用必须同时满足数据库 attempt 行、一次性 token 与 run_root 之外密钥的 HMAC；无法证明时重新执行或 fail closed。
- `DATACON_FAULT_AFTER_TOOL` 是仅供故障注入测试使用的环境变量，会令 worker 在工具日志落盘后、数据库结果写入前退出；它要求同时设置 `DATACON_TEST_MODE=1`，否则 worker 在领取任务前直接以 `INVALID_CONFIGURATION` 退出。不要在生产 worker 上设置。
- 操作者身份来自 `DATACON_OPERATOR_ID`（未设置时使用本机用户）；它是本地单用户边界，不是多租户身份认证。

## CI

`.github/workflows/ci.yml` 在 Pull Request 和 `main` 分支推送时运行：安装锁定依赖、启动固定 digest 的 PostgreSQL 17、按文件名顺序应用 `migrations/*.sql`、安装宿主 `clang` / LLVM symbolizer / patch，并在 pytest 前显式检查 `DATACON_TEST_DATABASE_URL`、这些工具、Docker 和固定 clang 镜像。CI 把契约、PostgreSQL、真实 Docker 隔离 / 合成端到端和 ASan 用例分成四组执行，逐个解析 JUnit 报告，要求每组 `total > 0` 且 `skipped=0`；缺少数据库、clang、llvm-symbolizer、Docker 或镜像时会在测试侧 `fail` 而不是 skip。wheel 冒烟会把构建产物安装进临时 venv，执行 `datacon --help`，断言 `importlib.metadata` 的版本 / 依赖 / `datacon = datacon.cli:main` entry point，并从安装后的 wheel 解析和 `analyze_case` 默认案例。`uv` 按 `requirements-ci.txt` 中的 wheel hash 安装；构建后端固定为 uv 自带的 `uv_build==0.12.7`，`uv sync --frozen` 不解析或安装 setuptools，CI 还会以 verbose 重装确认实际使用的是内置后端。第三方 Action 固定到完整提交 SHA，工作流只有 `contents: read` 权限。真实 Docker 组在一次性 Linux runner 上运行固定镜像探针、双版本构建、六次回放、恢复和验包，不接触真实案例材料。本地未设置 `DATACON_TEST_DATABASE_URL`、缺少 clang 或 Docker 守护进程时仍允许显式 skip；`CI=true` 时不允许。

## 开发方式

需求和接口契约先定义可观察的验收条件。编码 Agent 按任务范围实施，通过 TDD 记录失败测试、最小实现和回归结果。CI/CD 计划覆盖契约测试、隔离环境验证和实验版本发布。

## 许可证

[MIT](LICENSE)。
