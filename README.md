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
- **T06 验证、报告与证据**：`src/datacon/asan.py` 解析原始 ASan 日志与签名；`src/datacon/verdict.py` 按 SRS 优先级返回 `REPRODUCED`、`NOT_REPRODUCED` 或 `INCONCLUSIVE`；`src/datacon/evidence.py` 写出 `manifest.json`、`report.json`、`report.md`、计划、审核快照、构建产物 / 日志、原始诊断和元数据，并实现 `datacon export` 与离线 `datacon verify-bundle`。`status` 返回 `verdict`、`verdict_reason` 和证据可用性 / 归档错误。
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

本机有 `psql` 时也可以逐个执行 `psql -v ON_ERROR_STOP=1 "$DATACON_DATABASE_URL" -f "$migration"`。六个迁移都可重复执行，但任一语句失败会立即中止并返回非 0；`001`、`002` 只增量加列和表，不删除 T01/T02 的任务；`003` 在不丢数据的前提下把旧 `002` 的 `attempts` 唯一键升级为包含 `generation` 的形状；`004` 只把旧 binary 任务的 `workflow_synced` 回填为 `true`；`005` 只增加 `verdict`、`verdict_reason` 和证据归档字段及约束；`006` 只增加可为空的 `attempts.attempt_token` 与索引，旧任务保持有效且不会被复用为无 provenance 的 journal。`005` / `006` 在事务开头取 `pg_advisory_xact_lock(hashtext('datacon:migrations'))`，并发执行同一迁移会串行等待，不会因 `ADD CONSTRAINT` 竞态失败。

发布说明（迁移锁）：`002` 的 `CREATE INDEX` 会短暂阻塞写入，`003` 的 `ADD CONSTRAINT ... UNIQUE` 需要扫描并重写 `attempts` 的索引，在大型表上会持有强锁。对已有大量数据的部署应在维护窗口执行，或先评估“`CREATE UNIQUE INDEX CONCURRENTLY` + 以现有唯一索引挂接约束”的方案；`CONCURRENTLY` 不能在事务块内运行，也不能与当前按文件整段执行的迁移脚本混用。本仓库的合成数据集很小，不在迁移中自动切换，以免改变可审计的建表顺序。

### 3. 提交、生成计划、审核、执行并导出证据

```bash
export DATACON_OPERATOR_ID=local-reviewer
export DATACON_RUN_ROOT="$PWD/.datacon/runs"
export DATACON_EVIDENCE_ROOT="$PWD/.datacon/evidence"
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
- 执行器先从获批计划物化只读材料：`build.sh`、`harness.c`、双版本源码、依赖锁、补丁、正常 / 候选输入；每个文件写出后重新校验 SHA-256。构建与回放命令均由固定模板生成，目标代码从不在宿主执行。
- 探针容器使用与目标相同的隔离参数，检查：非 root UID、`network=none` 且无可路由的 IPv4 / IPv6 默认路由、无可用的非 loopback 接口、只读根、只读材料、可写 `/work` + 有上限 `/tmp`、PID / 内存 / CPU cgroup 限制（v2 优先，缺失时显式读取 v1；`max` / `unknown` 一律阻断）、`NoNewPrivs=1`、`CapEff=0`、`Seccomp=2` 且 filter 数可证、无宿主 Docker socket。Docker inspect 还核对 `NetworkMode`、`ReadonlyRootfs`、`CapDrop=ALL`、`no-new-privileges`、安全选项中的显式 seccomp profile、PID / 内存 / CPU / tmpfs 总量和**恰好声明过的**只读 bind。任一条件无法落实时阻断，不运行目标。
- seccomp 不依赖 daemon 默认值：仓库内固定 `src/datacon/data/seccomp/default.json`（来自 moby `v27.3.1` 的 Docker 默认 profile，出处与许可见同目录 README），注册表 / 计划记录其 canonical JSON 摘要 `seccomp_profile_digest`；create 命令显式传 `--security-opt seccomp=<profile path>`，inspect 输出中的 profile 重新计算摘要并必须与计划一致。旧计划缺少该摘要时以 `POLICY_DENIED` 阻断，不回退到“默认 profile”。
- 双版本各用新的 `silkeh/clang:19-bookworm@sha256:...` 容器构建；同一镜像、编译器参数（从审核过的构建配方提取）、ASan 选项和依赖摘要。构建产物、构建日志、命令和摘要写入证据；两次构建的镜像、配方和参数不一致时判定为不可比。
- 每个版本先跑一次正常对照，再用同一候选输入分别回放两次，共六次；每次都是新的容器。记录退出码、超时、OOM / 配额事件、原始 stdout / stderr（含 ASan）和解析后的签名；容器停止后显式 `docker rm -f`，启动新代次前按 label 回收遗留容器。
- 尝试按 `(job_id, stage='execute', step_key, attempt_no, generation)` 记录。**每个逻辑步骤跨 generation 最多启动两次**（journal 复用不计入新启动，见下）；超过上限时不再执行目标，以 `RUN_INCOMPLETE` 收敛。工具完成后先把日志、产物和摘要原子写入 `DATACON_RUN_ROOT` 日志，再写 `completed` 尝试。进程在工具结束、结果入库前退出时，新代次只有在以下条件全部满足后才复用旧日志：存在同 `job_id/step/attempt_no/generation` 的数据库 `started`/`completed` 行、journal 的 job/generation/attempt/plan/input/container 字段与该行一致、一次性 `attempt_token` 一致、且 journal HMAC 用 `DATACON_RUN_ROOT` 之外的密钥验证通过；仅凭 run_root 文件不能决定复用。旧代次的 `record_attempt` 仍因 generation 围栏失败。`DATACON_FAULT_AFTER_TOOL=build:vulnerable` 只在 `DATACON_TEST_MODE=1` 时可用，否则 worker 在领取任务前以配置错误退出。

## 判定、报告与证据包（T06）

- `src/datacon/asan.py` 从原始 ASan 日志提取错误类别、`READ/WRITE`、访问大小、故障函数和源码路径；签名匹配支持源码路径后缀。缺帧、截断或不可符号化记录不会晋升为事实。
- `src/datacon/verdict.py` 严格按 SRS 优先级判定：必要回放缺失、正常对照异常、间歇触发、其他崩溃、超时 / 资源耗尽、证据不可比或日志截断 -> `INCONCLUSIVE`；缺陷版两次命中审核签署名且修复版两次干净 -> `REPRODUCED`；两者候选均干净 -> `NOT_REPRODUCED`；修复版仍命中或其余完整组合 -> `INCONCLUSIVE`。退出码、信号或模型建议本身不构成复现证据。
- `report.json` 记录目标、状态、原因、双版本提交、镜像 / 工具链 / 编译参数、预算、种子摘要、逐次回放、判定规则与证据引用；`report.md` 从同一结构渲染。证据目录还包含 `manifest.json`、计划、审核快照、探针、构建产物 / 日志、原始 stdout / stderr 和元数据。原始日志只保存为文件；`report.json`、`metadata/execution.json` 和数据库尝试行只保存摘要、字节数、截断标志与短预览，避免重复放大日志。
- 清单逐个文件记录相对路径、角色、字节数和 SHA-256；校验器拒绝缺失、额外文件、摘要不符、重复条目、绝对路径、父路径、反斜杠、Windows drive / UNC 路径、符号链接和特殊文件。`verify_bundle` 还重新计算计划摘要、要求审核为 `approve` 且绑定同一计划、核对 manifest / report 的 verdict 与 reason，并对 `REPRODUCED` / `NOT_REPRODUCED` / `INCONCLUSIVE` 要求完整的探针、双版本构建和六组回放证据；`BLOCKED` / `FAILED` 允许最小证据集。归档前会先对暂存目录执行同一校验，未通过时任务以 `FAILED/EVIDENCE_WRITE_FAILED` 收敛且不发布证据。
- 注意：上述校验证明的是**证据包内部一致性、完整性和与计划 / 审核的绑定**，不是作者身份、真实性或数字签名。能重写整个证据目录和数据库记录的一方仍可伪造一套自洽材料；本仓库当前不提供签名或外部时间戳。`export` 先校验归档包和数据库中的清单摘要，再复制到新目录并再次校验，不覆盖非空目标。归档写入失败时任务进入 `FAILED/EVIDENCE_WRITE_FAILED`，`status.evidence.error` 保留原因；阻断或中途失败也会尽量保存已有材料。
- 证据包默认写入私有 `DATACON_EVIDENCE_ROOT`（默认 `.datacon/evidence`）；运行日志与工作目录默认在 `DATACON_RUN_ROOT`（默认 `.datacon/runs`）。二者已由 `.gitignore` 排除，不应提交真实案例输入、诊断或证据。

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
- `tests/integration/test_workflow_migrations.py`：001 旧任务在 002 增量迁移后保留，新表 / 列 / 索引存在，计划与审核每任务唯一，迁移可重复执行；003 在不丢数据的前提下把旧 `attempts` 唯一键升级为包含 `generation`；004 把旧 binary 的 `workflow_synced` 回填为 `true` 且可重复执行，worker 的 claim 查询排除 `UNSUPPORTED_TARGET`。
- `tests/contract/test_verdict.py`：ASan 签名解析与 SRS 判定优先级的表驱动用例：正例、正常候选、修复版仍命中、间歇、缺回放、超时 / 资源限制、对照失败、其他崩溃、不可比和日志截断。
- `tests/contract/test_evidence.py`：清单往返、缺失 / 额外 / 改写 / 符号链接 / 绝对、父路径、反斜杠、Windows drive / UNC 路径 / 重复条目 / 畸形清单；语义校验覆盖 manifest / report verdict 与 reason、重新计算计划摘要、审核决定与计划绑定、0/5 与未知 / 重复回放、完整六次回放、`BLOCKED` / `FAILED` 最小证据；导出覆盖 expected digest、源目录在 verify 与 copy 之间被替换、空目标目录、bundle 内目标和复制后复验。
- `tests/contract/test_sandbox_policy.py`：Docker create 参数和 inspect 校验；非 root、断网、只读根、cap-drop、no-new-privileges、显式 seccomp profile 与摘要、CPU / 内存 / PID / tmpfs、bind 白名单，以及 cgroup v1/v2、`max` / `unknown`、网络 links / IPv6 路由和 `NoNewPrivs` / `CapEff` 探针判定；还覆盖 create 后 inspect / 校验失败时删除容器。
- `tests/integration/test_execution.py`：PostgreSQL + 类型化 fake sandbox 分支：`REPRODUCED` / `NOT_REPRODUCED`、探针失败、计划 / 材料漂移、超时和缺证 `INCONCLUSIVE`、归档前校验与失败可见、大日志不重复入库、journal 无 DB provenance / 错误 token / 错误 generation 时拒绝复用、completed attempt 输入摘要不匹配时重跑、跨 generation 尝试上限、ARCHIVING 崩溃后 archive-only 恢复且不启动容器、`material_root` 子目录、旧计划缺 seccomp 摘要阻断、两个 worker 并发 claim READY 只有一个成功、fault 注入的生产保护，以及 `export` / `verify-bundle`。
- `tests/e2e/test_mvp_docker.py`：真实 Linux Docker 的 MVP-01 正例六次回放与证据导出、MVP-02 正常候选、MVP-03 拒绝 / 恢复（工具结束、结果入库前退出）、MVP-04 单控制漂移负例（缺只读根 / root 用户 / bridge 网络 / 缺 no-new-privileges / 缺或 unconfined seccomp / 缺 PID、内存、CPU、tmpfs 上限）、容器清理、篡改和额外文件验包失败。每个负例都断言按 label 无遗留容器。
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
migrations/             001 任务表、002 工作流增量、003 attempts 代次键升级、004 旧 binary 回填、005 判定 / 证据、006 journal provenance token
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
- `DATACON_RUN_ROOT` 下的文件按不可信输入处理：`run_root` 目录仍以 0700 创建并校验所有者，但仅凭其中的 journal / 日志不能触发复用或决定最终 verdict。复用必须同时满足数据库 attempt 行、一次性 token 与 run_root 之外密钥的 HMAC；无法证明时重新执行或 fail closed。
- `DATACON_FAULT_AFTER_TOOL` 是仅供故障注入测试使用的环境变量，会令 worker 在工具日志落盘后、数据库结果写入前退出；它要求同时设置 `DATACON_TEST_MODE=1`，否则 worker 在领取任务前直接以 `INVALID_CONFIGURATION` 退出。不要在生产 worker 上设置。
- 操作者身份来自 `DATACON_OPERATOR_ID`（未设置时使用本机用户）；它是本地单用户边界，不是多租户身份认证。

## CI

`.github/workflows/ci.yml` 在 Pull Request 和 `main` 分支推送时运行：安装锁定依赖、启动固定 digest 的 PostgreSQL 17、按文件名顺序应用 `migrations/*.sql`、安装宿主 `clang` / LLVM symbolizer / patch，并在 pytest 前显式检查 `DATACON_TEST_DATABASE_URL`、这些工具、Docker 和固定 clang 镜像。CI 把契约、PostgreSQL、真实 Docker 隔离 / 合成端到端和 ASan 用例分成四组执行，逐个解析 JUnit 报告，要求每组 `total > 0` 且 `skipped=0`；缺少数据库、clang、llvm-symbolizer、Docker 或镜像时会在测试侧 `fail` 而不是 skip。wheel 冒烟会把构建产物安装进临时 venv，执行 `datacon --help`，断言 `importlib.metadata` 的版本 / 依赖 / `datacon = datacon.cli:main` entry point，并从安装后的 wheel 解析和 `analyze_case` 默认案例。`uv` 按 `requirements-ci.txt` 中的 wheel hash 安装；构建后端固定为 uv 自带的 `uv_build==0.12.7`，`uv sync --frozen` 不解析或安装 setuptools，CI 还会以 verbose 重装确认实际使用的是内置后端。第三方 Action 固定到完整提交 SHA，工作流只有 `contents: read` 权限。真实 Docker 组在一次性 Linux runner 上运行固定镜像探针、双版本构建、六次回放、恢复和验包，不接触真实案例材料。本地未设置 `DATACON_TEST_DATABASE_URL`、缺少 clang 或 Docker 守护进程时仍允许显式 skip；`CI=true` 时不允许。

## 开发方式

需求和接口契约先定义可观察的验收条件。编码 Agent 按任务范围实施，通过 TDD 记录失败测试、最小实现和回归结果。CI/CD 计划覆盖契约测试、隔离环境验证和实验版本发布。

## 许可证

[MIT](LICENSE)。
