# DataCon

DataCon 是面向授权实验环境的 CVE 复现平台项目。它的目标是让团队在隔离环境中对照运行缺陷版与修复版，并用可离线校验的证据包复核结论。

**项目状态**：MVP 第一批 T01–T02 已合入 `main`；第二批 T03–T04 在 `feat/mvp-supervisor-review` 分支实现。当前提供本地 CLI 的任务提交、查询、Supervisor 计划生成、人工审核与恢复，PostgreSQL 业务记录与 LangGraph 持久化检查点，离线情报 / Git / Tree-sitter 分析，合成 C 案例材料，B03 公开案例准入记录，契约测试和 PR CI。执行范围截至 `READY`；Docker 构建、ASan 回放、判定与证据导出属于 T05–T06。

## 首版范围

1. 通过本地 CLI 提交已登记的 C/C++ 案例，查询任务状态。
2. 从离线公告快照、固定 Git 提交、补丁和源码生成可审核的复现计划。
3. 操作者审核计划后，系统进入 `READY`；T05 在一次性 Docker 容器中用相同 ASan 工具链和测试输入对照运行两个版本。
4. 导出报告和证据包，记录版本、构建环境、输入摘要、运行日志和判定依据。

首版验收包括一个合成双版本案例和一个公开 CVE 案例。真实案例在获授权的实验环境中运行。

## 当前实现（T01–T04）

- **T01 案例与测试基线**：`tests/fixtures/cases/` 提供 B01/B02 的缺陷版、修复版、正常与候选输入、构建配方、依赖快照、预期退出码和预期 ASan 签名。`manifest.json` 固定全部材料摘要；`fixture-repo.bundle` 是包含两个固定提交的只读 Git bundle；`advisory.json` 是离线公告快照；`registry.json` 把案例、材料、仓库和公告关联起来。
- **T02 任务入口**：`src/datacon/contracts.py` 校验请求并计算稳定计划摘要；`src/datacon/cli.py` 实现 `submit`、`status`、`review` 和 `worker`；`migrations/001_create_jobs.sql` 创建任务表并为旧表补列。
- **T03 持久化、Supervisor 与审核**：`migrations/002_workflow.sql` 增量增加计划、审核、尝试、审计和恢复字段，保留既有任务；`src/datacon/state.py` 以 PostgreSQL 业务记录决定状态、审核与租约；`src/datacon/workflow.py` 用 LangGraph 编译 Supervisor，以 `thread_id=job_id` 保存检查点。`worker` 领取 `QUEUED`，生成并冻结计划，置为 `AWAITING_REVIEW`；`review` 在任务、计划摘要、操作者和 24 小时审核时限绑定下写入 `approve|reject`。批准原子地进入 `READY`，拒绝或过期进入 `BLOCKED`，恢复时从业务记录路由。
- **T04 情报、版本与源码分析**：`src/datacon/cases.py` 读取本地案例注册表；`src/datacon/agents/analysis.py` 读取离线公告、校验来源与摘要、解析固定 Git 提交、生成 diff、事实 / 假设和证据引用，并计算稳定计划摘要；`src/datacon/tools/source.py` 用受限 Git 命令和 Tree-sitter 提取目标函数与调用点。模型是可选的类型化端口，默认离线运行，真实 LLM 调用不是本批验收条件。
- 合法 source 请求返回唯一 `job_id` 和 `QUEUED`。结构合法的 binary 请求在提交时归档为 `BLOCKED`，原因码 `UNSUPPORTED_TARGET`，不会进入 Supervisor。省略预算时应用 SRS 默认值。
- 非法 CVE 格式、超出上限的预算、未知字段、重复 JSON 键和其他结构错误返回退出码 `2`，并在连接数据库前拒绝，不产生任务。
- **B03 准入**：`B03-admission.json` / `B03-admission.md` 记录公开候选 `CVE-2019-13224` 的公告、修复提交、许可、离线构建、共享 harness 和 ASan 计划。状态为 `conditional_admission`；真实案例执行与发布验收按任务顺序留到 T05/T08。

## 快速开始

### 依赖

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) 0.12.7（仓库锁定依赖，提交了 `uv.lock`；`pyproject.toml` 的 `required-version` 与 `uv_build==0.12.7` 同 CI 固定的 uv 版本一致）
- PostgreSQL 17
- `git`（读取固定提交与 diff）
- `clang` + `llvm-symbolizer`（仅 B01/B02 的 ASan 合成回放需要）。本地和 CI smoke 使用宿主 clang，版本不锁定；`silkeh/clang:19-bookworm` 固定镜像声明 clang 19.1.7，由 T05 容器回放验证。缺少 `clang` 时相关测试跳过；缺少 `llvm-symbolizer` 时，签名用例在断言错误类型/操作后跳过函数/源码帧断言（CI 会安装 LLVM 并执行该断言）。

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
for migration in migrations/*.sql; do
  docker exec -i datacon-pg psql -U datacon -d datacon < "$migration"
done
```

本机有 `psql` 时也可以逐个执行 `psql "$DATACON_DATABASE_URL" -f "$migration"`。两个迁移都可重复执行；`002` 只增量加列和表，不删除或回填 T01/T02 的任务。

### 3. 提交、生成计划、审核并查询 READY

```bash
export DATACON_OPERATOR_ID=local-reviewer

job=$(uv run datacon submit --request examples/request.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
# {"job_id": "<uuid>", "state": "QUEUED"}

uv run datacon worker --once
# {"processed": 1, "job_id": "<uuid>", "state": "AWAITING_REVIEW", "workflow": "interrupted"}

uv run datacon status "$job"
# 输出 pending_plan：plan_digest、summary、完整 plan、created_at

digest=$(uv run datacon status "$job" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pending_plan"]["plan_digest"])')
uv run datacon review "$job" --plan-digest "$digest" --decision approve
# {"job_id": "<uuid>", "state": "READY", ..., "idempotent": false}

uv run datacon worker --once   # 恢复被审核中断的图，使检查点追上业务状态
uv run datacon status "$job"   # state=READY，review_state.decision=approve
```

`submit`、`worker`、`review` 和 `status` 都是独立进程；状态、计划与审核从 PostgreSQL 读取，检查点只标记调度位置。`datacon worker` 不带 `--once` 时按 `--poll-seconds` 轮询队列。

拒绝、摘要不符和过期的可复制命令见[审核与恢复](#审核与恢复)。

## CLI 与退出码

| 命令 | 行为 |
| --- | --- |
| `datacon submit --request request.json` | 校验并提交，输出 `job_id` 和初始 `state` |
| `datacon status JOB_ID` | 输出状态、阶段、`pending_plan`、`review_state`、原因码、错误和证据引用 |
| `datacon review JOB_ID --plan-digest DIGEST --decision approve\|reject` | 以当前操作者身份写入决议；同一决议幂等，冲突决议返回错误 |
| `datacon worker [--once] [--poll-seconds N]` | 领取队列任务或恢复待审 / 已决任务；重启后读取持久化记录 |
| `datacon export` / `datacon verify-bundle` | T06 实现，本批不可用 |

| 退出码 | 含义 |
| ---: | --- |
| `0` | 命令成功；复现结论通过状态字段返回 |
| `2` | 参数或契约错误；非法请求未写入数据库 |
| `3` | 任务不存在、当前状态 / 权限 / 审核时限阻断操作 |
| `1` | 数据库未配置或数据库操作失败 |

审核命令的失败原因码包括 `PLAN_MISMATCH`、`REVIEW_CONFLICT`、`REVIEW_EXPIRED`、`INVALID_STATE` 和 `JOB_NOT_FOUND`。Supervisor 阻断原因包括 `MATERIAL_MISSING`、`SOURCE_CONFLICT`、`EVIDENCE_INVALID`、`UNSUPPORTED_TARGET`、`DEADLINE_EXCEEDED`、`REVIEW_REJECTED`、`REVIEW_EXPIRED` 和 `PLAN_MISMATCH`。

## 请求契约

请求字段为 `schema_version`、`cve_id`、`target`，可选 `limits`。示例见 `examples/request.json`。

- `schema_version` 必须为整数 `1`。
- `cve_id` 必须匹配 `CVE-YYYY-NNNN`；`target.kind` 枚举为 `source|binary`。
- `target.case_id` 必须关联 `tests/fixtures/cases/registry.json` 中登记的合成案例。当前登记 `fixture-c-parser` 和 `fixture-c-parser-clean`，两者都关联 `CVE-2099-0001`。
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

- `plan_digest`：对规范化字段计算的 `sha256`；`summary`：案例、双版本、修改路径、事实 / 假设数量、输入、预期退出码、ASan 签名、预算、隔离策略和情报摘要；`plan`：完整计划；`created_at`。
- 双版本完整 Git 对象 ID、仓库来源、bundle 与补丁摘要、依赖锁、镜像摘要、构建配方、harness、候选与正常输入。
- `expected_exit`、目标 ASan 签名、请求预算、隔离策略（`network=none`、非 root、只读根文件系统、`cap_drop=ALL`、`no_new_privileges`、seccomp）。
- 情报来源、采集时间、内容摘要与来源 URL 列表。
- `analysis`：diff 摘要、修改路径、Tree-sitter 符号 / 调用点、逐条 `fact|hypothesis`、置信级别和证据引用；`analysis_digest` 绑定该分析。

计划摘要的规范化规则固定为：只包含契约字段；Git 完整对象 ID、`sha256` 摘要、预算、隔离策略、情报和分析摘要均校验；按 key 排序、无多余空白、UTF-8 编码。`tests/contract/test_plan.py` 用固定向量锁定字节串和摘要。

审核记录绑定 `job_id`、`plan_digest`、`reviewer_id`、`decision` 与 `decided_at`；审核时限为计划挂起后的 24 小时。同一操作者对同一计划重复提交同一决议幂等；不同决议或不同操作者返回 `REVIEW_CONFLICT`；摘要不符返回 `PLAN_MISMATCH`，原待审计划保持不变；超时在审核请求或 worker 中记录 `BLOCKED/REVIEW_EXPIRED`。

## Supervisor、恢复与租约

- LangGraph 图是 `prepare → await_review → END`，检查点表由 `langgraph-checkpoint-postgres` 管理，`thread_id` 为 `job_id`。PostgreSQL 业务记录是状态与审核结果的唯一依据；检查点只表示调度位置。
- `worker` 用 `SELECT ... FOR UPDATE SKIP LOCKED` 领取 `QUEUED`、过期 `PREPARING`、未同步的 `AWAITING_REVIEW` / `READY` / `BLOCKED` 任务，增加 `generation` 并写入有期限的租约。旧代次的写回被拒绝。
- 准备阶段固定 `prepare_deadline_at`；计划冻结时固定 `review_deadline_at`；执行期限在 T05 首次执行领取时固定。
- 待审时进程退出：检查点停在 `await_review` 中断，重新启动只读取既有计划，不会生成第二份。
- 审核决议已入库但工作流尚未恢复：`review` 与任务状态在同一事务提交（`READY` 或 `BLOCKED`），检查点仍停在中断；下一次 `worker` 用 `Command(resume=...)` 恢复并同步检查点。计划与审核各只有一份有效记录。
- 工具尝试按 `job_id/stage/step_key/attempt_no/generation` 记录，重复执行不会覆盖新代次；审计事件只追加。

### 审核与恢复

```bash
# 拒绝：BLOCKED / REVIEW_REJECTED，不产生任何 sandbox 工具尝试
uv run datacon review "$job" --plan-digest "$digest" --decision reject

# 摘要不符：退出码 3，PLAN_MISMATCH，原待审计划保持
uv run datacon review "$job" --plan-digest "sha256:$(printf '0%.0s' {1..64})" --decision approve

# 过期：把待审任务时限调到过去后，审核或 worker 记录 BLOCKED / REVIEW_EXPIRED
docker exec -i datacon-pg psql -U datacon -d datacon \
  -c "UPDATE jobs SET review_deadline_at = now() - interval '1 second' WHERE job_id = '$job'"
uv run datacon worker --once
uv run datacon status "$job"
```

## 情报、版本与源码分析

- 案例注册表 `tests/fixtures/cases/registry.json` 指向 `manifest.json`、`fixture-repo.bundle` 和 `advisory.json`。部署时可用 `DATACON_CASE_ROOT` 指向自己的注册目录；默认使用仓库内合成案例。
- 情报只读离线快照：记录 `collected_at`、来源 URL 和快照 SHA-256。快照与注册表 / Git 提交不一致时阻断为 `SOURCE_CONFLICT`；缺失、篡改或摘要不符阻断为 `MATERIAL_MISSING`。
- Git 通过只读 bare 仓库和固定命令模板读取：禁用全局 / 系统 Git 配置、hooks、外部 diff、textconv、子模块拉取和自由 shell。解析 `refs/heads/vulnerable` 与 `refs/heads/fixed` 的完整对象 ID，并核对注册表与材料摘要；diff 只保留修改路径和摘要。
- Tree-sitter C 解析器提取目标函数定义（两版）和 harness 中的候选调用点，记录路径与行号。
- 分析结果的每条 `fact` 必须有可解析的证据引用；`hypothesis` 标注置信级别。伪造引用、事实缺证据或模型输出类型不符阻断为 `EVIDENCE_INVALID`。
- 公告文本、源码注释、diff 和工具输出都只作为数据；分析器只调用 `git.resolve`、`git.diff`、`tree_sitter.extract`，不会因外部文本触发执行工具。
- 模型是可选端口（`AnalysisModel` / `ModelSuggestion`）；默认离线替身不产生建议，测试用替身验证合法假设与伪造引用。真实 LLM 调用不属于本批验收条件。

## 合成案例与 B03

`tests/fixtures/cases/manifest.json` 记录：

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
uv run pytest -q tests/integration/test_fixture_replay.py
```

- `tests/contract/test_request.py`、`test_plan.py`、`test_fixtures.py`：请求、计划摘要、案例材料与 B03 记录。
- `test_agent_contracts.py`：`AgentInput` / `AgentOutput` / `Finding` 的字段、枚举、时间戳、事实证据和错误码。
- `test_analysis.py`：从真实合成材料生成冻结计划、稳定摘要、事实 / 假设、Tree-sitter 提取、缺件 / 冲突 / 篡改 / 二进制 / 伪造引用 / 外部文本注入 / 可选模型替身。
- `tests/integration/test_worker_and_review.py`：真实 PostgreSQL 中的计划冻结、待审查询、批准 / 拒绝 / 摘要不符 / 过期、重复与冲突决议、worker 领取、binary 不被领取。
- `tests/integration/test_recovery.py`：待审退出后重启、审核已入库但图未恢复、旧代次写入失败、检查点 `thread_id=job_id`、计划与审核各一份。
- `tests/integration/test_workflow_migrations.py`：001 旧任务在 002 增量迁移后保留，新表 / 列 / 索引存在，计划与审核每任务唯一，迁移可重复执行。
- `tests/integration/test_fixture_replay.py`：宿主 clang + ASan 的 B01/B02 合成回放，仍是 T01 材料回归，不是 T05 容器隔离验收。

未设置 `DATACON_TEST_DATABASE_URL` 时，PostgreSQL 用例跳过；契约、Agent 和分析用例仍离线运行。

## 目录

```text
src/datacon/
  cli.py                submit / status / review / worker
  contracts.py          请求、分析与计划契约
  cases.py              本地案例注册表与材料校验
  store.py              提交与状态查询入口
  state.py              PostgreSQL 业务状态、审核、租约、尝试、审计
  workflow.py           LangGraph Supervisor 与恢复
  agent_contracts.py    AgentInput / AgentOutput / Finding
  agents/analysis.py    离线情报、版本、diff、事实 / 假设与计划冻结
  tools/source.py       受限 Git 与 Tree-sitter
migrations/             001 任务表、002 工作流增量
examples/               示例请求
tests/contract/         请求、计划、Agent、分析、案例材料与 B03
tests/integration/      真实 PostgreSQL CLI / 审核 / 恢复 / 迁移 / ASan 回放
tests/fixtures/cases/   合成材料、Git bundle、公告快照、案例注册表与 B03
.github/workflows/      PR CI
```

## 范围外

本批不实现 Docker 构建、ASan 回放、判定和证据导出，也不实现二进制逆向、CodeQL、AFL++ / libFuzzer 搜索和 Web 界面。这些分别属于 T05–T08 或扩展路径；`READY` 是本批终点。真实案例只在授权实验环境执行。

## 安全与数据

- `.datacon/`、`.env`、运行产物和证据目录由 `.gitignore` 排除。
- 仓库不包含数据库凭证、真实案例输入、完整诊断或实验日志。CI 的 PostgreSQL service 只在隔离的 runner 上以 `POSTGRES_HOST_AUTH_METHOD=trust` 启动，连接串不含口令；该 trust 配置不得复用于共享或生产数据库。本地 Docker 示例也不提供默认口令，必须显式设置 `DATACON_DB_PASSWORD`。
- 合成案例只用于离线回归；真实案例的准入与使用边界见 B03 记录。公告、源码、diff 和工具输出按不可信输入处理。
- 操作者身份来自 `DATACON_OPERATOR_ID`（未设置时使用本机用户）；它是本地单用户边界，不是多租户身份认证。

## CI

`.github/workflows/ci.yml` 在 Pull Request 和 `main` 分支推送时运行：安装锁定依赖、启动固定 digest 的 PostgreSQL 17、按文件名顺序应用 `migrations/*.sql`、安装宿主 `clang` / LLVM symbolizer / patch，并执行完整 `pytest`（契约、Agent、分析、工作流恢复、真实 PostgreSQL、迁移和合成 ASan 回放）。`uv` 按 `requirements-ci.txt` 中的 wheel hash 安装；构建后端固定为 uv 自带的 `uv_build==0.12.7`，`uv sync --frozen` 不解析或安装 setuptools，CI 还会以 verbose 重装确认实际使用的是内置后端。第三方 Action 固定到完整提交 SHA，工作流只有 `contents: read` 权限。ASan smoke 使用 runner 的宿主 clang，锁定的 clang 19.1.7 镜像留给 T05 验证。

## 开发方式

需求和接口契约先定义可观察的验收条件。编码 Agent 按任务范围实施，通过 TDD 记录失败测试、最小实现和回归结果。CI/CD 计划覆盖契约测试、隔离环境验证和实验版本发布。

## 许可证

[MIT](LICENSE)。
