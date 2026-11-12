# DataCon

DataCon 是面向授权实验环境的 CVE 复现平台项目。它的目标是让团队在隔离环境中对照运行缺陷版与修复版，并用可离线校验的证据包复核结论。

**项目状态**：首批 MVP 任务 T01–T02 已实现。当前提供本地 CLI 的任务提交与查询、PostgreSQL 持久化、合成 C 案例材料、B03 公开案例准入记录、契约测试和 PR CI。Supervisor、人工审核、LLM 调用、隔离执行与证据导出从后续任务开始。

## 首版范围

1. 通过本地 CLI 提交已登记的 C/C++ 案例，查询任务状态。
2. 根据漏洞公告、固定的 Git 提交和补丁生成复现计划，由操作者审核。
3. 在一次性 Docker 容器中，用相同的 AddressSanitizer（ASan）工具链和测试输入对照运行两个版本。
4. 导出报告和证据包，记录版本、构建环境、输入摘要、运行日志和判定依据。

首版验收包括一个合成双版本案例和一个公开 CVE 案例。真实案例在获授权的实验环境中运行。

## 当前实现（T01–T02）

- **T01 案例与测试基线**：`tests/fixtures/cases/` 提供 B01/B02 的缺陷版、修复版、正常与候选输入、构建配方、依赖快照、预期退出码和预期 ASan 签名。`manifest.json` 固定全部材料摘要。
- **T02 任务入口**：`src/datacon/contracts.py` 校验请求并计算稳定计划摘要；`src/datacon/cli.py` 实现 `datacon submit` 和 `datacon status`；`src/datacon/store.py` 使用 PostgreSQL 保存任务；`migrations/001_create_jobs.sql` 只创建提交和查询所需表。
- 合法 source 请求返回唯一 `job_id` 和 `QUEUED` 状态；结构合法的 binary 请求在提交时归档为 `BLOCKED`，原因码为 `UNSUPPORTED_TARGET`。新 CLI 进程可从数据库查回同一任务。省略预算时应用 SRS 默认值。
- 非法 CVE 格式、超出上限的预算、未知字段、重复 JSON 键和其他结构错误返回退出码 `2`，并在连接数据库前拒绝，不产生任务。
- **B03 准入**：`tests/fixtures/cases/B03-admission.json` 和 `B03-admission.md` 记录公开候选 `CVE-2019-13224` 的公告、修复提交、许可、离线构建、共享 harness 和 ASan 计划。状态为 `conditional_admission`；真实案例执行与发布验收按任务顺序留到 T05/T08，本轮不执行真实案例。

## 快速开始

### 依赖

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) 0.12.7（仓库锁定依赖，提交了 `uv.lock`；`pyproject.toml` 的 `required-version` 与 `uv_build==0.12.7` 同 CI 固定的 uv 版本一致）
- PostgreSQL 17
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

### 2. 安装依赖并建表

```bash
uv sync
docker exec -i datacon-pg psql -U datacon -d datacon < migrations/001_create_jobs.sql
```

本机有 `psql` 时也可以执行 `psql "$DATACON_DATABASE_URL" -f migrations/001_create_jobs.sql`。迁移可重复执行。

### 3. 提交并查询一次任务

```bash
uv run datacon submit --request examples/request.json
# {"job_id": "<uuid>", "state": "QUEUED"}

uv run datacon status <uuid>
# {"job_id": "<uuid>", "state": "QUEUED", "stage": null, "pending_plan": null, ...}
```

`submit` 与 `status` 是两个独立进程；状态从 PostgreSQL 读取，不依赖进程内内存。

## 请求契约

请求字段为 `schema_version`、`cve_id`、`target`，可选 `limits`。示例见 `examples/request.json`。

- `schema_version` 必须为整数 `1`。
- `cve_id` 必须匹配 `CVE-YYYY-NNNN`；`target.kind` 枚举为 `source|binary`。
- `target.case_id` 必须关联本批登记的合成案例。当前登记 `fixture-c-parser` 和 `fixture-c-parser-clean`，两者都关联 `CVE-2099-0001`。
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

请求拒绝未知字段、重复 JSON 键、`NaN`/`Infinity`、非法 UTF-8 和非对象顶层值。合法的 `binary` 请求结构上通过校验，但超出 MVP 范围，提交时直接归档为 `BLOCKED`，原因码为 `UNSUPPORTED_TARGET`；不会停留在 `QUEUED`，也不进入后续 Supervisor 流程。

### 退出码

| 退出码 | 含义 |
| ---: | --- |
| `0` | 命令成功 |
| `2` | 参数或契约错误；非法请求未写入数据库 |
| `3` | 查询的任务不存在 |
| `1` | 数据库未配置或数据库操作失败 |

## 测试

```bash
export DATACON_TEST_DATABASE_URL="$DATACON_DATABASE_URL"
uv run pytest -q
```

测试分层：

```bash
uv run pytest -q tests/contract
uv run pytest -q tests/integration/test_cli.py
uv run pytest -q tests/integration/test_cli_operational.py
uv run pytest -q tests/integration/test_migrations.py
uv run pytest -q tests/integration/test_fixture_replay.py
```

- `tests/contract/` 固定请求校验、默认预算、计划摘要规范化 JSON 与 UTF-8 规则、案例材料摘要和 B03 准入记录。
- `tests/integration/test_cli.py` 使用真实 PostgreSQL，通过子进程验证跨进程提交/查询、唯一任务 ID、默认预算落库，以及非法输入（含 CLI 层的非法 UTF-8、`NaN`、`Infinity`）在连接数据库前被拒绝且无落库副作用。该文件的非法请求用例使用不可达 DSN，若代码尝试连接就会得到退出码 `1`，因此返回 `2` 证明了校验先于连接。未设置 `DATACON_TEST_DATABASE_URL` 时跳过。
- `tests/integration/test_cli_operational.py` 不需要 PostgreSQL，验证未配置数据库和数据库操作失败都返回退出码 `1`。
- `tests/integration/test_migrations.py` 在迁移前插入哨兵任务，重复执行 `001_create_jobs.sql` 后断言该行仍存在且内容不变，验证迁移“不破坏已有任务”。
- `tests/integration/test_fixture_replay.py` 用宿主 `clang` + ASan 编译 B01/B02 两版，验证正常输入、缺陷版命中预期 `heap-buffer-overflow`、修复版和 B02 候选正常退出。错误类型、操作和访问大小始终断言；未安装 `llvm-symbolizer` 时，签名用例在完成这些断言后跳过函数/源码帧断言。它是合成材料回归，不是 T05 的容器隔离验收。

## 计划摘要

`plan_digest` 对计划字段做固定规则计算：只包含契约列出的字段，校验 Git 完整对象 ID、`sha256:<64 hex>` 摘要、签名和完整预算；以键排序、无多余空白、UTF-8 编码的 JSON 作为摘要输入。`tests/contract/test_plan.py` 用固定向量锁定字节串和摘要，字段顺序变化不会改变摘要，材料、提交、预算或策略变化会改变摘要。

## 合成案例与 B03

`tests/fixtures/cases/manifest.json` 记录：

- B01 合成正例：缺陷版对 `inputs/candidate.txt` 触发 `heap-buffer-overflow`（`parse_token`，退出码 `86`），修复版正常；正常输入在两版均输出 `OK`。
- B02 合成反例：`inputs/clean.txt` 未越界，两版均正常退出，预期 `NOT_REPRODUCED`。
- 双版本源码、patch、harness、构建脚本、依赖锁和输入都带 SHA-256 摘要；CI 验证缺失和篡改会被发现。
- `fix.patch` 是 vulnerable 到 fixed 的完整 diff；契约测试会把 patch 应用到 vulnerable 副本，并与 fixed 逐字节比对。

B03 只提交公开元数据，不提交真实案例输入、构建日志、诊断或证据包。准入记录明确 `asan_replay` 仍由 T05 执行并冻结签名；T08 才能做发布验收。

## 目录

```text
src/datacon/          请求契约、PostgreSQL 存储、CLI
migrations/           提交/查询所需数据库迁移
examples/             示例请求
tests/contract/       请求、计划摘要、案例材料与 B03 记录测试
tests/integration/    真实 PostgreSQL CLI 测试与合成 ASan 回放
tests/fixtures/cases/ B01/B02 合成材料与 B03 准入记录
.github/workflows/    PR CI
```

## 范围外

本批不实现 Supervisor、人工审核、LLM 调用、隔离容器执行、判定与证据导出。这些分别属于 T03–T06；真实案例只在授权实验环境执行。

## 安全与数据

- `.datacon/`、`.env`、运行产物和证据目录由 `.gitignore` 排除。
- 仓库不包含数据库凭证、真实案例输入、完整诊断或实验日志。CI 的 PostgreSQL service 只在隔离的 runner 上以 `POSTGRES_HOST_AUTH_METHOD=trust` 启动，连接串不含口令；该 trust 配置不得复用于共享或生产数据库。本地 Docker 示例也不提供默认口令，必须显式设置 `DATACON_DB_PASSWORD`。
- 合成案例只用于离线回归；真实案例的准入与使用边界见 B03 记录。

## CI

`.github/workflows/ci.yml` 在 Pull Request 和 `main` 分支推送时运行：安装锁定依赖、启动固定 digest 的 PostgreSQL 17、应用迁移、安装宿主 `clang`/LLVM symbolizer、运行合成 ASan 回放，并执行完整 `pytest`。`uv` 按 `requirements-ci.txt` 中的 wheel hash 安装；构建后端固定为 uv 自带的 `uv_build==0.12.7`，`uv sync --frozen` 不解析或安装 setuptools，CI 还会以 verbose 重装确认实际使用的是内置后端。第三方 Action 固定到完整提交 SHA，工作流只有 `contents: read` 权限。ASan smoke 使用 runner 的宿主 clang，锁定的 clang 19.1.7 镜像留给 T05 验证。

## 开发方式

需求和接口契约先定义可观察的验收条件。编码 Agent 按任务范围实施，通过 TDD 记录失败测试、最小实现和回归结果。CI/CD 计划覆盖契约测试、隔离环境验证和实验版本发布。

## 许可证

[MIT](LICENSE)。
