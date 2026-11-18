# DataCon 发布环境与仓库保护设置（合并前必检项）

## 为什么必须配置仓库设置（S-2 残余风险说明）

GitHub Actions 在触发 `push`（含 `refs/tags/v*`）或 `workflow_dispatch` 时，会从**被触发 ref 自身包含的 `.github/workflows/release.yml` 版本**加载并执行 workflow。例如 PR #7 历史提交 `04f45b8` 中包含旧版 `release.yml`（该旧版使用 job 级 `DATACON_DATABASE_URL` / `DATACON_RELEASE_APPROVAL` 且缺少 `/compare/main` 校验）。

代码层在当前 head 上收窄 `release.yml` **无法追溯修改或删除历史提交中的旧版 workflow 文件**。如果有人创建指向历史 PR 提交的 `v*` tag，GitHub 仍会按旧文件调度 job。因此，**GitHub Environment 规则与 Tag Protection 是唯一能阻断旧 workflow 接触 `internal-lab` secrets 的控制面**。

## 维护者在 GitHub 仓库 Settings 中必须完成的设置

### 1. Environment `internal-lab`（Settings → Environments → `internal-lab`）

1. **Deployment branches and tags**：选择 **Selected branches and tags**，仅添加分支规则 **`main`**（不要允许 `v*` tag 或任意分支部署到 `internal-lab`）。
2. **Required reviewers**：勾选并添加至少 1 位维护者作为必须审批人。
3. **Environment secrets**：
   - `DATACON_DATABASE_URL`
   - `DATACON_RELEASE_APPROVAL`
   - `DATACON_B03_CASE_ROOT`
   - `DATACON_B03_ADMISSION`
   - `DATACON_B03_REVIEW`
4. **Environment / Repository variables（非 secret）**：
   - `DATACON_B03_EVIDENCE_DIR`：授权 `datacon-internal` runner 上的持久化绝对目录路径（B03 在清理临时目录前会把 bundle 复制到 `<DATACON_B03_EVIDENCE_DIR>/<job_id>/` 并用 `evidence.verify_bundle` 复验；未设置时 `b03-internal` fail closed）。

### 2. 分支与 Tag 保护（Settings → Rules → Rulesets）

1. 启用 `main` 分支保护（禁止非审核合入、禁止强推），并开启 **`Require review from Code Owners`**（配合仓库根目录 [`.github/CODEOWNERS`](../.github/CODEOWNERS) 保护 `.github/`、`src/datacon/ci_gates.py`、`scripts/run_suite.sh`、`tests/contract/test_ci_gates.py` 与 `tests/contract/test_release_workflow.py` 等可信根）。
2. 启用 **`v*` Tag Protection**：限制仅维护者可创建、更新或删除 `v*` tag，并严禁将 `v*` tag 指向未合入 `main` 的历史提交（如 `04f45b8`）。
3. **合入前置硬要求（非替代关系）**：由于历史提交 `04f45b8` 已存在于远端 Git 对象库中，即使采用 squash merge，任何能推送 `v*` tag 的用户仍可将 `v*` tag 指向 `04f45b8` 触发旧版 workflow 并接触 `internal-lab` secrets。因此，**必须在合入 PR #7 前同时完成两项控制面锁定**：
   - `internal-lab` Environment 仅允许 **`main`** 分支部署并开启 Required reviewers；
   - 启用 **`v*` Tag Protection**（仅维护者可创建/更新/删除 `v*` tag）。
   （`squash merge` 仅作为保持 `main` 历史整洁的建议，**不构成** `v*` Tag Protection 或 `internal-lab` 环境锁定的安全替代。）

### 3. 自托管 Runner 与证据卷宿主机前置条件（`datacon-internal`）

`promote-internal`、`rollback-internal` 与 `b03-internal` 三个敏感内部 job 均固定运行在 `[self-hosted, linux, x64, datacon-internal]` runner 上（不使用 `ubuntu-latest`）。在首次 dispatch 前，宿主机与 runner 必须满足以下条件：

1. **Docker daemon 可用**：runner 服务进程所属用户可直接执行 `docker load`、`docker image inspect` 与 `docker run`（包括 `--network host` 访问内网 PostgreSQL）。
2. **宿主机 `evidence_root` 路径与 DB 一致**：宿主机挂载的证据根目录必须为绝对路径，且与数据库 `release_state.evidence_root` 完全一致（若运行 `b03-internal`，`DATACON_B03_EVIDENCE_DIR` 也须为同一套宿主机持久绝对路径）；`archived_bundle_preflight` 与 `ReleaseStore.latest_evidence_bundle` 会按此路径直接校验并挂载到候选容器。
3. **所有路径段禁止 symlink**：`evidence_root` 本身、其所有祖先父目录（例如挂载点父目录），以及归档的 `<job_id>/<generation>` bundle 目录均不得包含任何 symlink；否则 `archived_bundle_preflight`、`persist_b03_evidence_bundle` 与 `latest_evidence_bundle` 会 fail closed 拒绝执行。
4. **容器非 root 用户 `65534:65534` 只读遍历/读取权限**：[控制面 Dockerfile](../Dockerfile) 以 `USER 65534:65534` 运行容器；`promote-internal` 会将归档 bundle 以 `-v <bundle_path>:/bundle:ro` 挂载进容器内执行 `verify-bundle`。`evidence.write_bundle` / `export_bundle` / `execution._archive` / `persist_b03_evidence_bundle` 默认以 `0o755` 目录、`0o644`（或 `0o444`）文件生成共享只读权限；若存在历史 `0o700`/`0o600` 遗留归档包，`archived_bundle_preflight` 会在进容器前直接报错并提示修复权限。
5. **Baseline 与 >30 天历史镜像持久化（可选但强烈建议）**：GitHub Actions `release-candidate-artifacts` 仅保留 30 天，且 `datacon release bootstrap` 初始化的 baseline 镜像可能没有对应的 Actions run。为保障“bootstrap → promote → rollback to baseline”与 >30 天历史版本回滚闭环，请配置 repository/environment variable `DATACON_IMAGE_ARCHIVE_DIR`（runner 上的持久绝对路径，禁止 symlink），并在 bootstrap 时执行：
   ```bash
   docker save -o "$DATACON_IMAGE_ARCHIVE_DIR/${BASELINE_ID#sha256:}.tar" "$BASELINE_IMAGE"
   ```
   （`promote-internal` 在配置了 `DATACON_IMAGE_ARCHIVE_DIR` 时也会自动将验证通过的候选镜像 tar 归档到 `<hex>.tar`；当 `rollback-internal` 不传 `artifact_run_id` 时，会先查 runner 本机 Docker 存储，若不存在则从 `DATACON_IMAGE_ARCHIVE_DIR/<hex>.tar` 加载，并严格校验 `docker image inspect` 不可变 ID 与 `release_events` 持久化审计记录）。

## 维护者验证命令（需仓库管理员/读权限 token）

```bash
# 检查 internal-lab environment 配置（deployment_branch_policy、reviewers）
gh api repos/JayNey/DataCon/environments/internal-lab

# 检查允许部署到 internal-lab 的分支/tag 策略（应仅含 main，不含 v* tag）
gh api repos/JayNey/DataCon/environments/internal-lab/deployment-branch-policies

# 检查 tag protection / rulesets
gh api repos/JayNey/DataCon/rulesets

# 检查 [self-hosted, linux, x64, datacon-internal] 自托管 runner 是否在线
gh api repos/JayNey/DataCon/actions/runners
```

在未确认上述 GitHub 控制面设置生效且至少一台带 `datacon-internal` 标签的 runner 在线前，不得触发 `promote-internal`、`rollback-internal` 或 `b03-internal`。
