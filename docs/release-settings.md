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

1. 启用 `main` 分支保护（禁止非审核合入、禁止强推）。
2. 启用 **`v*` Tag Protection**：限制仅维护者可创建、更新或删除 `v*` tag，并严禁将 `v*` tag 指向未合入 `main` 的历史提交（如 `04f45b8`）。

## 维护者验证命令（需仓库管理员/读权限 token）

```bash
# 检查 internal-lab environment 配置（deployment_branch_policy、reviewers）
gh api repos/JayNey/DataCon/environments/internal-lab

# 检查允许部署到 internal-lab 的分支/tag 策略（应仅含 main，不含 v* tag）
gh api repos/JayNey/DataCon/environments/internal-lab/deployment-branch-policies

# 检查 tag protection / rulesets
gh api repos/JayNey/DataCon/rulesets
```

在未确认上述设置生效前，S-2 仅完成代码侧收窄，仍处于“需要维护者人工设置并确认”的阻塞状态。
