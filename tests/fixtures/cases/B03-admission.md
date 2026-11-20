# B03 公开案例准入核对

**结论** 选定 `CVE-2019-13224` 作为 B03 候选，准入状态为 `conditional_admission`。Step 3 固定走 **路线 B**：在授权 lab 上用真实材料完成 4 次回放标定，冻结 ASan 签名与控制输出，再在候选控制面镜像内执行 6 次回放验收并将结果写入 `b03_acceptance` 专用表。路线 A（扩展主流程的多文件构建）**延后**，不作为本次验收的前置条件，见文末。

机器可读记录见 `B03-admission.json`。该记录已由授权 lab 的 T05 calibration 冻结；真实签名来自 4 次真实回放，不是手写值。正式 6 次回放验收仍由 operator 在 `datacon-internal` 执行，并写入 `b03_acceptance`。

| 条件 | 结果 | 依据 |
| --- | --- | --- |
| 公开公告 | 通过 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-13224)、[GitHub Advisory GHSA-p5x5-jvwg-8vjr](https://github.com/advisories/GHSA-p5x5-jvwg-8vjr) |
| 明确修复提交 | 通过 | 修复提交 `0f7f61ed1b7b697e283e37bd2d731d0bd57adb55`，包含于 `v6.9.3` |
| 缺陷版本 | 通过 | 固定提交 `c509265c5f6ae7264f7b8a8aae1cfa5fc59d108c`，是修复提交的父提交 |
| 可离线构建 | 通过（设计核对） | 固定源码归档 + CMake + 固定 clang 镜像；构建期不访问外网 |
| 材料许可 | 通过 | 仓库 `COPYING` 为 BSD-2-Clause |
| 两版同一 harness | 通过（设计核对） | 同一 C harness 调用 `onig_new_deluxe()`，仅源码提交不同 |
| ASan 工具链 | 通过（计划） | 固定 clang 19.1.7 镜像 + AddressSanitizer |
| ASan 实际回放 | 通过（lab calibration） | `scripts/calibrate_b03.py` 4 次真实回放后经 `scripts/freeze_b03_admission.py` 冻结；error=`heap-use-after-free`、operation=`READ`、access_size=1 |

## 当前冻结状态

- Case root：授权 lab 上的 `/srv/datacon/b03-case`（真实材料，不提交仓库）。
- Real ASan signature：`heap-use-after-free` / `READ` / size `1` / `utf16be_mbc_to_code` / `/fixture/vulnerable/src/utf16_be.c`。
- Expected exit：normal `0`、candidate_clean `0`、candidate_asan `86`。
- Expected stdout：normal `OK\n`、candidate_clean `MISMATCH_REJECTED\n`。
- `plan_digest`（最终 frozen admission）：`sha256:a18aef14dc37c088fbc37ea9cb3ba431e15fac91c78ebceb19eb9d44941e964a`。

## Step 3 路线 B 操作顺序（固定）

1. 在授权 lab 上运行 calibration，得到真实 ASan 签名与 4 次回放的 exit/stdout。
2. 用 calibration 冻结 admission，得到一份 frozen admission JSON。
3. 用同一份 JSON 更新仓库 fixture `B03-admission.json` **和** `DATACON_B03_ADMISSION` secret。
4. 用冻结后的 admission 计算 `plan_digest`。
5. 第二位复核者签发 `DATACON_B03_REVIEW`（`plan_digest` 绑定，24 小时内有效）。
6. 在目标数据库应用 `009_b03_acceptance.sql`。
7. 在 `main` 上 dispatch `release.yml`：`run_b03=true` + `artifact_run_id=<release.yml 成功 run>`。

不要调换 4/5/6/7 的顺序；review 过期、candidate 不一致或 009 未应用都会 fail closed。

### 1. 标定（授权 lab，已完成）

```bash
uv run --frozen python scripts/calibrate_b03.py \
  --case-root "<authorized-case-root>" \
  --admission "<pending-admission.json>" \
  --out "<calibration.json>"
```

- 复用 `datacon.release.B03CaseMaterials` 与真实 `DockerSandbox`，对 `vulnerable`/`fixed` 各跑 `normal` + `candidate` 一次，共 4 次。
- 输出 **脱敏 JSON**：`schema_version`、`benchmark_id`、`cve_id`、`toolchain_image_digest`、`versions`、
  `asan_signature{error,operation,access_size,function,source}`、
  `expected_exit{normal,candidate_clean,candidate_asan}`、
  `expected_stdout{normal,candidate_clean}`、`runs[{version,phase,exit_code,stdout_sha256,signature}]`。
- 只写 `--out`；不写数据库、不写 evidence bundle、不打印宿主路径或原始日志。
- 任一回放失败/超时/截断、固定版本出现 ASan、vulnerable candidate 没有完整真实签名，或与 admission 里已写死的 exit/stdout/签名冲突时，直接失败且不产出文件。

### 2. 冻结 admission（已完成）

```bash
uv run --frozen python scripts/freeze_b03_admission.py \
  --admission "<pending-admission.json>" \
  --calibration "<calibration.json>" \
  --out "<frozen-admission.json>"
```

冻结会校验 calibration 与 admission 的 `cve_id`、`vulnerable/fixed` commit、toolchain digest 一致，并写入：

- `asan_signature.status = "frozen"`（五个真实字段全部来自 calibration）；
- `expected_verdict_status = "frozen"`；
- `harness.normal_exit_code` / `harness.candidate_clean_exit_code` / `harness.candidate_asan_exit_code`；
- `harness.expected_stdout`；
- `checks[asan_replay] = {"status": "pass", "evidence": "<脱敏帧与摘要>"}`。

如果 admission 已经冻结且字段不同、`asan_replay` 已有不同 evidence、或出现 `verified`/未知状态，脚本拒绝覆盖。输出前会用 `release._validate_b03_admission` 自检，保证结果可直接被 `prepare_b03_plan` 使用。

### 3. 更新 repo fixture 与 secret

- `tests/fixtures/cases/B03-admission.json` 已替换为 lab 产出的 frozen JSON；仓库只保留脱敏签名、summary 与公开元数据。
- 把**同一份 JSON 文本**写入 `internal-lab` environment secret `DATACON_B03_ADMISSION`。Step 3 的 workflow 直接 `json.loads` 该 secret，不再把 secret 当文件路径。
- `DATACON_B03_CASE_ROOT` 仍是授权 lab 上的真实材料目录（绝对路径），不提交仓库。

### 4. 计算 `plan_digest`

```bash
uv run --frozen python - "<frozen-admission.json>" "<authorized-case-root>" <<'PY'
import json
import pathlib
import sys

from datacon import release

admission = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
materials = release.B03CaseMaterials.load(sys.argv[2])
prepared = release.prepare_b03_plan(
    admission=admission,
    materials=materials,
    normal_input=materials.normal_input,
    candidate_input=materials.candidate_input,
)
print(prepared["plan_digest"])
PY
```

### 5. 第二位复核者签发 `DATACON_B03_REVIEW`

复核者确认 `plan_digest` 对应真实 case root 与冻结 admission 后，签发：

```json
{
  "reviewer_id": "<second-reviewer-id>",
  "decision": "approve",
  "plan_digest": "sha256:<64-hex>",
  "decided_at": "<RFC3339 UTC>"
}
```

写入 `internal-lab` environment secret `DATACON_B03_REVIEW`。`run_b03_acceptance` 会拒绝未来时间、超过 24 小时的 review，以及与 plan 不匹配的 digest。不要提交、打印或落在仓库里。

### 6. 应用 009

```bash
uv run --frozen datacon migrate --migrations-dir migrations
```

或对目标库执行等价的 `state.apply_migrations_dsn`。应用后确认：

```sql
SELECT to_regclass('b03_acceptance');
```

B03 的 `record_b03_acceptance` / `b03_acceptance_for` 在缺表时 fail closed；009 只新增专用表，不改 `release_events` 的 action/status CHECK。

### 7. dispatch

前置：`artifact_run_id` 必须是 `release.yml` 在 `main` 上成功完成、且产物含 `control-plane-image.tar` 与 `release-candidate-manifest.json` 的 run。

```bash
gh workflow run release.yml --ref main \
  -f action=build \
  -f run_b03=true \
  -f artifact_run_id=<release-workflow-run-id>
```

`b03-internal` 会：

- 校验 protected ref、run 的 `release.yml` 来源、`main` head 祖先关系；
- 下载 image tar + RC manifest，`docker load` 后校验 image id == `manifest.control_plane_image_id`；
- 用 `release.canonical_manifest_digest(manifest)` 计算 `candidate_digest`（绝不用 image id 代替）；
- 在候选控制面镜像内以 `docker run --rm --network host --group-add <host-docker-gid>` 运行
  `run_b03_acceptance`，挂载 Docker socket、case root、`DATACON_B03_EVIDENCE_DIR`，同路径 bind mount；
- 成功后调用 `ReleaseStore.record_b03_acceptance(environment="internal-lab", candidate_digest, control_plane_image_id, b03_bundle_manifest_digest, storage_ref, run_id, status="passed")`；
- Actions artifact 只上传脱敏 summary：`candidate_digest`、`b03_manifest_digest`、`storage_ref`、`run_id`；不上传 bundle、路径、输入或日志。

### Lab 宿主机前置条件

- case root 与 evidence dir 必须是不含 symlink 的绝对路径。
- 容器内用户 `65534:65534` 必须能只读遍历 case root；`DATACON_B03_EVIDENCE_DIR` 必须由 `65534` 拥有且可写（`persist_b03_evidence_bundle` 会 chmod 该根目录并创建 `<job_id>/`）。容器与宿主使用同一数值 uid，因此宿主上的持久目录应使用 `chown 65534:65534` + `0755`；不要用 `0700` 或仅 root 可写。
- `/var/run/docker.sock` 必须存在且 runner 用户可访问；job 会把 socket 的 host GID 通过 `--group-add` 传给容器。
- `DATACON_B03_EVIDENCE_DIR` 与数据库 `release_state.evidence_root` 使用同一套宿主机持久路径。

## 路线 A（主流程多文件构建）延后

本次验收**不扩展**主流程的 `prepare/execute` 多文件构建能力。B03 仍通过授权 `case_root` 提供固定材料树，并在候选镜像内直接调用 `run_b03_acceptance`；这是刻意收窄的范围。路线 A（让主工作流原生构建多文件 C 案例、复用同一构建器）记录为后续工作，不阻塞 Step 3 / P0-1 的准入与验收。

## 使用边界

- 仓库只提交公开元数据、准入记录、脱敏 ASan 签名与公开源码摘要契约；不提交真实材料树、构建日志、完整 ASan 诊断、凭证或证据包实体。
- 真实材料树只存在于授权 lab 的 `/srv/datacon/b03-case`，不随仓库分发。
- `scripts/calibrate_b03.py` 与 `scripts/freeze_b03_admission.py` 不写数据库、不写 evidence bundle；真实 6 回放只由 operator 在 `datacon-internal` 上执行，Agent 不得伪造。
- `run_b03_acceptance` 会硬拒绝未冻结的 admission、过期/不匹配的 review、失败 probe/build、缺失材料和不一致输入。
