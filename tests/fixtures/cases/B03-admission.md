# B03 公开案例准入核对

**结论** 选定 `CVE-2019-13224` 作为 B03 候选，准入状态为 `conditional_admission`：来源、许可、双版本、离线构建和同一 harness 条件已核对；真实 ASan 回放与发布验收由 `datacon.release.run_b03_acceptance` 在授权隔离 Linux 环境执行。

机器可读记录见 [B03-admission.json](B03-admission.json)。

| 条件 | 结果 | 依据 |
| --- | --- | --- |
| 公开公告 | 通过 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-13224)、[GitHub Advisory GHSA-p5x5-jvwg-8vjr](https://github.com/advisories/GHSA-p5x5-jvwg-8vjr) |
| 明确修复提交 | 通过 | 修复提交 `0f7f61ed1b7b697e283e37bd2d731d0bd57adb55`，包含于 `v6.9.3` |
| 缺陷版本 | 通过 | 固定提交 `c509265c5f6ae7264f7b8a8aae1cfa5fc59d108c`，是修复提交的父提交 |
| 可离线构建 | 通过（设计核对） | 固定源码归档 + CMake + 固定 clang 镜像；构建期不访问外网 |
| 材料许可 | 通过 | 仓库 `COPYING` 为 BSD-2-Clause |
| 两版同一 harness | 通过（设计核对） | 同一 C harness 调用 `onig_new_deluxe()`，仅源码提交不同 |
| ASan 工具链 | 通过（计划） | 固定 clang 19.1.7 镜像 + AddressSanitizer；预期 `heap-use-after-free`（T05/T08 回放） |
| ASan 实际回放 | 待授权环境执行 | 在授权隔离环境执行双版本 6 次回放并离线 `verify-bundle` 校验后冻结签名与清单摘要 |

## T08 验收流程与使用边界

- 验收编排入口：`datacon.release.run_b03_acceptance`（执行隔离探针、双版本构建、每版 1 次正常对照 + 2 次候选输入共 6 次回放，得出 `REPRODUCED` 并通过 `datacon.evidence.verify_bundle` 校验）。
- 仓库内仅提交公开元数据、准入核对记录与脱敏摘要契约，不提交真实案例输入、构建日志、完整 ASan 诊断、凭证或证据包实体。
- 预期结论为 `REPRODUCED`，仓库基线在未连接授权 Linux 实验环境实机回放前保持 `expected_verdict_status = pending_t05_replay` 与 `asan_signature.status = expected_pending_t05_replay`。
- `run_b03_acceptance` 会硬拒绝 `pending_t05_replay` / 非 `frozen` 的签名状态；必须由 T05 在授权环境完成回放并冻结签名后，才能用真实 `case_root`、审核人 `review` 和授权 runner 执行验收。
