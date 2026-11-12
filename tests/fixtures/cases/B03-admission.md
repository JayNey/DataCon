# B03 公开案例准入核对

**结论** 选定 `CVE-2019-13224` 作为 B03 候选，准入状态为 `conditional_admission`：来源、许可、双版本、离线构建和同一 harness 条件已核对；真实 ASan 回放与发布验收按任务顺序留到 T05/T08，不在本轮执行。

机器可读记录见 [B03-admission.json](B03-admission.json)。

| 条件 | 结果 | 依据 |
| --- | --- | --- |
| 公开公告 | 通过 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-13224)、[GitHub Advisory GHSA-p5x5-jvwg-8vjr](https://github.com/advisories/GHSA-p5x5-jvwg-8vjr) |
| 明确修复提交 | 通过 | 修复提交 `0f7f61ed1b7b697e283e37bd2d731d0bd57adb55`，包含于 `v6.9.3` |
| 缺陷版本 | 通过 | 固定提交 `c509265c5f6ae7264f7b8a8aae1cfa5fc59d108c`，是修复提交的父提交 |
| 可离线构建 | 通过（设计核对） | 固定源码归档 + CMake + 本地 clang 镜像；构建期不访问外网 |
| 材料许可 | 通过 | 仓库 `COPYING` 为 BSD-2-Clause |
| 两版同一 harness | 通过（设计核对） | 同一 C harness 调用 `onig_new_deluxe()`，仅源码提交不同 |
| ASan 工具链 | 通过（计划） | 固定 clang 19 + AddressSanitizer；预期 `heap-use-after-free` |
| ASan 实际回放 | 待 T05 | 在授权隔离环境执行后冻结具体栈帧、输入摘要和退出码 |

## 使用边界

- 仅提交公开元数据，不提交真实案例输入、构建日志、诊断、凭证或证据包。
- 真实案例只在授权的隔离 Linux 环境执行；本轮 T01/T02 只使用 B01/B02 合成材料。
- 预期结论为 `REPRODUCED`，但 `expected_verdict_status` 在 T05 回放前保持 `pending_t05_replay`。
- T05 回放前，`asan_signature` 的 `status` 保持 `expected_pending_t05_replay`；T08 发布验收必须使用回放后冻结的签名。
