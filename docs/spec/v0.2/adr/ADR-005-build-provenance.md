# ADR-005 构建溯源与可比性

**Status** Accepted  
**Date** 2026-11-21

## Context

v0.1 要求两版使用相同的工具链、镜像、harness、依赖、编译参数与运行参数，并把 build recipe 摘要写入计划。当前实现从 recipe 中提取第一条含 `clang` 的行的参数作为记录，但“recipe 里写了什么”不等于“编译器实际收到什么”：CMake 会追加工具链参数，Make 可能通过隐式规则改写 `CC` 或 `CFLAGS`，shell 配方可以 `exec` 任意命令。

如果只比较 recipe 文本，两版可能在不同生效参数下构建却被判为可比；如果完全相信构建日志的自由文本，又无法结构化对账。v0.2 需要把构建输入结构化，并把“声明参数”和“生效参数”分开核对。

当前仓库的合成案例使用 shell 配方直接调用 `clang`，这属于 legacy 形态；它可以用经审核的日志作为核对面，但不能因此把任意 shell 脚本都视为可比。CMake 与 Make 的核对面必须来自构建工具本身，而不是配方作者的自述。

参数顺序本身也是语义：`-I a -I b` 与 `-I b -I a` 的搜索顺序不同，不能因为“集合相同”就判为可比。v0.2 因此要求保留顺序并对两版做有序序列比较。

## Decision

1. **统一 BuildSpec**。构建输入使用 `BuildSpec`，`kind` 限定为 `cmake`、`make` 或 `shell`。字段只有 `kind`、`configure`（仅 cmake）、`build`、`install`（可选）、`env`、`outputs`、`declared_compile_flags`，以及 shell 专属的 `shell_recipe_digest`、`shell_face_digest`、`shell_face_review`。删除 `make_env`：Make 的 `CC` shim 通过 `env.CC` 注入，`env` 是唯一的构建环境来源。plan 另显式列出归一化后的 `compile_flags`；两者必须一致，且都进入 `plan_digest`。
2. **固定模板注入**。构建命令由工具执行器用固定模板和参数数组拼装，不接受自由 shell。`shell` 配方属于 legacy：可以继续运行已审核的固定脚本，但必须单独审核其核对面，默认不构成可比性证据。
3. **shell 核对面与配方摘要分离**。`shell_recipe_digest` 只表示配方文本摘要，不是核对面；`shell_face_digest` 是案例注册表预审基线核对面（已做路径/时间戳归一化）的 SHA-256，由 `shell_face_review` 记录审核人、审核时间与面类型。冻结阶段校验两者非空，构建阶段对实际构建日志走同一归一化后比对摘要；三种构建系统的核对面原文以 `build_provenance` 角色按固定文件名（`compile_commands.json`、`cc-shim.log`、`shell-face.log`，见[接口契约增量](../interface-contract-delta.md)第 8 节）归档，不能只留配方摘要。
4. **生效参数核对面**。CMake 读取构建目录的 `compile_commands.json`；Make 使用 `env.CC` 指向的 `CC` shim，由 shim 记录每次调用的编译器与参数；shell legacy 必须提供经审核的日志核对面。没有核对面时，在冻结计划阶段返回 `BUILD_PROVENANCE_MISSING`，不允许“先构建再看”。
5. **归一化规则**。保留原始顺序，不做整体排序，也不按 `-D` 名称重排；绝对路径改为相对仓库根；去掉仅包裹整个参数的外层引号；连续空白压成单空格。连写/分写等价收敛为封闭 7 项集合 `{-I, -L, -l, -D, -U, -isystem, -include}`（短选项统一连写单 token、长选项统一双 token 分写，规范形态见[接口契约增量](../interface-contract-delta.md)第 5 节），只合并单个选项与其参数，不改变选项之间的顺序。`declared_compile_flags` 与生效参数在比较前都调用**同一**归一化函数，不允许只归一化一侧。重复 `-I` 保留首次出现；`-L`、`-l`、`-include`、`-isystem` 不去重、不重排；`-I a -I b` 与 `-I b -I a` 仍必须不相等。归一化实现必须与 plan 摘要使用同一版本。
6. **多编译单元聚合与可比性判据**。多 `.c` 编译单元从 `compile_commands.json` 或 `cc-shim.log` 中过滤仅编译目标源码的命令（按仓库相对源文件路径升序确定性排序，排除纯链接命令与编译器名/`-c`/`-o <obj>`/源文件本身），记录按文件映射及用于全局声明核对的扁平生效标志集合（完整规则见[接口契约增量](../interface-contract-delta.md)第 5 节）。对每一版，声明参数必须是生效参数的多重集子集；两版共同编译单元归一化后的生效序列必须**逐编译单元有序严格相等**（长度、顺序与逐项值都相同）。判据不是“两版声明相等”，也不是“recipe 文本相等”。任一条不满足即失败关闭。
7. **顺序反例**。`-I a -I b` 与 `-I b -I a` 归一化后仍不相等，两版按此对比必须返回 `BUILD_PROVENANCE_MISSING`；即使两者作为集合相同，也不能判为可比。该反例同时写入接口契约第 5 节，作为实现与测试的固定向量。
8. **两阶段失败**。冻结计划阶段缺少核对面或 BuildSpec 无法产生可信核对面时返回 `BUILD_PROVENANCE_MISSING`；构建阶段发现声明未生效、顺序不等或两版生效不等时同样返回该码，并保留已产生的构建日志与差异摘要。不得降级为 `INCONCLUSIVE` 继续回放。
9. **工具链边界**。固定镜像已有 cmake、make、autoconf、automake 与 libFuzzer；缺少 pkg-config、libtool、ninja、git。Oniguruma 类案例不需要新镜像；只有确实需要缺失工具的案例才引入工具链镜像 v2，并按案例固定摘要。guided 的 fuzz 镜像默认就是同一固定工具链镜像，`fuzz_image_digest` 与构建镜像一致；只有显式审批的独立 fuzz 镜像才允许不同。
10. **输入摘要归属**。v2 构建记录中的 `staged_materials` 不再包含 candidate 与 normal 两个 input；input 摘要只出现在 replay 记录中。构建复用只比较构建材料、工具链与 `build_inputs_digest`，不把输入混入构建来源。本条款只约束 v2；v1 证据分支按 D15 冻结，继续保留 `inputs/normal.txt` 与 `inputs/candidate.txt` 两个别名，既有 v1 包不改写、不重跑。
11. **复用绑定**。campaign 的构建记录产生 `build_ref`；validation 通过 `build_ref` 复用制品，并核对 `vulnerable`/`fixed` 两版 artifact、build log、build inputs 与来源 job/generation。`build_ref.generation` 是 campaign 构建 attempt 的 generation，两版 artifact 共享同一值；`reuse_origin.generation` 必须与它一致，本轮不扩展为按版本分别记录 generation。任何不一致返回 `REUSE_MISMATCH`。
12. **错误信息与证据**。失败信息必须能定位版本、声明参数、生效参数、顺序差异与核对面类型；不得只返回“构建失败”。两版核对面原文以 `build_provenance` 角色归档，差异摘要随 report 保存，便于离线复核。
13. **版本化规则**。归一化规则、BuildSpec schema 与核对面解析器合并为 `build_provenance_rules_version`，写入 plan 与 report，并计入 `plan_digest`；规则变化不得悄悄改变旧计划的解释。

## Alternatives considered

- **继续解析 recipe 文本**。实现成本低，但无法覆盖 CMake/Make 的追加参数与包装器，正是不可比问题的主要来源。
- **只比较构建日志中的命令行**。日志可能被截断、重排或包含包装器内部命令；需要结构化核对面与归一化，而不是自由文本匹配。
- **把参数当集合比较、忽略顺序**。实现简单，却会把 `-I a -I b` 与 `-I b -I a` 判为可比，掩盖头文件搜索顺序差异。
- **让 LLM 生成或修正构建配方**。会把未审核代码带入构建路径，且无法保证两版使用同一模板；违反“构建配方经审核后固化”。
- **默认升级到工具链镜像 v2**。会扩大镜像与供应链面，且当前固定镜像已满足已登记案例；按案例引入更可控。

## Consequences

- 计划增加 `build_spec` 与 `compile_flags`，构建记录增加核对面与差异摘要；v1 计划没有这些字段，走只读兼容路径。
- CMake 与 Make 需要额外的核对面采集逻辑；shell legacy 需要人工审核记录，迁移成本较高。
- 两版生效参数不等时任务更早失败，减少“看似完整但不可比”的 `INCONCLUSIVE` 证据。
- `staged_materials` 语义收窄，构建复用与 replay 输入的来源在证据中分离，审计更清晰。
- 归一化规则本身需要版本控制；规则变更可能让旧计划无法重算，因此必须随 plan 冻结并在证据中记录。
- CMake 的 `compile_commands.json` 与 Make shim 日志都含大量路径；证据归档要按角色裁剪，避免把宿主机路径带入可共享材料。
- 核对面采集失败与参数不等分开报告，便于区分工具问题和配方问题。
- 构建复用的 artifact 摘要校验先于任何回放；不复用摘要不符的制品。
- 工具链镜像 v2 必须按案例固定摘要，不得在运行时替换基础镜像。
- 删除 `make_env` 会让旧式 Make 配方在迁移时必须把 shim 配置移入 `env`；这是一次显式迁移，不是静默兼容。
- 保留顺序意味着两份“内容相同、顺序不同”的配方会被判为不可比；这是有意收紧，而不是归一化缺陷。

## 对应 REQ

- [REQ-15 构建溯源与可比性](../srs-delta.md)
- 修改后的 [REQ-06 可比测试输入](../srs-delta.md)（生效参数判据）
- 修改后的 [REQ-03 可审核的分析与计划](../srs-delta.md)（BuildSpec 与显式 compile_flags）

## 测试坐标

- 声明子集：`tests/contract/test_build_provenance.py::test_declared_flags_must_be_subset_of_effective_flags`
- 两版相等：`tests/contract/test_build_provenance.py::test_two_versions_must_have_equal_effective_flags`
- 顺序显著：`tests/contract/test_build_provenance.py::test_include_order_is_significant`
- 连写/分写等价：`tests/contract/test_build_provenance.py::test_connected_and_split_flag_forms_are_equivalent`
- 声明先归一化：`tests/contract/test_build_provenance.py::test_declared_flags_are_normalized_before_compare`
- 成功核对面：`tests/contract/test_build_provenance.py::test_cmake_and_make_success_faces_are_captured`
- 规则版本：`tests/contract/test_build_provenance.py::test_build_provenance_rules_version_is_bound_in_plan`
- 无核对面：`tests/contract/test_build_provenance.py::test_missing_face_blocks_plan_freeze`
- shell legacy：`tests/contract/test_build_provenance.py::test_shell_recipe_requires_separate_face_review`
- 工具链边界：`tests/integration/test_toolchain_image.py::test_oniguruma_case_uses_existing_toolchain_image`
- 用例映射：[TC-15](../test-plan-delta.md)、[TC-06](../test-plan-delta.md)

以上坐标为 T13 计划测试，T09 不创建代码。实现须先看到对应断言失败，再补最小行为。
