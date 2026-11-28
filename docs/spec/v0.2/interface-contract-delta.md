# 接口与数据契约增量（v0.2）

本文件是 [v0.1 接口契约](../interface-contract.md) 的增量。未列出的命令、字段、校验与退出码继续按 v0.1 执行。v0.2 契约版本为 `2`；v1 结构只读兼容，不参与新探索轮次。

通用规则不变：UTF-8、UTC RFC 3339、时长秒、空间 MiB、摘要为带 `sha256` 前缀的 64 位小写十六进制；拒绝未知字段、重复 JSON 键与非有限数值；规范化 JSON 的字段排序与 UTF-8 编码由契约测试固定。

## 1. Request v2

新增可选 `exploration`。未提供时按 `mode=fixed` 处理，不产生 fuzz 轮次；提供时只声明探索意图，实际信封由已注册案例、策略与人工审批共同冻结，请求不能扩大案例上限。

```json
{
  "schema_version": 2,
  "cve_id": "CVE-2099-0001",
  "target": {
    "kind": "source",
    "case_id": "fixture-c-parser",
    "goal": "验证固定输入在缺陷版触发预期 ASan 异常"
  },
  "limits": {
    "prepare_seconds": 600,
    "execute_seconds": 1200,
    "replay_seconds": 10,
    "cpu": 2,
    "memory_mib": 2048,
    "pids": 128,
    "scratch_mib": 512
  },
  "exploration": {
    "mode": "guided",
    "allowed_mutation_families": ["byte_flip", "length_boundary"],
    "max_rounds": 8,
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300
  }
}
```

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `schema_version` | integer | `2`（`contracts.SCHEMA_VERSION_V2`）；v1 请求只读解析，不产生 v2 轮次 |
| `exploration.mode` | string | `fixed` 或 `guided`；缺省为 `fixed` |
| `exploration.allowed_mutation_families` | array[string] | 非空、去重、必须在案例注册表允许集合内；`fixed` 模式必须为空 |
| `exploration.max_rounds` | integer | 正整数，不得超过案例或策略上限；`fixed` 模式必须为 1 |
| `exploration.max_total_seconds` | integer | 正整数，不得超过 `limits.execute_seconds` 与 family 上限（v0.2 沿用 v0.1 `limits.execute_seconds` 1200 秒上限，真实多轮案例如需更长预算另立配置调整） |
| `exploration.max_fuzz_seconds` | integer | 非负整数，不得超过 `max_total_seconds`；`fixed` 模式必须为 0 |

`seed_corpus_digest`、`fuzz_image_digest`、`harness_digest`、`accepted_signature_set`、`mutation_limits` 与 `admission_predicate_version` 不从请求自由填写，由案例注册表与冻结策略生成，进入 `Envelope` 并由人审批。请求不能扩大 `mutation_limits` 或签名集合。

## 2. Envelope

信封是人工审批对象的一部分，正文不内联进 plan；其规范化摘要 `envelope_digest` 写入每个 v2 plan，因此 fuzz 镜像与 mutation 上限通过 `envelope_digest` 被间接绑定。fixed 模式仍冻结退化信封，`envelope_digest` 非空。

```json
{
  "mode": "guided",
  "allowed_mutation_families": ["byte_flip", "length_boundary"],
  "mutation_limits": {
    "allowed_ops": ["append", "truncate", "byte_flip"],
    "max_input_bytes": 4096
  },
  "seed_corpus_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
  "fuzz_image_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000002",
  "harness_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000003",
  "max_rounds": 8,
  "max_total_seconds": 900,
  "max_fuzz_seconds": 300,
  "accepted_signature_set": [
    {
      "error": "heap-buffer-overflow",
      "function": "parse_token",
      "source": "parser.c",
      "operation": "WRITE",
      "access_size": 1
    }
  ],
  "admission_predicate_version": "admission-v1"
}
```

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `mode` | string | `fixed` 或 `guided`；决定是否允许 mutation family 与 fuzz 轮次 |
| `allowed_mutation_families` | array[string] | 与请求和案例注册表取交集；每轮只能使用其中一族 |
| `mutation_limits.allowed_ops` | array[string] | 信封允许的变异操作集合；`ExperimentSpec.mutation_constraints.allowed_ops` 必须逐项属于该集合；`fixed` 必须为 `[]` |
| `mutation_limits.max_input_bytes` | integer | 单次输入字节上限；`ExperimentSpec.mutation_constraints.max_input_bytes` 不得大于该值；`fixed` 必须为 `0` |
| `seed_corpus_digest` | digest | 经审核种子语料的规范化摘要；guided 必填，fixed 为 null |
| `fuzz_image_digest` | digest | fuzz 固定镜像摘要；guided 必填且默认等于固定工具链镜像摘要，独立 fuzz 镜像必须显式审批；fixed 为 null |
| `harness_digest` | digest | 经审核 harness 的摘要，与 build recipe 同级冻结；guided（改9）绑定 `{harness, fuzz_shim}` 规范化对（见下），fixed 只绑定 harness |
| `max_rounds` | integer | family 级轮次上限，由准入 predicate 校验 `round_no <= max_rounds` |
| `max_total_seconds` | integer | family 级总时长上限 |
| `max_fuzz_seconds` | integer | 总时长内的 fuzz 子预算 |
| `accepted_signature_set` | array[object] | 只接受其中签名；每项与 plan `asan_signature` 同结构：`error`/`function`/`source` 必填，`operation`/`access_size` 可选 |
| `admission_predicate_version` | string | 准入谓词版本；与 plan、admission、证据同时记录 |

**固定 fuzz shim 与 guided `harness_digest`（改9）**。libFuzzer 入口由仓库固定的 fuzz shim 提供（`LLVMFuzzerTestOneInput` 把输入字节交给已审核 harness 的同一解析入口），不新增 per-case fuzz harness，模型不得合成或改写 shim。guided 信封的 `harness_digest` 为规范化对 `{"harness": <harness 文件 SHA-256>, "fuzz_shim": <shim 文件 SHA-256>}` 的 `digest_json`；fixed 信封不含 fuzz，`harness_digest` 仍为 harness 文件摘要。shim 未审核、字节与登记摘要不符或该对的摘要与信封不符时返回 `HARNESS_REJECTED`，执行入口在容器启动前再校验一次（准入阶段已查过也不例外）。

**种子语料登记（改9）**。初始 seed corpus 在案例注册表 `exploration_ceilings.<case_id>.seed_corpus` 显式登记为数组，每项 `{"name": <basename>, "path": <材料相对路径>, "digest": <sha256>}`；缺省登记该案例的 `normal` 与 `candidate` 两个输入。`name` 为不含 `/` 的唯一文件名，`path` 遵守材料路径规则。`seed_corpus_digest = digest_json(sorted([{"name", "sha256"}], by name))`：只由文件名与字节摘要决定，与路径、登记顺序无关。语料受[安全 §5](security-design-delta.md) 上限约束（总 64 MiB、单文件 8 MiB、4096 个文件），超限归 `POLICY_DENIED`，审计 `detail.sub_reason` 为 `CORPUS_TOTAL_BYTES_EXCEEDED`、`CORPUS_FILE_BYTES_EXCEEDED` 或 `CORPUS_FILE_COUNT_EXCEEDED`（见第 10 节）。

`mutation_limits`、`allowed_mutation_families` 以及两个预算上限都参与 `envelope_digest`。fixed 的退化信封固定为 `allowed_mutation_families=[]`、`mutation_limits={"allowed_ops":[],"max_input_bytes":0}`、`max_fuzz_seconds=0`、`seed_corpus_digest=null`、`fuzz_image_digest=null`，`harness_digest` 与 `accepted_signature_set` 仍必填。这些 null/空值是规范化信封的一部分，必须参与 `envelope_digest`；`envelope_digest` 不属于信封正文，计算时排除自身，并进入 plan、admission、manifest 与 report。

## 3. Plan v2

Plan v2 在 v0.1 `_PLAN_FIELDS`（21 个既有字段）之上**新增且仅新增 11 个字段**：`schema_version`、`family_id`、`parent_job_id`、`round_no`、`parent_approval_digest`、`envelope_digest`、`build_ref`、`build_spec`、`compile_flags`、`experiment_digest`、`build_provenance_rules_version`。这 11 个新增字段与既有 `_PLAN_FIELDS` 一并构成 Plan v2 的完整封闭字段集，全部参与规范化并计入 `plan_digest`（未知字段一律拒绝）。其中：

- `build_recipe_digest`：v2 **保留**该既有字段，其值固定为 `build_spec` 规范化 JSON 的 SHA-256（无论 `build_spec.kind` 为 `cmake`、`make` 或 `shell`），避免破坏既有读取逻辑；
- `inputs`：fixed 与 validation round 计划继续按 v0.1 要求提供 `{"normal": "<digest>", "candidate": "<digest>"}`；`campaign` 计划（`round_no=null`）固定取 `inputs: null`，该 `null` 显式保留并参与规范化（不与 v0.1 必填规则冲突）。

以下为新增与关键字段节选，完整计划仍包含 v0.1 的版本、依赖、镜像、harness、`build_recipe_digest`、签名、预算与隔离策略。

```json
{
  "schema_version": 2,
  "case_id": "fixture-c-parser",
  "cve_id": "CVE-2099-0001",
  "family_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "parent_job_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "round_no": 2,
  "parent_approval_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000004",
  "envelope_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000005",
  "build_ref": {
    "source_job_id": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "generation": 3,
    "build_inputs_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000008",
    "artifacts": {
      "vulnerable": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000006",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000007"
      },
      "fixed": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000011",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000012"
      }
    }
  },
  "build_spec": {
    "kind": "cmake",
    "configure": [
      "cmake",
      "-S",
      ".",
      "-B",
      "build",
      "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
      "-DCMAKE_C_COMPILER=clang"
    ],
    "build": ["cmake", "--build", "build", "--target", "parser"],
    "install": [],
    "env": {
      "CC": "clang",
      "CFLAGS": "-fsanitize=address -g -O1 -Iinclude -D_GNU_SOURCE"
    },
    "outputs": ["build/parser"],
    "declared_compile_flags": [
      "-fsanitize=address",
      "-g",
      "-O1",
      "-Iinclude",
      "-D_GNU_SOURCE"
    ],
    "shell_recipe_digest": null,
    "shell_face_digest": null,
    "shell_face_review": null
  },
  "compile_flags": [
    "-fsanitize=address",
    "-g",
    "-O1",
    "-Iinclude",
    "-D_GNU_SOURCE"
  ],
  "inputs": {
    "candidate": "sha256:0000000000000000000000000000000000000000000000000000000000000009",
    "normal": "sha256:000000000000000000000000000000000000000000000000000000000000000a"
  },
  "limits": {
    "prepare_seconds": 600,
    "execute_seconds": 1200,
    "replay_seconds": 10,
    "cpu": 2,
    "memory_mib": 2048,
    "pids": 128,
    "scratch_mib": 512
  },
  "policy_version": "policy-v2.0",
  "analysis_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000b",
  "experiment_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000013",
  "build_provenance_rules_version": "build-provenance-v1"
}
```

首份计划（guided 的 campaign 计划）没有可引用的父审批摘要，`parent_approval_digest` 必须为 `null`；该 null 值仍参与规范化并计入 `plan_digest`，不允许省略字段。fixed 的首份计划是 `round_no=1` 的 round 计划，规则相同。首份计划节选如下；后续轮次才使用非空 `parent_approval_digest`（见本节开头的 round 2 计划）：

```json
{
  "schema_version": 2,
  "family_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "parent_job_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "round_no": null,
  "parent_approval_digest": null,
  "envelope_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000005",
  "build_ref": null,
  "build_recipe_digest": "sha256:000000000000000000000000000000000000000000000000000000000000001e",
  "inputs": null,
  "experiment_digest": null,
  "build_provenance_rules_version": "build-provenance-v1"
}
```

| 字段 | 规则 |
| --- | --- |
| `schema_version` | `2`；计入 `plan_digest` |
| `family_id` | 同一探索 family 的稳定标识；等于父 job 的 `job_id`；计入 `plan_digest` |
| `parent_job_id` / `round_no` | 绑定 child job 与轮次；`family_id = parent_job_id`，round 的 `round_no >= 1`，campaign 的 `round_no = null`；与数据库 CHECK 和唯一约束一致；均计入 `plan_digest` |
| `parent_approval_digest` | 父审批摘要；首份计划为 `null`，后续轮次引用 `family_approvals.approval_digest` 的当前链尾；计入 `plan_digest` |
| `envelope_digest` | 信封规范化摘要（含 `mutation_limits`）；v2 execution/campaign 必填，fixed 的退化信封同样非空；计入 `plan_digest` |
| `build_ref` | 仅复用 campaign 的 validation execution 非空；fixed/non-reuse 与 campaign 必须为 null；含 `vulnerable`/`fixed` 两版 artifacts，全部计入 `plan_digest`；`generation` 是 campaign 构建 attempt 的 generation，两版共享同一值；每版 `artifact_digest` 绑回放 parser，guided validation 另加 `fuzzer_digest` 绑 fuzzer（改9 增补：两版同绑或都不绑，`reuse_origin.artifacts` 同形） |
| `build_spec` | 结构化构建输入；字段见第 5 节，`kind` 为 `cmake`、`make` 或 `shell`；计入 `plan_digest` |
| `compile_flags` | 冻结的声明参数，按第 5 节规则归一化后与 `build_spec.declared_compile_flags` 一致，保留顺序；计入 `plan_digest` |
| `experiment_digest` | ExperimentSpec 规范化摘要；fixed 与 campaign 为 null 但仍参与规范化，并计入 `plan_digest` |
| `build_provenance_rules_version` | BuildSpec schema、归一化规则与核对面解析器的合并版本；计入 `plan_digest` |
| `build_recipe_digest`（沿用 v0.1） | v2 保留，固定等于 `build_spec` 规范化 JSON 的 SHA-256；计入 `plan_digest` |
| `inputs`（沿用 v0.1） | fixed/validation 为 `{"normal": "<digest>", "candidate": "<digest>"}`；campaign 固定为 `null`；计入 `plan_digest` |

`plan_digest` 覆盖 v0.1 `_PLAN_FIELDS` 与上述 11 个新增字段组成的完整封闭字段集，包括 `parent_approval_digest=null`、`experiment_digest=null`、`build_ref=null` 与 campaign `inputs=null` 的显式 null。任何身份、审批、信封、构建来源或编译参数变化都必须产生新摘要；不能在同一 plan 上原地修改。

`build_ref.generation` 固定为 campaign 构建 attempt 的 generation（D41）。一个 campaign 一次构建同时产出 `vulnerable` 与 `fixed` 两版，因此两版 artifact 共享同一个 `generation`；`reuse_origin.generation` 必须与 `build_ref.generation` 相等，不一致按 `REUSE_MISMATCH` 失败关闭。若未来允许两版分别构建，再扩展为 `artifacts.<version>.generation`，本轮不做，也不在 plan 中预留该分支。

父审批摘要按 D23/D36 生成：人批后把 `{family_id, envelope_digest, first_plan_digest, reviewer_id, decided_at}` 的规范化 JSON 取 SHA-256 得到 `approval_digest`，**排除 `approval_digest` 自身**；`supersedes` 只记录链关系，不进入摘要输入。`decided_at` 参与哈希前统一渲染为 UTC RFC 3339 固定 6 位小数（`YYYY-MM-DDTHH:MM:SS.ffffffZ`，不足补零），避免数据库微秒精度与离线重算不一致。

`first_plan_digest` 固定为 family 的首份 plan 摘要：guided 取 campaign plan 的 `plan_digest`，fixed 取 `round_no=1` 的 round plan 的 `plan_digest`。它不随换信封改变，因此 approval 摘要不会形成“计划引用审批、审批又引用计划”的循环；换信封只让 `envelope_digest`（以及新的 `decided_at`）变化，从而产生新的 `approval_digest`。后续 plan 使用新 approval digest，并校验其 `envelope_digest` 与 `family_approvals` 链尾一致；链尾不符返回 `ADMISSION_DENIED`。换信封重批只追加 `family_approvals`，不重写 `reviews`。

## 4. ExperimentSpec

模型只输出 hypothesis；确定性规划器把候选假设转成 `ExperimentSpec`。字段固定为以下九项，不接收自由命令、shell 或额外可执行材料。

```json
{
  "target_symbol": "parse_token",
  "target_path": "src/parser.c",
  "target_line": 42,
  "input_family": "length_boundary",
  "mutation_constraints": {
    "max_input_bytes": 4096,
    "allowed_ops": ["append", "truncate"]
  },
  "expected_signature": {
    "error": "heap-buffer-overflow",
    "function": "parse_token",
    "source": "parser.c",
    "operation": "WRITE",
    "access_size": 1
  },
  "rationale": "补丁在终止符写入前增加了长度检查，长度边界输入可复核该假设。",
  "evidence_refs": [
    "log/build:fixed#L10-12",
    "patch:fix.patch#hunk-2"
  ],
  "confidence": "medium"
}
```

| 字段 | 规则 |
| --- | --- |
| `target_symbol` / `target_path` / `target_line` | 必须落在 plan 固定的版本与源码范围内 |
| `input_family` | 必须属于 `allowed_mutation_families` |
| `mutation_constraints` | 必须逐项是信封 `mutation_limits` 的子集：`allowed_ops` ⊆ `mutation_limits.allowed_ops`，`max_input_bytes <= mutation_limits.max_input_bytes`；不接受任意字节生成器 |
| `expected_signature` | 与 `accepted_signature_set` 中某一项做全字段严格相等匹配：`error`/`function`/`source` 必填，`operation`/`access_size` 可选；字段存在性、值与可选字段缺失/存在都要比较 |
| `rationale` | 只作说明，不作为判定证据 |
| `evidence_refs` | 至少一项可解析；支持 v0.1 引用与新增 `log/build`、`log/fuzz` 语法 |
| `confidence` | `low`、`medium` 或 `high`；只影响展示与实验排序，不影响判定 |

### 4.1 AgentOutput v2

v0.1 的 `AgentOutput` 允许 `finding.kind` 为 `fact` 或 `hypothesis`。v0.2 覆盖该规则：

| 规则 | v0.2 行为 |
| --- | --- |
| 模型来源 finding | 只允许 `kind=hypothesis`；出现 `kind=fact` 视为非法输出并阻断 |
| 确定性工具事实 | 不通过模型 `AgentOutput` 的 `fact` 输出，改为工具结果与证据引用（`ToolResult.artifacts`、`evidence_refs`）随证据归档 |
| 判定 | 事实与假设都不能改变判定；判定只来自六次回放与确定性规则 |
| v1 兼容 | 既有 v1 `AgentOutput` 记录只读兼容：可查询、可导出，不重跑，不做在线改写 |

模型来源的 hypothesis 仍须附 `statement`、`confidence` 与可解析 `evidence_refs`；不可解析的 hypothesis 保留为线索，不生成 ExperimentSpec。

## 5. BuildSpec

BuildSpec 只有一套字段：`kind`、`configure`（仅 cmake）、`build`、`install`（可选）、`env`、`outputs`、`declared_compile_flags`，以及 shell 专属的三个面字段。`make_env` 已删除，Make 的 `CC` shim 通过 `env` 注入。

| `kind` | 必填字段 | 核对面 |
| --- | --- | --- |
| `cmake` | `configure`、`build`、`env`、`outputs`、`declared_compile_flags` | 构建目录中的 `compile_commands.json` |
| `make` | `build`、`env`、`outputs`、`declared_compile_flags` | `env.CC` 指向的 `CC` shim 日志；不得依赖未记录的隐式规则 |
| `shell` | `build`、`env`、`outputs`、`declared_compile_flags`、`shell_recipe_digest`、`shell_face_digest`、`shell_face_review` | 经审核的日志核对面；默认不构成可比性证据 |

**campaign 双产物（改9）**。campaign child 每版只构建一次，`outputs` 同时列出回放用 parser（ASan）与 fuzzer（libFuzzer + 固定 shim）两个产物，二者都以 `build_artifact` 角色归档；按“固定路径”的 `BuildSpec.outputs` 映射落在 `build/{version}/` 下（默认 `build/{version}/parser` 与 `build/{version}/fuzzer`）。guided validation 复用 campaign 两版的这两个产物，不重新构建；fixed execution/validation 照常构建两版回放产物，不产 fuzzer。

`install` 为可选数组，缺省等价于 `[]`。`shell_recipe_digest` 只表示配方摘要，不是核对面；`shell_face_digest` 为案例注册表预审基线核对面（已做路径与时间戳归一化）的 SHA-256，`shell_face_review` 记录审核人、审核时间与核对面类型。冻结阶段校验 `shell_face_digest` 与 `shell_face_review` 非空；构建阶段对实际构建日志执行同一路径/时间戳归一化后计算摘要并与 `shell_face_digest` 比对，不符即返回 `BUILD_PROVENANCE_MISSING`。

```json
{
  "kind": "make",
  "build": ["make", "-C", "src", "parser"],
  "install": [],
  "env": {
    "CC": "/opt/datacon/cc-shim",
    "CFLAGS": "-fsanitize=address -g -O1 -Iinclude -D_GNU_SOURCE"
  },
  "outputs": ["src/parser"],
  "declared_compile_flags": [
    "-fsanitize=address",
    "-g",
    "-O1",
    "-Iinclude",
    "-D_GNU_SOURCE"
  ],
  "shell_recipe_digest": null,
  "shell_face_digest": null,
  "shell_face_review": null
}
```

shell legacy 的核对面必须显式审核并归档：

```json
{
  "kind": "shell",
  "build": ["sh", "./build.sh"],
  "env": {"CC": "clang"},
  "outputs": ["out/parser"],
  "declared_compile_flags": ["-fsanitize=address", "-g", "-Iinclude"],
  "shell_recipe_digest": "sha256:000000000000000000000000000000000000000000000000000000000000001c",
  "shell_face_digest": "sha256:000000000000000000000000000000000000000000000000000000000000001d",
  "shell_face_review": {
    "reviewer_id": "reviewer-01",
    "reviewed_at": "2099-01-01T00:00:00Z",
    "face_kind": "build_log"
  }
}
```

核对面原文（CMake 的 `compile_commands.json`、Make shim 日志、shell 审核日志）以 `build_provenance` 角色随证据归档，两版各一份；`build_metadata` 只存结构化摘要。

### 多编译单元解析与 compile_flags 归一化

**多编译单元解析规则**。当目标包含多个 `.c`/`.cc`/`.cpp` 编译单元时：从 `compile_commands.json` 或 `cc-shim.log` 中过滤仅编译目标源码的命令（按仓库相对源文件路径升序确定性排序，排除纯链接命令以及编译器可执行文件名、`-c`、`-o <obj>` 与源文件本身等非编译选项项）；为每个编译单元记录归一化后的有序生效标志序列（按文件映射），并汇总得到用于全局声明核对的扁平生效标志集合。两版可比判据要求：两版共同编译单元（交集）的归一化有序生效标志序列必须**逐编译单元严格相等**，且两版各自满足“声明 ⊆ 生效（多重集包含）”。若某编译单元在单版缺失且无法由目标补丁解释，仍以 `BUILD_PROVENANCE_MISSING` 失败关闭。

**compile_flags 归一化规则**：

1. **保留顺序，不整体排序**。不做全局排序，也不按 `-D` 名称重排。
2. **路径、引号、空白归一化**：绝对路径改为相对仓库根；去掉仅包裹整个参数的外层引号；连续空白压成单空格。
3. **连写/分写等价（封闭集合）**。仅对封闭集合 `{-I, -L, -l, -D, -U, -isystem, -include}` 7 个选项执行规范化，写死规范形态如下：短选项 `-I`、`-L`、`-l`、`-D`、`-U` 统一归一化为**连写单 token**（`-I<dir>`、`-L<dir>`、`-l<lib>`、`-D<macro>`、`-U<macro>`，例如 `-I include` → `-Iinclude`）；长选项 `-isystem`、`-include` 统一归一化为**双 token 分写**（`["-isystem", "<dir>"]`、`["-include", "<file>"]`，若输入为 `-isystem<dir>` 或 `-include<file>` 则拆分为双 token）。等价规则只作用于单个选项与其参数，不改变选项之间的先后顺序，也不合并两个独立选项。
4. **声明先归一化再比较**。`declared_compile_flags` 与生效参数在比较前都调用同一归一化函数；不允许只归一化生效侧或用两套规则，否则连写/分写差异会被误判为不可比。
5. **重复 `-I` 保留首次出现**，后续同值丢弃；`-L`、`-l`、`-include`、`-isystem` 不去重、不重排。
6. **不重排任何位置相关参数**；`-include`、`-isystem`、`-L`、`-l` 的先后顺序即语义。
7. **两版比较用有序序列严格相等**：每个共同编译单元的生效序列长度、顺序与逐项值都必须相同。
8. **声明对生效用多重集包含**：每个（已归一化的）声明项在目标版本生效标志中的出现次数不少于声明序列，不因排序或去重丢失顺序信息。
9. 反例：`-I a -I b` 与 `-I b -I a` 归一化后仍**不相等**；即使集合相同，两版生效序列不同也必须返回 `BUILD_PROVENANCE_MISSING`。等价规则只消除封闭集合内单个选项的连写/分写差异，不消除参数顺序。

判据为“声明 ⊆ 生效（多重集包含），且两版共同编译单元生效有序序列逐一严格相等”。无核对面时在冻结计划阶段返回 `BUILD_PROVENANCE_MISSING`。

v2 构建记录中的 `staged_materials` 不再包含 `candidate` 与 `normal` 两个 input；input 摘要只出现在 replay 记录里。`build_inputs_digest` 只覆盖构建材料、工具链与 BuildSpec，不覆盖输入。v1 构建记录按冻结分支继续保留 `inputs/normal.txt` 与 `inputs/candidate.txt` 两个别名；既有 v1 包不改写。

## 6. Admission 记录

`admissions` 是独立表，不是 `reviews`。人批只写 `reviews` 与 `family_approvals`；轮次内 policy 准入只写 `admissions` 并追加 `round_admitted` 审计事件。

```json
{
  "admission_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "job_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "parent_job_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "round_no": 2,
  "approval_kind": "policy",
  "envelope_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000005",
  "parent_approval_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000004",
  "seed_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000c",
  "predicate_version": "admission-v1",
  "recomputable": true,
  "supporting_bundle_digest": null,
  "decided_at": "2099-01-01T00:00:00Z"
}
```

| 字段 | 规则 |
| --- | --- |
| `approval_kind` | 只允许 `policy`；人批在 `reviews` 与 `family_approvals` 中，不写此表 |
| `envelope_digest` / `parent_approval_digest` | 必须与 plan 和 `family_approvals` 当前审批一致；后续 round 的 admission 必须使用非空 `parent_approval_digest`；首份计划所在轮次不使用本表 |
| `seed_digest` | 本轮实际使用种子的摘要；crash seed 另有字节与 provenance |
| `predicate_version` | 与信封的 `admission_predicate_version` 一致 |
| `recomputable` | 准入是否可仅凭离线证据重算 |
| `supporting_bundle_digest` | 不可重算时指向 campaign bundle；证据中以“由 campaign bundle 佐证”标注 |
| `decided_at` | 数据库时钟写入的 UTC 时间 |

## 7. 持久化增量

`jobs` 的 v2 身份列使用完整的 v1/v2 分支 CHECK。v1 旧行 `job_contract_version=1` 且四个身份列全为 NULL；v2 新行 `job_contract_version=2`、`job_kind` 非空并按 kind 校验。`parent_job_id` 必须引用真实 job，且不得自父。

```sql
ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS family_id uuid,
    ADD COLUMN IF NOT EXISTS job_kind text,
    ADD COLUMN IF NOT EXISTS parent_job_id uuid REFERENCES jobs(job_id),
    ADD COLUMN IF NOT EXISTS round_no integer,
    ADD COLUMN IF NOT EXISTS job_contract_version integer NOT NULL DEFAULT 1;

ALTER TABLE jobs
    ADD CONSTRAINT jobs_job_contract_version_check
    CHECK (job_contract_version IN (1, 2));

ALTER TABLE jobs
    ADD CONSTRAINT jobs_identity_check
    CHECK (
      (job_contract_version = 1
       AND family_id IS NULL AND job_kind IS NULL
       AND parent_job_id IS NULL AND round_no IS NULL)
      OR
      (job_contract_version = 2 AND (
        (job_kind='family' AND parent_job_id IS NULL AND round_no IS NULL AND family_id=job_id)
        OR
        (job_kind='campaign' AND parent_job_id IS NOT NULL AND round_no IS NULL
         AND family_id=parent_job_id AND parent_job_id<>job_id)
        OR
        (job_kind='round' AND parent_job_id IS NOT NULL AND round_no IS NOT NULL AND round_no>=1
         AND family_id=parent_job_id AND parent_job_id<>job_id)
      ))
    );

ALTER TABLE jobs
    ADD CONSTRAINT jobs_v2_identity_not_null
    CHECK (job_contract_version = 1
           OR (job_kind IS NOT NULL AND family_id IS NOT NULL));

CREATE UNIQUE INDEX IF NOT EXISTS jobs_parent_round_key
    ON jobs(parent_job_id, round_no);

CREATE UNIQUE INDEX IF NOT EXISTS jobs_family_campaign_key
    ON jobs(parent_job_id) WHERE job_kind = 'campaign';
```

上式给出约束的完整表达式，不是可直接重复执行的迁移脚本；T10 的迁移必须用 `DO $$ ... $$` 先检查约束是否存在，或用等价的幂等写法，保证在已有库上可重复执行。另需注意：SQL 中 `CHECK` 遇到 NULL 会放行，因此 v2 分支额外用 `jobs_v2_identity_not_null` 守卫，确保 `job_contract_version=2` 时 `job_kind` 与 `family_id` 非空。此外，`jobs.parent_job_id` 非空时必须指向 `job_contract_version = 2 AND job_kind = 'family'` 的真实父行（由应用层或数据库 `BEFORE INSERT OR UPDATE` 触发器强制校验，禁止把 v1 job 或非 family child 设为父任务）。

| 表 | 增量 | 约束 |
| --- | --- | --- |
| `jobs` | `family_id`、`job_kind`、`parent_job_id`、`round_no`、`job_contract_version` | 上述 `CHECK (job_contract_version IN (1, 2))`、按 kind 的身份 CHECK 与 `jobs_v2_identity_not_null` 非空守卫；`UNIQUE(parent_job_id, round_no)`；partial unique index 保证每个 family 至多一个 campaign；`parent_job_id` 外键引用 `jobs(job_id)` 且必须指向 `job_contract_version=2 AND job_kind='family'`（应用层或触发器校验） |
| `family_approvals` | `approval_id`、`family_id`、`approval_digest`、`envelope_digest`、`first_plan_digest`、`reviewer_id`、`decided_at`、`supersedes` | `approval_digest` 唯一；`family_id` 引用 `jobs(job_id)` 且必须是 `job_kind=family`（应用层校验）；`supersedes` 外键引用 `family_approvals(approval_id)` 并指向同 family 的上一条 approval；写入前必须确认 `supersedes` 是当前链尾；`UNIQUE(family_id, envelope_digest)` 兜底同一信封只产生一条 approval |
| `family_envelopes` | `envelope_id`、`family_id`、`envelope_digest`、`envelope_json`、`status`、`review_deadline_at`、`reviewer_id`、`decided_at`、`created_at` | `UNIQUE(family_id, envelope_digest)`；partial unique index 保证每个 family 至多一个 `status='pending'`；`status ∈ {pending, approved, rejected, expired}`；`review_deadline_at` 非空（默认创建时间 + 24 小时） |
| `admissions` | `admission_id`、`job_id`、`parent_job_id`、`round_no`、`approval_kind`、`envelope_digest`、`parent_approval_digest`、`seed_digest`、`predicate_version`、`recomputable`、`supporting_bundle_digest`、`decided_at` | `approval_kind='policy'`；`UNIQUE(parent_job_id, round_no)` 保证每轮至多一条 policy 准入 |
| `budget_ledger` | `family_id`、`max_total_seconds`、`max_fuzz_seconds`、`remaining_total_seconds`、`remaining_fuzz_seconds`、`updated_at` | 约束 `max_total_seconds > 0`、`max_fuzz_seconds >= 0`、`max_fuzz_seconds <= max_total_seconds`、`remaining_total_seconds >= 0`、`remaining_total_seconds <= max_total_seconds`、`remaining_fuzz_seconds >= 0`、`remaining_fuzz_seconds <= max_fuzz_seconds`；**禁止**增加 `remaining_fuzz_seconds <= remaining_total_seconds` 的交叉 CHECK；原子 `UPDATE ... WHERE remaining >= x` |
| `budget_charges` | `charge_id`、`family_id`、`job_id`、`step_key`、`attempt_no`、`charge_kind`、`seconds`、`fuzz_seconds`、`created_at` | `UNIQUE(job_id, step_key, attempt_no)`；`CHECK (0 <= fuzz_seconds AND fuzz_seconds <= seconds)`；`charge_kind IN ('general','fuzz')` |

**父审批链与自动准入表（`family_approvals` / `admissions`）**。最小 DDL：

```sql
CREATE TABLE IF NOT EXISTS family_approvals (
    approval_id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES jobs(job_id),
    approval_digest text NOT NULL UNIQUE,
    envelope_digest text NOT NULL,
    first_plan_digest text NOT NULL,
    reviewer_id text NOT NULL,
    decided_at timestamptz NOT NULL,
    supersedes uuid REFERENCES family_approvals(approval_id),
    CONSTRAINT family_approvals_envelope_unique UNIQUE (family_id, envelope_digest)
);

CREATE TABLE IF NOT EXISTS admissions (
    admission_id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES jobs(job_id),
    parent_job_id uuid NOT NULL REFERENCES jobs(job_id),
    round_no integer NOT NULL CHECK (round_no >= 1),
    approval_kind text NOT NULL CHECK (approval_kind = 'policy'),
    envelope_digest text NOT NULL,
    parent_approval_digest text NOT NULL,
    seed_digest text NOT NULL,
    predicate_version text NOT NULL,
    recomputable boolean NOT NULL,
    supporting_bundle_digest text,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT admissions_parent_round_unique UNIQUE (parent_job_id, round_no),
    CONSTRAINT admissions_supporting_check CHECK (
        recomputable = true OR supporting_bundle_digest IS NOT NULL
    )
);
```

**审核信封表（D42）**。family 的待审信封不是 plan 的副本，必须独立持久化，才能区分“首轮人批”与“换信封重批”。最小结构：

```sql
CREATE TABLE IF NOT EXISTS family_envelopes (
    envelope_id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES jobs(job_id),
    envelope_digest text NOT NULL,
    envelope_json jsonb NOT NULL,
    status text NOT NULL,
    review_deadline_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '24 hours'),
    reviewer_id text,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT family_envelopes_digest_unique UNIQUE (family_id, envelope_digest),
    CONSTRAINT family_envelopes_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired'))
);

CREATE UNIQUE INDEX IF NOT EXISTS family_envelopes_one_pending
    ON family_envelopes(family_id) WHERE status = 'pending';
```

首份 plan 冻结时把首信封插入为 `pending`（`review_deadline_at` 与首份 child 审核时限一致，默认 24 小时）；换信封时由 `datacon propose-envelope` 校验后插入新的 `pending` 并设置 `review_deadline_at`（默认创建时间 + 24 小时），旧行按决议转为 `approved`/`rejected`/`expired`，不删除。`reviewer_id` 与 `decided_at` 对 `approved`/`rejected` 必填，`expired` 可无 reviewer；这些是应用层校验，SQL 只固定状态枚举与唯一性。`jsonb` 保存规范化信封正文，`envelope_digest` 仍按第 2 节的规范化 JSON 计算。与 jobs 约束一样，T10 的迁移必须用 `DO $$ ... $$` 或等价幂等写法添加约束，保证在已有库上可重复执行。

`budget_ledger` 与 `budget_charges` 的最小约束：

```sql
CREATE TABLE IF NOT EXISTS budget_ledger (
    family_id uuid PRIMARY KEY REFERENCES jobs(job_id),
    max_total_seconds integer NOT NULL,
    max_fuzz_seconds integer NOT NULL,
    remaining_total_seconds integer NOT NULL,
    remaining_fuzz_seconds integer NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT budget_ledger_max_total_positive CHECK (max_total_seconds > 0),
    CONSTRAINT budget_ledger_max_fuzz_non_negative CHECK (max_fuzz_seconds >= 0),
    CONSTRAINT budget_ledger_total_non_negative CHECK (remaining_total_seconds >= 0),
    CONSTRAINT budget_ledger_fuzz_non_negative CHECK (remaining_fuzz_seconds >= 0),
    CONSTRAINT budget_ledger_remaining_within_max_total
        CHECK (remaining_total_seconds <= max_total_seconds),
    CONSTRAINT budget_ledger_remaining_within_max_fuzz
        CHECK (remaining_fuzz_seconds <= max_fuzz_seconds),
    CONSTRAINT budget_ledger_fuzz_within_total CHECK (max_fuzz_seconds <= max_total_seconds)
);

CREATE TABLE IF NOT EXISTS budget_charges (
    charge_id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES jobs(job_id),
    job_id uuid NOT NULL REFERENCES jobs(job_id),
    step_key text NOT NULL,
    attempt_no integer NOT NULL,
    charge_kind text NOT NULL,
    seconds integer NOT NULL,
    fuzz_seconds integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT budget_charges_idempotent UNIQUE (job_id, step_key, attempt_no),
    CONSTRAINT budget_charges_attempt_positive CHECK (attempt_no >= 1),
    CONSTRAINT budget_charges_seconds_non_negative CHECK (seconds >= 0),
    CONSTRAINT budget_charges_fuzz_bounded CHECK (fuzz_seconds >= 0 AND fuzz_seconds <= seconds),
    CONSTRAINT budget_charges_kind_matches_fuzz CHECK (
        (charge_kind = 'general' AND fuzz_seconds = 0)
        OR (charge_kind = 'fuzz' AND fuzz_seconds > 0)
    )
);
```

**字段命名映射**：数据库列 `budget_ledger.remaining_total_seconds` 对应 JSON（`report.budget`、`status.budget`、`family.json`）中的 `remaining_seconds`；其余 5 个预算字段在 DB/汇总与 JSON 中同名（`max_total_seconds`、`max_fuzz_seconds`、`spent_seconds`、`spent_fuzz_seconds`、`remaining_fuzz_seconds`）。

**预算执行与扣减协议（唯一协议）**：
1. **启动前门禁与硬超时下发**：启动容器前先校验总余额 `remaining_total_seconds >= 1`（fuzz 步骤同时校验 `min(remaining_total_seconds, remaining_fuzz_seconds) >= 1`），不足即拒绝启动并触发 `BUDGET_EXHAUSTED`；校验通过后将该可用余额上限（fuzz 为 `min(remaining_total_seconds, remaining_fuzz_seconds)`）下发为容器硬超时上限。
2. **容器退出后独立短事务落账**：容器执行本身在数据库事务外进行；容器退出后在独立短事务内计算 `charged_seconds = min(ceil(elapsed), remaining_total_seconds)`（fuzz 步骤另算 `charged_fuzz = min(max(1, ceil(elapsed_fuzz)), remaining_fuzz_seconds, charged_seconds)`），按幂等键 `(job_id, step_key, attempt_no)` 执行原子条件 `UPDATE budget_ledger ... WHERE remaining_total_seconds >= charged_seconds`（fuzz 同时校验 `remaining_fuzz_seconds >= charged_fuzz`）并写入 `budget_charges` 与步骤结果记录；若实耗触达或超过余额（扣减后归零或因并发/超时无法再扣），同时触发 `BUDGET_EXHAUSTED`。
3. **幂等与恢复**：同一 `(job_id, step_key, attempt_no)` 重复扣费返回既有记录；恢复同一 attempt 不重复扣费，重试产生新 `attempt_no` 并新扣费。`family_id` 冗余在 charge 上，便于按 family 离线重建 `spent_seconds` 与 `spent_fuzz_seconds`。未真正启动的 fuzz 不落 charge，因此 `charge_kind='fuzz'` 的 `fuzz_seconds` 恒 ≥ 1，且始终满足 `0 <= fuzz_seconds <= seconds`。

**runtime 接线（改9）**。上述协议由执行器对 v2 `campaign`/`round` child 的每个容器步骤执行（probe、build、replay 为 `general`，fuzz 为 `fuzz`）；`step_key` 为执行器步骤键（如 `build:vulnerable`、`replay:fixed:normal`），`attempt_no` 为该步骤的执行 attempt 号。门禁在写 attempt 行与创建容器之前执行，下发的上限同时约束该步容器的硬超时；容器退出后无论完成、超时、OOM、失败或被取消都按实耗落账，落账失败不掩盖步骤自身的异常。步骤开始前余额不足时，当前 child 以 `BUDGET_EXHAUSTED` 收束：尚无回放时为 `FAILED`，已有回放时为 `INCONCLUSIVE`，均保留已产出证据；campaign/family 仍按既有 `COMPLETED` 收敛。report 与 `budget/snapshot.json` 的预算按扣费后的 family charge 重建。

**派生轮次与准入（改9）**。边 #23/#26 的 family 级转移先 gate、后建 child，首份人批计划（含 fixed 的 round 1）不经此路径：

1. **派生前 gate**（`check_round_derivation`）：先校验前置条件——family 须为 guided 模式（fixed 不走该路径）、处于 `AGGREGATING`、无 `pending` 信封、无非终态（含未同步或未归档的 blocked）child（串行，`sub_reason=CHILD_NOT_TERMINAL`）、有且仅有一个 `COMPLETED` campaign child，且 `round_no` 等于已有最大轮次 +1（不满足时无原因码，返回对应 `sub_reason` 或 `StateError`）。随后只按 `max_rounds` 与总余额 ≥ 1 秒做容量门禁：`round_no` 超过有效 `max_rounds` 或总余额不足 1 秒时返回 `BUDGET_EXHAUSTED`。guided 的 validation 轮次只执行 general 步骤（构建/回放），不检查 fuzz 子预算；fuzz 子预算只在 fuzz 步骤自身的门禁生效。gate 不通过时**不创建任何 child**，family 按归档门禁收敛（总余额耗尽或轮次用尽可归档）。
2. **建 child**：gate 通过后创建 `job_kind=round` child 与其冻结 plan（按非首份 plan 规则绑定审批链尾），child 以 `READY`、`workflow_synced=true`、`stage='admission'` 落库，v2 领取门禁在 policy admission 行存在前不领取；准入输入（信封正文、seed 摘要、ExperimentSpec、campaign 佐证）经结构与大小（64 KiB）校验后随 plan 存入 `plans.summary.admission_inputs`（对 `status()` 隐藏，同轮重入须一致否则 `PlanConflict`）。
3. **准入**：随后调用 `record_admission`。通过后 child 可被领取执行；已有 `admissions` 行的 round 不得再被阻断。拒绝时 child 不启动任何容器，直接 `BLOCKED` 并归档 blocked 包，`ADMISSION_DENIED`、`ENVELOPE_VIOLATION`、`HARNESS_REJECTED` 原样作为原因码；`record_admission` 遇确定性错误（`StateError`/`KeyError`/`TypeError`）时 fail closed 为 `BLOCKED(ADMISSION_DENIED)` 并归档，遇瞬时数据库错误（`psycopg.Error`）时不阻断、保持 `READY` 待恢复重试。单轮被 policy 拒绝（`ENVELOPE_VIOLATION`/`ADMISSION_DENIED`/`HARNESS_REJECTED` 且无 admission 行）不立即终结 family：family 保持 `AGGREGATING` 可继续派生下一轮（`round_no + 1`），仍受 `max_rounds` 与总余额约束；当轮次用尽、总余额不足 1 秒或当前决策点记录 `no_next_round` 时，若存在其他合法轮次则归档 `family.json`（索引已归档的 blocked round）并收敛 `COMPLETED`，若全部轮次均被 policy 拒绝且无其他合法轮次则终态 `BLOCKED`（对应 §10）。
4. **竞态兜底（仅防御路径）**：正常路径不会带着耗尽的预算进入准入。只有极端竞态（gate 与准入谓词之间账本变化）下谓词仍以 `BUDGET_EXHAUSTED` 拒绝时，才允许“先建后封”：已建 child 记为 `BLOCKED(ADMISSION_DENIED)`（`BUDGET_EXHAUSTED` 不属于 `BLOCKED` 封闭集），细因保留在 `round_admission_denied` 审计；这不是预算耗尽的正常语义。
5. **崩溃恢复**：建 child 后、准入前崩溃会留下 `READY`/`stage='admission'`、无 admission 行的 round；worker 每轮扫描超过宽限期（300 秒，数据库时钟）的此类 round，在事务内复核仍无 admission 行后用已存准入输入幂等重试 `record_admission`；仍被拒或遇确定性错误按第 3 条阻断归档。阻断 round 与 `record_blocked` 归档之间崩溃（或 I/O 失败）会留下有 plan 但 `evidence_status IS NULL` 的 `BLOCKED` round；worker 在 `converge_families` 前幂等补归档 blocked 包，family 收敛前等待补归档完成。

**扣费崩溃恢复（改9）**。预算步骤在容器启动前写入 `started` attempt 行（`started_at` 与 `result.budget = {charge_kind, ceiling_seconds}`，其中 `ceiling_seconds` 为该步下发给容器的硬超时，即 `min(步骤自身超时, 剩余 deadline, gate 上限)`，不超过 gate 上限）。若进程在容器退出后、落账前崩溃，该行保持 `started` 且无 `budget_charges` 行；worker 扫描按“先补扣再封存”顺序（`expire_pending_envelopes` → `recover_uncharged_attempts` → `recover_unadmitted_rounds` → `recover_unarchived_blocked_rounds` → `converge_families`）运行，在该 job 租约过期（或已由更新 generation 接管）后按 `min(ceil(now - started_at), ceiling_seconds)` 补扣（再经本节公式按余额截断），沿用幂等键 `(job_id, step_key, attempt_no)`，并写 `budget_charge_recovered` 审计。family 存在待补扣候选 attempt 时暂不封存；已封存（非 `AGGREGATING`）的 family 不再改账；不可补扣的行（已封存 family、fuzz 子预算已归零或 `ceiling_seconds` 非有限/非正）关闭为 `status='infra_error'`（`result.budget_recovery="unchargeable"`）并写 `budget_charge_recovery_skipped` 审计移出候选集，避免每个 tick 重扫。child 归档前先补扣同 child 旧 generation 未扣费 attempt，并按最新 charge 重建 `budget/snapshot.json` 与 `report.budget`。补扣偏保守，可能计入停机时间，但不超过该步下发给容器的硬超时，也不会漏扣；租约仍有效的 attempt 不补扣。

预算不变量（D41）：`budget_ledger` 除上述上下界与 `max_fuzz_seconds <= max_total_seconds` 约束外，**不得**新增 `CHECK (remaining_fuzz_seconds <= remaining_total_seconds)`。原因是 `charge_kind='general'` 的 build/replay 只扣总预算、不扣 fuzz 子预算，正常运行中 `remaining_fuzz_seconds` 完全可能大于 `remaining_total_seconds`；加该 CHECK 会把合法账本判为脏数据。实际可执行的 fuzz 上限为 `min(remaining_total_seconds, remaining_fuzz_seconds)`（JSON 对应 `min(remaining_seconds, remaining_fuzz_seconds)`）：任一余额不足即返回 `BUDGET_EXHAUSTED`，不以单一余额判断。

`job_contract_version` 是 job/worker 契约版本，独立于证据 `schema_version`，也独立于发布 manifest 的 `contract_version`：

- 证据 `schema_version`：`1` 或 `2`，由校验器分派；`contracts.SCHEMA_VERSION` 保持 `1`（v1 请求/契约），v2 Request 使用新增的 `contracts.SCHEMA_VERSION_V2 = 2`；
- `jobs.job_contract_version`：v1 旧行 `1`，v2 新行 `2`；
- 发布 manifest 的 `contract_version`：本轮固定为 `1`。`release.CONTRACT_VERSION` 不得继续依赖 `contracts.SCHEMA_VERSION`，T10 改为字面量 `1` 或独立常量，避免 v2 契约常量一升级就静默改写发布门禁；v2 发布 smoke 另立任务，不复用该字段表达 job 身份。

**v2 终态 `COMPLETED` 与无租约收敛（D40）**。campaign child 搜索结束/预算耗尽并归档后、family 聚合归档后，`jobs.state=COMPLETED`。它是 v2 新增终态：`verdict` 与 `reason_code` 为 null，`evidence_status='archived'`（因此仍满足归档指针 CHECK 与“无 verdict 的失败行”检查，不需要为它放宽 v1 约束）。两条收敛接口职责分离：
- `finish_execution`：**仅用于持有有效 worker lease 且状态为 `RUNNING`/`ARCHIVING` 的 child job**（含 `campaign` child 落 `COMPLETED`）；其终态白名单从 `REPRODUCED`/`NOT_REPRODUCED`/`INCONCLUSIVE`/`BLOCKED`/`FAILED` 扩展为包含 `COMPLETED`，archived 分支要求 `evidence_path` 与 `evidence_digest` 同时非空。
- `complete_family(family_id, evidence_path, evidence_digest)`：**无执行租约的 family 终态收敛接口**。在锁住 `job_kind='family'` 行后，将状态从 `AGGREGATING` 迁移至 `COMPLETED`，设置 `evidence_status='archived'`、非空 `evidence_path` 与 `evidence_digest`、`verdict=NULL`、`reason_code=NULL`，无需执行租约，仍受 007 `jobs_archived_evidence_check` 约束；若 family 已为 `COMPLETED` 且指针一致则幂等返回，状态非法则拒绝。
- **崩溃恢复路径**：若末轮 child 已归档终态，但进程在 `family.json` 落盘或 `complete_family` 提交前崩溃，worker 恢复扫描检测到“全部 child 已终态（或已满足预算/轮次/结论终止条件，或存在与当前轮次匹配的 `no_next_round` 决策，见 §9.2）且 family 仍为 `AGGREGATING`”时，幂等补落盘 `family.json` 并调用 `complete_family` 收敛，不让 family 永久滞留 `AGGREGATING` 阻塞回滚。

`claim_next` 不领取 `COMPLETED`；回滚排空集合不包含它。campaign 不再用 `INCONCLUSIVE` 表示搜索完成；`INCONCLUSIVE` 仍只表示复现判定未形成结论。v1 终态枚举不变。迁移 007 允许的 `state='INCONCLUSIVE'`、`verdict=NULL`、`evidence_status='archived'` 组合继续有效；新增 `COMPLETED` 的行为属于 T10 的迁移与实现，不在 007 中回改。

**family 归档索引与 `COMPLETED` 证据指针（D43 补充 D40）**。family 归档时落盘 `family.json` 作为 family index，`jobs.evidence_path` 指向该文件，`evidence_digest` 是该文件的 SHA-256，`evidence_status='archived'`，因此 007 的 `jobs_archived_evidence_check`（`evidence_status='archived'` ⇔ `evidence_path` 与 `evidence_digest` 均非空）自然成立，不允许 family 以 `evidence_status=NULL` 或空指针绕过。`family.json` 不是 v2 evidence bundle：不新增 `bundle_kind=family`、不新增 `family_index` 角色、不参与 `verify_bundle` 的 execution/blocked/campaign 分派，而是按第 8 节的 family index schema 单独校验。`export --family` 根目录的 `family.json` 与归档件字节一致，导出不得重写单轮 manifest。

**回滚排空门禁（D38）**。保留 `state.RELEASE_ACTIVE_STATES`（v1 3 状态：`PREPARING`、`RUNNING`、`ARCHIVING`），不破坏 v1 升级保留 `AWAITING_REVIEW` 的基线契约；新增 **v2 排空条件 SQL**，专门针对 `job_contract_version = 2` 检查 7 个非终态（`QUEUED`、`PREPARING`、`AWAITING_REVIEW`、`AGGREGATING`、`READY`、`RUNNING`、`ARCHIVING`）以及 `state = 'BLOCKED' AND workflow_synced = false`（v1 job 仍按既有 v1 3 状态判断，不因 v2 集合被误判为残留）。该分支查询由 `PostgresPromotionBackend.active_slots()` 与 `switch()`（含 `rollback` 分支，经 `_require_drained` 调用）共同执行；`rollback_release` 必须在 smoke 前后各执行一次 drain gate：smoke 前阻止带残留回滚，smoke 后、切换前再次确认没有新残留。回滚静默窗口必须对 `submit` 施加共享发布锁或入口停写，防止竞态插入新的 v2 `QUEUED` 任务。`release.ACTIVE_JOB_STATES` 目前未被使用，T10 必须把它与 `state.RELEASE_ACTIVE_STATES` 保持同步或直接删除，不能保留过期定义。

**迁移编号（D38）**。仓库迁移已到 `009_b03_acceptance.sql`；T10 新增迁移从 `010_*.sql` 起编号，不复用或改写既有编号。纯增量迁移在文件冻结后登记到 `release.ROLLBACK_COMPATIBLE_MIGRATIONS`（文件名 + 文件 SHA-256），未登记导致回滚阻断属于预期行为，不是缺陷；不得用运行时计算摘要替代白名单。

版本围栏：v2 worker 领取时按 `job_contract_version = 2` 过滤；已部署的 v1 worker 不认识该字段。本版采用**排空/静默**，不引入独立队列表：回滚到 v1 前必须排空上述 v2 非终态 job，并由回滚 gate 阻断任何残留。`AWAITING_REVIEW` 有 24 小时审核窗口，是运行中最常停留的状态，不能漏在排空集合外。CHECK 只防脏数据，不能防旧 worker 误领。

v1 读取边界：v1 控制面只承诺读取 v1 时代数据；回滚后 v2 终态证据由保留的 v2 只读 verifier/export 服务读取，不在 v1 代码中增加 v2 plan/evidence 解析。

T09 只冻结结构；迁移脚本由 T10 新增，既有 v1 任务不执行在线回填。

## 8. Evidence v2

### manifest

v2 manifest 保留 v1 的 `verdict`、`reason_code`、`created_at`，并新增 family/轮次身份、信封与构建规则版本、`build_ref` 与 `reuse_origin`。`files` 列出的角色必须覆盖该 `bundle_kind` 的必需角色，不得只放 report 与一个 `build.log`。

```json
{
  "schema_version": 2,
  "bundle_kind": "execution",
  "family_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "job_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "parent_job_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "round_no": 2,
  "plan_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000d",
  "envelope_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000005",
  "experiment_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000013",
  "build_provenance_rules_version": "build-provenance-v1",
  "verdict": "INCONCLUSIVE",
  "reason_code": "EVIDENCE_INCOMPLETE",
  "created_at": "2099-01-01T00:00:00Z",
  "build_ref": {
    "source_job_id": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "generation": 3,
    "build_inputs_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000008",
    "artifacts": {
      "vulnerable": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000006",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000007"
      },
      "fixed": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000011",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000012"
      }
    }
  },
  "reuse_origin": {
    "source_job_id": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "generation": 3,
    "campaign_bundle_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000e",
    "artifacts": {
      "vulnerable": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000006",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000007"
      },
      "fixed": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000011",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000012"
      }
    }
  },
  "files": [
    {"path": "report.json", "role": "report_json", "size_bytes": 4096, "sha256": "000000000000000000000000000000000000000000000000000000000000000f"},
    {"path": "report.md", "role": "report_markdown", "size_bytes": 2048, "sha256": "000000000000000000000000000000000000000000000000000000000000002d"},
    {"path": "plan.json", "role": "plan", "size_bytes": 8192, "sha256": "0000000000000000000000000000000000000000000000000000000000000029"},
    {"path": "admission.json", "role": "admission", "size_bytes": 1024, "sha256": "000000000000000000000000000000000000000000000000000000000000002a"},
    {"path": "envelope.json", "role": "envelope", "size_bytes": 2048, "sha256": "000000000000000000000000000000000000000000000000000000000000002b"},
    {"path": "budget/snapshot.json", "role": "budget_snapshot", "size_bytes": 512, "sha256": "000000000000000000000000000000000000000000000000000000000000002c"},
    {"path": "budget/ledger.json", "role": "budget_ledger", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000025"},
    {"path": "budget/charges.json", "role": "budget_charge", "size_bytes": 1024, "sha256": "0000000000000000000000000000000000000000000000000000000000000026"},
    {"path": "experiments/spec-1.json", "role": "experiment_spec", "size_bytes": 1024, "sha256": "0000000000000000000000000000000000000000000000000000000000000027"},
    {"path": "model/audit.json", "role": "model_audit", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000030"},
    {"path": "metadata/execution.json", "role": "execution_metadata", "size_bytes": 1024, "sha256": "0000000000000000000000000000000000000000000000000000000000000031"},
    {"path": "metadata/probe.json", "role": "probe", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000032"},
    {"path": "metadata/case.json", "role": "case_config", "size_bytes": 2048, "sha256": "0000000000000000000000000000000000000000000000000000000000000033"},
    {"path": "build/vulnerable/metadata.json", "role": "build_metadata", "size_bytes": 1024, "sha256": "0000000000000000000000000000000000000000000000000000000000000019"},
    {"path": "build/vulnerable/build.log", "role": "build_log", "size_bytes": 8192, "sha256": "000000000000000000000000000000000000000000000000000000000000001a"},
    {"path": "build/vulnerable/build_provenance/compile_commands.json", "role": "build_provenance", "size_bytes": 4096, "sha256": "000000000000000000000000000000000000000000000000000000000000001b"},
    {"path": "build/vulnerable/parser", "role": "build_artifact", "size_bytes": 65536, "sha256": "000000000000000000000000000000000000000000000000000000000000001c"},
    {"path": "build/fixed/metadata.json", "role": "build_metadata", "size_bytes": 1024, "sha256": "000000000000000000000000000000000000000000000000000000000000001d"},
    {"path": "build/fixed/build.log", "role": "build_log", "size_bytes": 8192, "sha256": "000000000000000000000000000000000000000000000000000000000000001e"},
    {"path": "build/fixed/build_provenance/compile_commands.json", "role": "build_provenance", "size_bytes": 4096, "sha256": "000000000000000000000000000000000000000000000000000000000000001f"},
    {"path": "build/fixed/parser", "role": "build_artifact", "size_bytes": 65536, "sha256": "0000000000000000000000000000000000000000000000000000000000000020"},
    {"path": "replay/vulnerable/normal/stdout.log", "role": "normal_output", "size_bytes": 256, "sha256": "0000000000000000000000000000000000000000000000000000000000000040"},
    {"path": "replay/vulnerable/normal/stderr.log", "role": "normal_error", "size_bytes": 128, "sha256": "0000000000000000000000000000000000000000000000000000000000000041"},
    {"path": "replay/vulnerable/normal/metadata.json", "role": "replay_metadata", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000042"},
    {"path": "replay/vulnerable/candidate_1/stdout.log", "role": "replay_stdout", "size_bytes": 256, "sha256": "0000000000000000000000000000000000000000000000000000000000000043"},
    {"path": "replay/vulnerable/candidate_1/stderr.log", "role": "asan_log", "size_bytes": 2048, "sha256": "0000000000000000000000000000000000000000000000000000000000000044"},
    {"path": "replay/vulnerable/candidate_1/metadata.json", "role": "replay_metadata", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000045"},
    {"path": "replay/vulnerable/candidate_2/stdout.log", "role": "replay_stdout", "size_bytes": 256, "sha256": "0000000000000000000000000000000000000000000000000000000000000046"},
    {"path": "replay/vulnerable/candidate_2/stderr.log", "role": "asan_log", "size_bytes": 2048, "sha256": "0000000000000000000000000000000000000000000000000000000000000047"},
    {"path": "replay/vulnerable/candidate_2/metadata.json", "role": "replay_metadata", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000048"},
    {"path": "replay/fixed/normal/stdout.log", "role": "normal_output", "size_bytes": 256, "sha256": "0000000000000000000000000000000000000000000000000000000000000049"},
    {"path": "replay/fixed/normal/stderr.log", "role": "normal_error", "size_bytes": 128, "sha256": "000000000000000000000000000000000000000000000000000000000000004a"},
    {"path": "replay/fixed/normal/metadata.json", "role": "replay_metadata", "size_bytes": 512, "sha256": "000000000000000000000000000000000000000000000000000000000000004b"},
    {"path": "replay/fixed/candidate_1/stdout.log", "role": "replay_stdout", "size_bytes": 256, "sha256": "000000000000000000000000000000000000000000000000000000000000004c"},
    {"path": "replay/fixed/candidate_1/stderr.log", "role": "asan_log", "size_bytes": 2048, "sha256": "000000000000000000000000000000000000000000000000000000000000004d"},
    {"path": "replay/fixed/candidate_1/metadata.json", "role": "replay_metadata", "size_bytes": 512, "sha256": "000000000000000000000000000000000000000000000000000000000000004e"},
    {"path": "replay/fixed/candidate_2/stdout.log", "role": "replay_stdout", "size_bytes": 256, "sha256": "000000000000000000000000000000000000000000000000000000000000004f"},
    {"path": "replay/fixed/candidate_2/stderr.log", "role": "asan_log", "size_bytes": 2048, "sha256": "0000000000000000000000000000000000000000000000000000000000000050"},
    {"path": "replay/fixed/candidate_2/metadata.json", "role": "replay_metadata", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000051"},
    {"path": "intel/snapshot.json", "role": "intel_snapshot", "size_bytes": 4096, "sha256": "0000000000000000000000000000000000000000000000000000000000000017"},
    {"path": "intel/license.json", "role": "license_record", "size_bytes": 512, "sha256": "0000000000000000000000000000000000000000000000000000000000000018"}
  ]
}
```

| 字段 | 规则 |
| --- | --- |
| `schema_version` | `1` 或 `2`；校验器先读该字段再分派 |
| `bundle_kind` | `execution`、`blocked` 或 `campaign`；复用型 validation 仍用 `execution` |
| `family_id` / `parent_job_id` / `round_no` | `execution`/`campaign` 必填；`blocked` 可为 null；round 的 `family_id=parent_job_id`、`round_no>=1`；campaign 的 `round_no=null`、`family_id=parent_job_id` |
| `plan_digest` | `execution`/`campaign` 必填；`blocked` 可为 null（计划未冻结时） |
| `envelope_digest` | `execution`/`campaign` 必填；fixed 同样非空；`blocked` 可为 null |
| `experiment_digest` | validation 的 ExperimentSpec 摘要；fixed 与 campaign 为 null；`blocked` 可为 null |
| `build_provenance_rules_version` | BuildSpec/归一化/核对面解析器的合并版本；`execution`/`campaign` 必填，`blocked` 可为 null |
| `verdict` / `reason_code` | `execution` 为终态枚举，`reason_code` 必须属于该终态的封闭集合；`campaign` 两者均为 null；`blocked` 固定 `verdict=BLOCKED` 且 `reason_code` 属于 `BLOCKED` 集合 |
| `created_at` | UTC RFC 3339 时间；`execution`/`campaign`/`blocked` 都必填 |
| `build_ref` | `reuse_origin != null` 时必填；fixed/non-reuse 必须为 null；campaign 必须为 null |
| `reuse_origin` | 复用型 validation 必填并指向 campaign；fixed/normal execution 为 null；campaign 为 null |
| `files` | 路径、角色、字节数、SHA-256；角色必须来自 v2 封闭角色表，路径必须符合“固定路径”表；完整 validation 必须列出六组回放的 18 个条目 |

validation 与 fixed execution 包必须包含 `metadata/execution.json`、`metadata/probe.json`、`metadata/case.json`、两版 `build_metadata`、`build_log`、`build_artifact` 与 `build_provenance`（按分阶段生效规则）、六组回放的 `stdout.log`/`stderr.log`/`metadata.json`（18 个条目），以及 `envelope` 与 `budget_snapshot`；campaign 包必须包含两版 `build_metadata`/`build_log`/`build_artifact`/`build_provenance`、fuzz 日志与 fuzz provenance（不含 18 个回放文件），记录到候选 crash seed 时还必须包含 crash seed 与对应 provenance；0 crash 的 campaign 允许没有 `crash_seed`，验包不得因此失败。campaign 包与复用型 validation 包的两版 `build_artifact` 同时包含 parser 与 fuzzer 两个产物（改9）；validation 复用 campaign 两版的这两个产物。`reuse_origin.artifacts` 必须与 plan `build_ref.artifacts` 逐字段相等；不一致返回 `REUSE_MISMATCH`，plan 的 `build_ref` 是唯一权威。复用型 validation 的每版 artifacts 为 `{artifact_digest, build_log_digest, fuzzer_digest}`：`artifact_digest` 绑 `build/{version}/parser`，`fuzzer_digest` 绑 `build/{version}/fuzzer`，二者与 `build.log` 的字节摘要任一不符即 `REUSE_MISMATCH`（改9 增补）；`build_inputs_digest` 为 `digest_json({build_recipe_digest, build_spec, compile_flags, image_digest, staged_materials})`，只覆盖构建材料、工具链与 BuildSpec。

### 固定路径

v2 沿用 v1 的固定路径，不另起目录；新角色使用下列新路径（D39）。清单按逻辑内容、角色与路径三元组固定，验包按 `role` 与路径后缀双重核对：

| 逻辑内容 | 角色 | 路径 |
| --- | --- | --- |
| 执行元数据 | `execution_metadata` | `metadata/execution.json` |
| 环境探针 | `probe` | `metadata/probe.json` |
| 案例配置 | `case_config` | `metadata/case.json` |
| 构建日志 / 元数据 / 产物 | `build_log` / `build_metadata` / `build_artifact` | `build/{version}/build.log`、`build/{version}/metadata.json`、`build/{version}/parser`（默认单产物归档名；多产物或自定义目标名按 `BuildSpec.outputs` 相对路径映射到 `build/{version}/` 下） |
| 构建核对面 | `build_provenance` | `build/{version}/build_provenance/compile_commands.json`（cmake）、`build/{version}/build_provenance/cc-shim.log`（make）、`build/{version}/build_provenance/shell-face.log`（shell） |
| 回放六组 | `replay_stdout`/`normal_output`、`replay_stderr`/`normal_error`/`asan_log`、`replay_metadata` | `replay/{version}/{phase}/stdout.log`、`replay/{version}/{phase}/stderr.log`、`replay/{version}/{phase}/metadata.json`；`version ∈ {vulnerable,fixed}`，`phase ∈ {normal,candidate_1,candidate_2}` |
| 计划 / 人批 / 准入 | `plan`、`review`、`admission` | `plan.json`、`review.json`、`admission.json` |
| 信封 / 预算 | `envelope`、`budget_snapshot`、`budget_ledger`、`budget_charge` | `envelope.json`、`budget/snapshot.json`、`budget/ledger.json`、`budget/charges.json` |
| 实验 / 模型 / 情报 | `experiment_spec`、`model_audit`、`intel_snapshot`、`license_record` | `experiments/*.json`、`model/audit.json`、`intel/snapshot.json`、`intel/license.json` |

上述 18 个回放条目按两版 × 三阶段 × 三文件展开；normal 阶段的 `stdout.log` 用 `normal_output`、`stderr.log` 用 `normal_error`，candidate 阶段的 `stdout.log` 用 `replay_stdout`、`stderr.log` 用 `asan_log`，每个阶段都有 `replay_metadata`。`review` 与 `admission` 仍按轮次二选一：人批轮次放 `review.json`，policy 轮次放 `admission.json`。路径不得使用“同上”省略，也不得把构建元数据写成 `build_metadata.json` 等与实现不一致的名字。

### family 归档索引（D43）

family 的归档物是 `family.json`（路径为 family 证据目录根的 `family.json`），它是 **family index**，不是 v2 evidence bundle。它有自己的 `kind="family_index"` 与 `schema_version=2`，不进入 `bundle_kind` 枚举，不新增 `family_index` 文件角色，也不参与 `verify_bundle` 的 execution/blocked/campaign 分派；校验器按本节的 family index schema 单独校验。`export --family` 的输出根目录同样是这个 `family.json`，且与归档件字节一致；它只索引轮次与摘要，不重写任何单轮 manifest。

```json
{
  "schema_version": 2,
  "kind": "family_index",
  "family_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "state": "COMPLETED",
  "created_at": "2099-01-01T00:00:00Z",
  "family_approval_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000052",
  "rounds": [
    {
      "round_no": 1,
      "job_id": "3b7e1f2a-5c6d-4e8f-9012-3456789abcde",
      "plan_digest": "sha256:000000000000000000000000000000000000000000000000000000000000002e",
      "state": "INCONCLUSIVE",
      "evidence_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000053"
    },
    {
      "round_no": 2,
      "job_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
      "plan_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000d",
      "state": "INCONCLUSIVE",
      "evidence_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000054"
    }
  ],
  "campaign": {
    "job_id": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "bundle_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000e"
  },
  "budget": {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 540,
    "spent_fuzz_seconds": 180,
    "remaining_seconds": 360,
    "remaining_fuzz_seconds": 120
  }
}
```

| 字段 | 规则 |
| --- | --- |
| `schema_version` / `kind` | 固定 `2` 与 `family_index`；未知值失败关闭 |
| `family_id` | 必须等于 family job；`state` 固定 `COMPLETED` |
| `created_at` | UTC RFC 3339；family 归档时间 |
| `rounds[]` | 每个已完成 round 一条，含 `round_no`、`job_id`、`plan_digest`、`state`、`evidence_digest`；按 `round_no` 升序，不复制单轮 report |
| `campaign` | guided family 为 campaign 的 `job_id` 与 `bundle_digest`；fixed family 为 `null` |
| `budget` | 6 个字段，与 report `budget` 同口径，可由 `budget_charges` 按 family 重建 |
| `family_approval_digest` | 当前 approval 链尾的 `approval_digest`，必须能在 `family_approvals` 中解析 |

`family.json` 的 `evidence_digest` 是单轮证据摘要的索引值，不是把单轮 manifest 内联进来；`export --family` 只复制单轮目录并复用同一索引。family 归档时 `jobs.evidence_path` 指向该 `family.json`、`jobs.evidence_digest` 为其 SHA-256、`jobs.evidence_status='archived'`；缺该文件或摘要不符时归档失败，不得把 `state=COMPLETED` 写成 `evidence_status=NULL`。campaign 自己的归档物仍是 campaign bundle（`bundle_kind=campaign`），不受本节影响。

### 文件角色

v2 角色表由“v0.1 完整角色集 + v0.2 新增角色集”组成，不是只写“继承 v1”。v0.1 的 27 个角色全部保留且语义不变：

| 分组 | 角色 |
| --- | --- |
| v0.1 基础 | `report_json`、`report_markdown`、`plan`、`review`、`execution_metadata`、`probe` |
| v0.1 构建 | `build_log`、`build_metadata`、`build_artifact` |
| v0.1 回放 | `normal_output`、`normal_error`、`asan_log`、`replay_stdout`、`replay_stderr`、`replay_metadata` |
| v0.1 材料 | `material_harness`、`material_build_recipe`、`material_dependencies`、`material_input_normal`、`material_input_candidate`、`material_source_vulnerable`、`material_source_fixed`、`material_patch`、`material_repository_bundle`、`material_advisory` |
| v0.1 案例 | `case_config`、`symbolizer_log` |
| v0.2 新增 | `envelope`、`budget_snapshot`、`build_provenance`、`admission`、`budget_ledger`、`budget_charge`、`experiment_spec`、`model_audit`、`fuzz_log`、`crash_seed`、`fuzz_provenance`、`intel_snapshot`、`license_record` |

`build_provenance` 存放核对面原文（`compile_commands.json`、`cc-shim` 日志、shell 审核日志），两个版本各一份。v2 必需角色：

| `bundle_kind` | 必需角色 |
| --- | --- |
| `execution`（fixed 人批轮次） | `report_json`、`report_markdown`、`plan`、`review`、`execution_metadata`（`metadata/execution.json`）、`probe`（`metadata/probe.json`）、`case_config`（`metadata/case.json`）、`envelope`、`budget_snapshot`、六组回放的 `normal_output`/`normal_error`/`asan_log`/`replay_stdout`/`replay_stderr`/`replay_metadata`（18 个文件）、两版 `build_metadata`/`build_log`/`build_artifact`/`build_provenance` |
| `execution`（policy 准入轮次） | `report_json`、`report_markdown`、`plan`、`admission`、`execution_metadata`、`probe`、`case_config`、`envelope`、`budget_snapshot`、六组回放的 18 个文件、两版 `build_metadata`/`build_log`/`build_artifact`/`build_provenance` |
| `campaign` | `report_json`、`report_markdown`、`plan`、`review`、`execution_metadata`、`probe`、`case_config`、`envelope`、`budget_snapshot`、两版 `build_metadata`/`build_log`/`build_artifact`/`build_provenance`、`fuzz_log`、`fuzz_provenance`、`crash_seed`（记录 ≥1 条候选 crash seed 时必需）；**不含** 18 个回放文件 |
| `blocked` | `report_json`、`report_markdown` |

分阶段生效：`build_provenance` 在 T13 落地后成为 `execution`/`campaign` 的必需角色；`model_audit` 在 T14 落地后成为 `execution`/`campaign` 的必需角色；`intel_snapshot`、`license_record` 在 T15 落地后成为必需角色（离线案例也要有快照）。T10/T12 验收只要求上述角色枚举存在、文件出现时角色合法，不得因尚未实现的 T13/T14/T15 而验包失败（避免阻塞 T12 与 T13 并行）。

### `model/audit.json`（`model_audit` 角色完整 schema）

`model/audit.json` 以 `model_audit` 文件角色归档，完整包含以下 11 个封闭字段（与 [安全设计增量](security-design-delta.md) 第 2.3 节对齐）；`report.model_audit` 则是它的 6 字段摘要（`provider`、`model_version`、`prompt_version`、`allowed_fields_digest`、`redaction_version`、`outcome`）：

```json
{
  "job_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "stage": "hypothesis_aggregator",
  "provider": "offline",
  "model_version": null,
  "prompt_version": null,
  "allowed_fields_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000014",
  "redaction_version": "redaction-v1",
  "request_digest": null,
  "response_digest": null,
  "duration_seconds": 0,
  "outcome": "offline"
}
```

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `job_id` | uuid | 产生本次审计的 child job ID |
| `stage` | string | 触发节点或阶段名（如 `patch`、`source`、`hypothesis_aggregator`） |
| `provider` | string | 模型供应方标识；离线模式固定为 `"offline"`，不得为 null 或空串 |
| `model_version` | string \| null | 模型版本标识；offline 时固定为 `null` |
| `prompt_version` | string \| null | 提示词模板版本标识；offline 时固定为 `null` |
| `allowed_fields_digest` | digest | 送出允许字段集合的规范化 SHA-256；online/offline 均必填 |
| `redaction_version` | string | 脱敏规则版本；online/offline 均必填 |
| `request_digest` | digest \| null | 脱敏后请求正文的 SHA-256；offline 时固定为 `null` |
| `response_digest` | digest \| null | 模型原始响应正文的 SHA-256；offline 时固定为 `null` |
| `duration_seconds` | number | 调用耗时（非负秒数）；offline 时固定为 `0` |
| `outcome` | string | 结果状态（如 `offline`、`ok`、`timeout`、`rejected`、`fallback_offline`）；offline 时固定为 `"offline"` |

v2 `execution` 恰好包含 `review` 或 `admission` 之一，不得两者都缺，也不得用两者互相代替；`campaign` 与 fixed 人批轮次的 `review.json` 是 family 人批决议的副本，路径仍在包根目录，校验以 `plan_digest` 绑定，不以包内 `job_id` 绑定。文件角色只扩展，不改变 v1 已有角色语义；v1 角色集合仍由冻结分支维护。

### `intel/snapshot.json` 与 `intel/license.json`（`intel_snapshot` / `license_record` 完整 schema）

两个情报文档的形状由 T15 提出并经规范 owner 评审认可（PR #60）。快照文档承载注册身份、采集事实与快照原字节；许可文档承载同一注册身份与授予。两份文档的键集均封闭。

```json
// intel/snapshot.json（role: intel_snapshot）
{
  "case_id": "cve-2099-0001",
  "source_id": "advisory-primary",
  "snapshot_digest": "sha256:…",          // 恰好对 body 的原字节求值
  "source_url": "https://advisory.example.com/cve-2099-0001.txt",
  "license": "CC-BY-4.0",                 // 未登记时为 null，缺口保持可见
  "fetched_at": "2026-11-26T00:00:00Z",   // 以下四项：没有采集记录时 redirect 与三者同为 null
  "http_status": 200,
  "redirect_chain_digest": "sha256:…",    // 未跟随重定向或无采集记录时为 null
  "tool_version": "datacon.intel_fetch/0.1.0",
  "body_base64": "…"                      // 正文原字节的规范 base64
}

// intel/license.json（role: license_record）
{
  "case_id": "cve-2099-0001",
  "source_id": "advisory-primary",
  "source_url": "https://advisory.example.com/cve-2099-0001.txt",
  "snapshot_digest": "sha256:…",          // 这份许可覆盖的那个快照
  "license": "CC-BY-4.0",
  "permitted_uses": ["research", "reproduction"]
}
```

| 字段 | 规则 |
| --- | --- |
| `case_id` / `source_id` | 非空文本。`case_id` 必须与所在包的 plan/report 一致（`SOURCE_CONFLICT`/`SOURCE_CASE_MISMATCH`）；`source_id` 无离线锚点，仅供展示，待注册摘要随 plan 归档后再绑定 |
| `snapshot_digest` | sha256 摘要，恰好描述 `body_base64` 解码后的字节 |
| `source_url` | 去凭据后的 https 源（`public_source_url` 规则）；无法归因 → `POLICY_DENIED`/`SOURCE_URL_INVALID` |
| `license` | 许可标识或 null（缺口可见，由许可判定拒绝） |
| `fetched_at` / `http_status` / `tool_version` | 采集事实，三者同有同无；`http_status` 为 100–599 的整数 |
| `redirect_chain_digest` | 摘要或 null；没有采集记录时必须为 null |
| `body_base64` | 正文原字节的规范 base64 拼写；解码后不得超过采集上限（32 MiB，文档最坏约 43 MiB，仍在包读取的 128 MiB 单文件上限内）；离线案例与 `materials/advisory` 的字节重复是自校验包的已知代价 |
| `permitted_uses` | 互异用途名组成的 JSON 数组；空数组是「什么都没授予」的合规记录 |

验包绑定（`execution`/`campaign` 调用，`blocked` 不携带这两份文档）：两份文档的五个共享字段一致；`report.intel` 是封闭三字段摘要且与快照文档一致；`plan.intel` 按 `contracts` 的封闭规则校验（四字段、`sources` 非空且全 https、无未知键）后绑定 `content_digest` 与 `collected_at`，且 `sources`（本次分析采信的来源）必须包含快照的 `source_url`（两侧去凭据后比较；plan 生成侧负责把线上抓取的来源加进 `sources`，而不是放宽验包）。最后仅凭归档的许可授予离线重推许可判定：不覆盖系统用途 → `POLICY_DENIED`/`LICENSE_REJECTED`。验包可出现的细因记号：`SNAPSHOT_DOCUMENT_INVALID`、`LICENSE_DOCUMENT_INVALID`、`INTEL_REGISTRATION_INVALID`、`INTEL_BINDING_MISMATCH`、`SOURCE_URL_MISMATCH`、`LICENSE_MISMATCH`（后两者为构造时记录与注册矛盾的细因）；`SOURCE_CASE_MISMATCH` 沿用 §10 既有记号。

### report

```json
{
  "schema_version": 2,
  "bundle_kind": "execution",
  "family_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "job_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "parent_job_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "round_no": 2,
  "plan_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000d",
  "envelope_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000005",
  "verdict": "INCONCLUSIVE",
  "state": "INCONCLUSIVE",
  "reason_code": "EVIDENCE_INCOMPLETE",
  "build_ref": {
    "source_job_id": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "generation": 3,
    "build_inputs_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000008",
    "artifacts": {
      "vulnerable": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000006",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000007"
      },
      "fixed": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000011",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000012"
      }
    }
  },
  "build_provenance": {
    "vulnerable": {
      "face": "compile_commands.json",
      "declared": ["-fsanitize=address", "-g", "-O1", "-Iinclude", "-D_GNU_SOURCE"],
      "effective": ["-fsanitize=address", "-g", "-O1", "-Iinclude", "-D_GNU_SOURCE"]
    },
    "fixed": {
      "face": "compile_commands.json",
      "declared": ["-fsanitize=address", "-g", "-O1", "-Iinclude", "-D_GNU_SOURCE"],
      "effective": ["-fsanitize=address", "-g", "-O1", "-Iinclude", "-D_GNU_SOURCE"]
    },
    "comparable": true
  },
  "experiment_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000013",
  "build_provenance_rules_version": "build-provenance-v1",
  "model_audit": {
    "provider": "offline",
    "model_version": null,
    "prompt_version": null,
    "allowed_fields_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000014",
    "redaction_version": "redaction-v1",
    "outcome": "offline"
  },
  "intel": {
    "snapshot_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000015",
    "license": "MIT",
    "redirect_chain_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000016"
  },
  "replays": [
    {
      "version": "vulnerable",
      "phase": "normal",
      "status": "completed",
      "input_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000a"
    },
    {
      "version": "vulnerable",
      "phase": "candidate_1",
      "status": "completed",
      "input_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000009"
    },
    {
      "version": "vulnerable",
      "phase": "candidate_2",
      "status": "completed",
      "input_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000009"
    },
    {
      "version": "fixed",
      "phase": "normal",
      "status": "completed",
      "input_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000a"
    },
    {
      "version": "fixed",
      "phase": "candidate_1",
      "status": "completed",
      "input_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000009"
    },
    {
      "version": "fixed",
      "phase": "candidate_2",
      "status": "completed",
      "input_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000009"
    }
  ],
  "admissions": [
    {
      "round_no": 2,
      "approval_kind": "policy"
    }
  ],
  "experiments": [
    {
      "target_symbol": "parse_token",
      "input_family": "length_boundary",
      "evidence_refs": [
        "log/build:fixed#L10-12",
        "log/fuzz:0#L42"
      ]
    }
  ],
  "budget": {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 540,
    "spent_fuzz_seconds": 180,
    "remaining_seconds": 360,
    "remaining_fuzz_seconds": 120
  },
  "reuse_origin": {
    "source_job_id": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "generation": 3,
    "campaign_bundle_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000e",
    "artifacts": {
      "vulnerable": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000006",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000007"
      },
      "fixed": {
        "artifact_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000011",
        "build_log_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000012"
      }
    }
  }
}
```

示例为节选：v0.1 的 `missing`、`error`、`evidence_complete` 等报告字段继续保留且语义不变，本节只列 v2 新增与变更字段。

| 字段 | 规则 |
| --- | --- |
| `schema_version` / `bundle_kind` | `2`；`execution`、`blocked` 或 `campaign` |
| `family_id` / `job_id` / `parent_job_id` / `round_no` | round 的 `family_id=parent_job_id`、`round_no>=1`；campaign 的 `round_no=null`；`blocked` 可为 null |
| `plan_digest` | 必须与 manifest 和 plan 一致；`blocked` 可为 null |
| `envelope_digest` | `execution`/`campaign` 必填；fixed 同样非空；`blocked` 可为 null |
| `verdict` / `state` | 必须相等；`execution` 为终态枚举；campaign 的 report `verdict`/`state` 均为 null（job 的 `state` 是另一字段，见第 9 节） |
| `reason_code` | 必须属于 `verdict` 的封闭集合；campaign 为 null；blocked 记录阻断原因 |
| `experiment_digest` / `build_provenance_rules_version` | validation 的实验摘要与构建规则版本；fixed/campaign 的 `experiment_digest` 为 null |
| `model_audit` | `model/audit.json` 的 6 字段摘要（`provider`、`model_version`、`prompt_version`、`allowed_fields_digest`、`redaction_version`、`outcome`）；完整 11 字段审计由 `model_audit` 文件角色归档。offline 也必须写 `provider=offline`、`outcome=offline`，版本字段写 null；不得省略该对象或把 `provider` 置空 |
| `intel` | 情报摘要对象（快照摘要、许可标识、重定向链摘要）；原始快照与许可正文分别以 `intel_snapshot`、`license_record` 文件角色归档。离线案例同样需要快照，不因离线而省略 |
| `build_ref` | `reuse_origin != null` 时必填；fixed/non-reuse 必须为 null；campaign 必须为 null |
| `build_provenance` | 两版声明、生效、核对面与 `comparable`；`execution` 与 `campaign` 均必填（仅 `blocked` 可省略） |
| `replays` | 完整 validation 恰好六项；campaign 不要求 |
| `admissions` | 轮次准入摘要；不复制 `reviews` |
| `experiments` | ExperimentSpec 摘要与结果引用（含对应 `evidence_refs`） |
| `budget` | family 预算汇总，必须含 `max_total_seconds`、`max_fuzz_seconds`、`spent_seconds`、`spent_fuzz_seconds`、`remaining_seconds`（对应 DB 列 `remaining_total_seconds`）、`remaining_fuzz_seconds`，并能由 `budget_charges` 重建 |
| `reuse_origin` | 复用型 validation 指向 campaign；fixed/normal execution 为 null；campaign 为 null |
| `fuzz` | 改9 增补：只出现在 campaign report，execution/blocked 不带；封闭对象 `{engine, status, rng_seed, fuzz_log_digest, crash_count, crash_seeds}`，`engine` 固定 `libfuzzer`，`status` 为 fuzz 搜索状态（`COMPLETED` campaign 恒为 `completed`），`rng_seed` 为确定性 libFuzzer `-seed`，`fuzz_log_digest` 为 `fuzz/fuzz.log` 的 SHA-256，`crash_seeds` 每项 `{path, sha256}`；与 `fuzz/provenance.json` 同口径，`crash_count` 等于 `crash_seeds` 项数，每项与一个 `crash_seed` 文件及 provenance 中同 `path`/`sha256` 的记录一一对应；只是搜索观测，不产 verdict |
| `evidence_refs` | 位于 `report` 发现项或 `experiments[]` 内的可解析构建、回放、fuzz 引用（语法见第 11 节）；越界、日志缺失或摘要不符视为不可解析并失败 |

`replays` 在完整 validation 报告中必须恰好覆盖两版的 `normal`、`candidate_1`、`candidate_2` 六项。campaign report 的 `verdict` 与 `reason_code` 为 null，不要求六次回放，但必须记录搜索观测、候选 seed 与 provenance。`spent_seconds` 与 `spent_fuzz_seconds` 必须等于 `budget_charges` 中 `seconds` 与 `fuzz_seconds` 的 family 汇总；不一致即证据不可对账。

## 9. CLI 变化

| 命令 | v0.2 行为 |
| --- | --- |
| `datacon submit --request request.json` | 接受 Request v2；`exploration` 缺省为 fixed；**返回 family job_id**，而不是首份 child 的 job_id |
| `datacon status JOB_ID` | family job 返回 `family`、`campaign`、`rounds` 与 `budget`，运行中 `state` 为 `AGGREGATING`、归档后为 `COMPLETED`；child job 返回单轮视图 |
| `datacon export JOB_ID --out DIR` | 导出单个轮次或 campaign 的 v2 包；v1 包仍按 v1 导出 |
| `datacon export --family FAMILY_ID --out DIR` | 聚合导出 family；每个轮次目录仍是独立 bundle，campaign 单独目录归档；根 `family.json` 是 family index（D43），与 family 归档件字节一致 |
| `datacon verify-bundle DIR` | 先读 `manifest.schema_version` 再分派；v1 只读校验，v2 校验新字段 |
| `datacon propose-envelope FAMILY_ID --request envelope.json` | 发起换信封重批入口：校验请求信封不扩大案例注册表上限（含 `mutation_limits`、签名集合与预算上限），且 family 处于 `AGGREGATING`，写入新 `family_envelopes(status='pending', review_deadline_at=clock_timestamp() + interval '24 hours')`；受单 `pending` partial unique index 保护（已有 `pending` 时拒绝） |
| `datacon review JOB_ID --plan-digest DIGEST [--envelope-digest DIGEST] --decision approve\|reject` | `JOB_ID` 是 **family job_id**；`--plan-digest` 始终必须等于 `first_plan_digest`（`--plan-digest` 不能指向后续轮次计划）。`--envelope-digest` 在首轮人批可省略，缺省解析为首份 plan 的 `envelope_digest`；换信封重批必须显式提供且等于 family 当前 `pending` 信封摘要，否则按 9.1 校验顺序返回对应结果或 `REVIEW_ENVELOPE_MISMATCH`。首份计划人批写 `reviews`（job_id=family）与 `family_approvals`，child `AWAITING_REVIEW` → `READY`；换信封重批只追加 `family_approvals` 新行，不重写 `reviews`（`UNIQUE(job_id)` 只承载首条）；不接受 policy 冒充人工决议。完整状态迁移、信封生命周期与幂等规则见 9.1 |

`status` 返回示例（guided family，child 串行执行）：

```json
{
  "job_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
  "state": "AGGREGATING",
  "family": {
    "family_id": "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11",
    "max_rounds": 8,
    "rounds_used": 2
  },
  "campaign": {
    "job_id": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "round_no": null,
    "state": "COMPLETED",
    "plan_digest": "sha256:000000000000000000000000000000000000000000000000000000000000002f",
    "admission_kind": "human",
    "verdict": null,
    "evidence_status": "archived",
    "reason_code": null
  },
  "rounds": [
    {
      "round_no": 1,
      "job_id": "3b7e1f2a-5c6d-4e8f-9012-3456789abcde",
      "state": "INCONCLUSIVE",
      "plan_digest": "sha256:000000000000000000000000000000000000000000000000000000000000002e",
      "admission_kind": "policy",
      "verdict": "INCONCLUSIVE",
      "evidence_status": "archived",
      "reason_code": "EVIDENCE_INCOMPLETE"
    },
    {
      "round_no": 2,
      "job_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
      "state": "INCONCLUSIVE",
      "plan_digest": "sha256:000000000000000000000000000000000000000000000000000000000000000d",
      "admission_kind": "policy",
      "verdict": "INCONCLUSIVE",
      "evidence_status": "archived",
      "reason_code": "EVIDENCE_INCOMPLETE"
    }
  ],
  "budget": {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 540,
    "spent_fuzz_seconds": 180,
    "remaining_seconds": 360,
    "remaining_fuzz_seconds": 120
  }
}
```

campaign 的 job `state` 在搜索结束/预算耗尽并归档后固定为 `COMPLETED`，只表示 campaign 完成，`verdict`/`reason_code` 仍为 null，campaign 不参与判定；job 的 `state`（`jobs` 表）与 report 的 `state` 不是同一字段，campaign report 的 `state`/`verdict` 均为 null。family job 运行期间 `state=AGGREGATING`，聚合归档后 `state=COMPLETED`；不得用 `INCONCLUSIVE` 表示 campaign 或 family 完成。fixed family 的 `campaign` 为 `null`，`rounds` 只有 `round_no=1`，该轮 `admission_kind="human"`。`admission_kind` 是派生展示字段：首份计划人批为 `human`（来自 `reviews`），轮次内为 `policy`（来自 `admissions`），没有决议时为 null；它不写数据库。family job 的 `state` 使用不可领取的 `AGGREGATING`，不得用 `RUNNING` 表示聚合。

### 9.1 审核状态同步与锁顺序

本节是审核状态与锁序的唯一权威表；其他文档只做摘要，冲突以本节为准。

审核对象是 family + 首份 child（D36）。`reviews.job_id` 挂在 family 上，但 `AWAITING_REVIEW` 与 `review_deadline_at` 只能落在首份 child 上，否则现有 worker 无法收敛超时。首份 child 定义为 `job_kind='campaign'`，或 fixed 模式的 `job_kind='round' AND round_no=1`。

**状态归属**。审核窗口期间 family 保持不可领取的 `AGGREGATING`；首份 child 持 `AWAITING_REVIEW` 与 `review_deadline_at`。后续 round child 不进入 `AWAITING_REVIEW`，只由 policy 准入。

**全局锁顺序**。所有同时涉及 family 与首份 child 的审核路径固定**先锁 family、再锁 child**，`record_review` 与 `expire_review` 都必须遵守。`expire_review` 先读取 child 的 `parent_job_id`（该列不可变，无需持锁），再按 family → child 加锁，重新校验 child 仍为 `AWAITING_REVIEW` 且 `generation`/lease 有效；lease 失效返回 `StaleGeneration` 且不改状态。

| 场景 | 加锁 | `family_envelopes` | child 状态 | family 状态 | 写入 |
| --- | --- | --- | --- | --- | --- |
| 首次 approve | family → 首份 child | `pending → approved` | `AWAITING_REVIEW → READY` | 保持 `AGGREGATING` | 同一事务写 `reviews(job_id=family)` 与 `family_approvals(supersedes=null)` |
| 首次 reject | family → 首份 child | `pending → rejected` | `AWAITING_REVIEW → BLOCKED(REVIEW_REJECTED)` | `AGGREGATING → BLOCKED(REVIEW_REJECTED)` | 写 `reviews`（reject）；不写 approval |
| 审核超时 | family → 首份 child（worker 调 `expire_review(child, generation)`） | `pending → expired` | `AWAITING_REVIEW → BLOCKED(REVIEW_EXPIRED)` | `AGGREGATING → BLOCKED(REVIEW_EXPIRED)` | 不写 approval；`reviews` 不变；审计 `review_expired`；归档 blocked bundle；child 与 family 两行同一事务 |
| 换信封重批 approve | 只锁 family | 新 `pending → approved` | 不变 | 保持 `AGGREGATING` | 追加 `family_approvals`，`supersedes` 指向链尾；不重写 `reviews` |
| 换信封重批 reject | 只锁 family | 新 `pending → rejected` | 不变 | `AGGREGATING → BLOCKED(REVIEW_REJECTED)` | 不写 approval；写审计 |
| 换信封重批超时 | 只锁 family（worker 定期扫描 `family_envelopes WHERE status='pending' AND review_deadline_at <= clock_timestamp()` 且对应 family 为 `AGGREGATING`） | 新 `pending → expired` | 不变 | `AGGREGATING → BLOCKED(REVIEW_EXPIRED)` | 写审计 `review_expired`；不改既有 `reviews` 与已完成 child |

**命令与信封身份（D42）**。命令形态为 `datacon review <family_id> --plan-digest <first_plan_digest> [--envelope-digest <digest>] --decision approve|reject`。首轮人批可省略 `--envelope-digest`，缺省解析为首份 plan 的 `envelope_digest`；换信封重批必须提供 `--envelope-digest`，且必须先通过 `datacon propose-envelope FAMILY_ID --request envelope.json` 写入待审信封（`status='pending'`、`review_deadline_at` 默认 24 小时），每个 family 至多一个 `pending`。`--plan-digest` 在任何情况下都必须等于 `first_plan_digest`（campaign plan 或 fixed round 1 plan 的 `plan_digest`），不符即拒绝且不写任何行。首份 plan 冻结时把首信封插入为 `pending`。

**幂等、冲突与 `REVIEW_ENVELOPE_MISMATCH` 校验顺序（D42）**。幂等键固定为五元组 `(family_id, first_plan_digest, envelope_digest, decision, reviewer_id)`，严格按以下三步顺序处理：
1. **先校验计划摘要**：校验 `--plan-digest == first_plan_digest`；不符即拒绝，不写任何行；
2. **再查目标信封状态**：按 `(family_id, envelope_digest)` 查询 `family_envelopes`：
   - 若记录已为 `approved`/`rejected`：匹配五元组 `(family_id, first_plan_digest, envelope_digest, decision, reviewer_id)` 返回 `idempotent`（不新增行），否则返回 `conflict`（不新增行）；
   - 若记录为 `expired`：返回 `expired`（不新增行）；
3. **最后判待审失配**：仅当 `(family_id, envelope_digest)` 不存在或非该 family 当前 `pending`（含首轮显式给出的摘要与首份 plan 不符）时，返回 `REVIEW_ENVELOPE_MISMATCH`（不写 `reviews`/`family_approvals`，首轮人批时 child 保持 `AWAITING_REVIEW`、换信封重批时 child 状态不变，family 保持 `AGGREGATING`）。

`reviews` 表结构不变且既有决议不因重批被改写；`family_approvals` 通过 `UNIQUE(family_id, envelope_digest)` 兜底。

**first_plan_digest 固定**。它固定为 family 首份 plan 摘要，不随换信封改变；新 `approval_digest` 通过 `envelope_digest`、`reviewer_id`、`decided_at` 的变化产生（`supersedes` 记录链关系，不进入摘要输入）。这样不会形成“approval 摘要包含计划、计划又引用 approval 摘要”的循环。后续 plan 使用新 approval digest，并校验其 `envelope_digest` 与 `family_approvals` 链尾一致。

`reviews` 只承载首条人批；换信封重批只追加 `family_approvals`，不改变 `reviews` 表结构。`record_review` 不再按同一个 `job_id` 查 `plans`，改为按 family 定位首份 child 及其 plan；该实现变更不修改 `reviews` 表结构。`decided_at` 参与哈希前统一渲染为 UTC RFC 3339 固定 6 位小数（`YYYY-MM-DDTHH:MM:SS.ffffffZ`）。

`export --family` 的输出目录结构固定为 `family.json`、`campaign/` 与 `rounds/<round_no>/`；`family.json` 记录轮次索引、预算与摘要，不改写任何单轮 manifest。

### 9.2 family 转移决策（改8）

campaign 完成且无候选 seed 时，runtime 记录 `no_next_round` 决策后 family 归档；无决策保持 `AGGREGATING`。该决策由 P1 的 state 入口承载，P2 的 runtime 调用：

```python
record_family_transition_decision(
    dsn, family_id, *,
    campaign_job_id, after_round_no, decision,
    reason_code=None, candidate_seed_count=None, next_round_no=None,
) -> dict
```

**决策点 `after_round_no`**（必填，非负整数，布尔值不算整数）：
- `0`：campaign child 归档 `COMPLETED` 后（边 #23/#24）。前置条件：family 尚无任何 `round` child。
- `k ≥ 1`：第 k 轮 round 归档后（边 #26）。前置条件：family 当前最大 `round_no` 恰为 k，round k 为 `INCONCLUSIVE`，不存在 `round_no > k` 的 child。

调用时机：campaign 归档后调用一次（`after_round_no=0`）；之后每轮 round 以 `INCONCLUSIVE` 归档、且 runtime 判定不再继续时调用一次（`after_round_no=k`）。轮次或预算耗尽、末轮形成结论时 family 按既有规则归档，不需要决策。

**参数值域（fail-closed）**：

| `decision` | `reason_code` | `candidate_seed_count` | `next_round_no` |
| --- | --- | --- | --- |
| `no_next_round` | 必填；`after_round_no=0` 只允许 `NO_CANDIDATE_SEED`，`after_round_no≥1` 只允许 `NO_REMAINING_SEEDS` | 必填且为 `0` | 必须为空 |
| `next_round` | 必须为空 | 必填且 `≥ 1` | 必填，等于 `after_round_no + 1`，且不超过锁内按审批链尾解析出的有效 `max_rounds` |

决策子码的封闭集合 `FAMILY_TRANSITION_REASON_CODES = {NO_CANDIDATE_SEED, NO_REMAINING_SEEDS}`；其余组合、类型（布尔值、浮点数、负数）一律拒绝，不写事件。

**锁与校验顺序**：只锁 family 行（与 §9.1“换信封重批只锁 family”一致）。① family 必须是 v2 `job_kind='family'`；② 按幂等键 `(campaign_job_id, after_round_no)` 查既有决策：`detail` 完全相同则返回既有记录（family 已终态时同样返回，这不代表之后还会归档），不同则以 `StateError` 拒绝；③ family 为 `AGGREGATING`；④ `campaign_job_id` 是本 family 的 `job_kind='campaign'` child 且为 `COMPLETED`；⑤ 无 `pending` 信封；⑥ 决策点前置条件；⑦ `next_round` 的 `max_rounds` 上限。不同决策点的决策可以共存。

**写入形态**：一条 `audit_events`，`job_id=family_id`、`stage='transition'`、`event_type='family_transition_decided'`、审计 `reason_code` 列为 NULL、`detail={campaign_job_id, after_round_no, decision, candidate_seed_count, next_round_no, reason_code}`；事件时间取数据库 `clock_timestamp()`，返回值的 `created_at` 为 UTC RFC 3339 字符串。入口不创建 child、不写 `family.json`、不改预算。

**归档采纳规则**：family 归档门禁保留 unindexable/terminal/verdict/`max_rounds`/预算规则；在判定等待前，只采纳 `campaign_job_id` 等于当前 campaign 且 `after_round_no` 等于已用轮次的那条决策，其为 `no_next_round` 时归档。`next_round`、其他决策点或缺少 `after_round_no` 的事件一律忽略。决策以 `audit_events` 为唯一来源，不读证据文件。

## 10. 新增原因码

| 原因码 | 触发条件 | 终态或去向 |
| --- | --- | --- |
| `BUILD_PROVENANCE_MISSING` | 没有可核对生效参数的核对面；或声明不 ⊆ 生效；或两版生效有序序列不相等 | 冻结阶段 `BLOCKED`；构建阶段 `FAILED`；保留已有证据 |
| `ENVELOPE_VIOLATION` | 轮次或 ExperimentSpec 超出信封的 family、mutation 上限、预算、签名集合或模式 | 拒绝该轮次；不产生 build/replay；父 job 保持 `AGGREGATING` 可继续其他合法轮次，若轮次/总预算用尽或记录 `no_next_round` 且无其他合法轮次则终态 `BLOCKED`（已有合法轮次则归档 `COMPLETED` 并索引该 blocked round） |
| `ADMISSION_DENIED` | 准入谓词不通过（重复轮次、人批缺失、摘要不符、不可重算且无佐证） | 该轮不执行；审计 `round_admission_denied` |
| `REVIEW_ENVELOPE_MISMATCH` | `(family_id, envelope_digest)` 不存在或非该 family 当前 `pending`（含首轮显式信封与首份 plan 的 `envelope_digest` 不符），且未命中已审 `approved`/`rejected`/`expired` 记录 | 拒绝该次 `review`；不写 `reviews`/`family_approvals`；首轮人批时 child 保持 `AWAITING_REVIEW`、换信封重批时 child 状态不变，family 保持 `AGGREGATING` |
| `BUDGET_EXHAUSTED` | family 总预算或 fuzz 子预算不足以启动下一轮或下一步 | 当前执行 child 的判定按已有回放为 `INCONCLUSIVE` 或 `FAILED`；campaign/family 完成归档后 job `state=COMPLETED`；不再建轮次 |
| `REUSE_MISMATCH` | `build_ref` 中某一版的 artifact/log/inputs 摘要与 campaign 记录不一致，或来源 job/generation 不匹配 | 禁止复用；构建阶段 `FAILED`，记录差异摘要 |
| `HARNESS_REJECTED` | harness 未审核、摘要不符、被模型改写或与冻结材料不一致 | 准入前拒绝；不执行容器；父 job 记录阻断 |

**T15 在线情报抓取与许可原因码归属**：T15 不新增顶层原因码枚举，按既有原因码归属并在审计事件 `detail.sub_reason` 中精确记录细因：
- 抓取失败（非 HTTPS、超时、超 5 跳重定向、超 8 MiB/32 MiB/100:1、快照缺失）：归属 `MATERIAL_MISSING`（`BLOCKED`），`detail.sub_reason` 记录 `REDIRECT_LIMIT_EXCEEDED` / `FETCH_TIMEOUT` / `SIZE_LIMIT_EXCEEDED` / `DECOMPRESSION_BOMB` 等；
- 情报来源冲突：归属 `SOURCE_CONFLICT`（`BLOCKED`）；
- 抓取路径的成帧与状态失败同归 `MATERIAL_MISSING`（`BLOCKED`）：正文截断 `CONTENT_TRUNCATED`、缺少或自相矛盾的 `Content-Length` `RESPONSE_UNFRAMED`、空正文 `EMPTY_CONTENT`、最终状态不在 2xx `HTTP_STATUS_REJECTED`、响应头超过 64 KiB `RESPONSE_HEAD_TOO_LARGE`；
- 固定快照（离线案例）沿用 v0.1 的归类：内容摘要与登记值不符属材料无法校验，归 `MATERIAL_MISSING`（`detail.sub_reason=DIGEST_MISMATCH`）；读不到、读取出错、登记摘要格式非法分别为 `SNAPSHOT_MISSING` / `SNAPSHOT_UNREADABLE` / `SNAPSHOT_DIGEST_INVALID`，为空或超过线上上限分别为 `EMPTY_CONTENT` / `SIZE_LIMIT_EXCEEDED`。来源登记给了别的案例属 `SOURCE_CONFLICT`（`detail.sub_reason=SOURCE_CASE_MISMATCH`，该快照不被打开）；来源 URL 缺失或无法解析属 `POLICY_DENIED`（`detail.sub_reason=SOURCE_URL_INVALID`）；
- 域名不在白名单、私网/回环/CGNAT/元数据/IPv4-mapped IPv6 被拒、缺许可或许可用途不符：归属 `POLICY_DENIED`（`BLOCKED`），其中许可拒绝的 `detail.sub_reason` 记录 `LICENSE_REJECTED`。

**corpus 超限细因（改9）**：种子语料或 fuzz 语料超过总 64 MiB、单文件 8 MiB 或 4096 个文件时归属 `POLICY_DENIED`（`BLOCKED`），审计 `detail.sub_reason` 分别为 `CORPUS_TOTAL_BYTES_EXCEEDED`、`CORPUS_FILE_BYTES_EXCEEDED`、`CORPUS_FILE_COUNT_EXCEEDED`；不用 `MATERIAL_MISSING`，不新增顶层原因码。

family 转移决策子码 `NO_CANDIDATE_SEED`、`NO_REMAINING_SEEDS`（见 §9.2）不是本节原因码：它们只出现在 `family_transition_decided` 审计事件的 `detail.reason_code`，不进入 `jobs.reason_code`、审计 `reason_code` 列或任何终态封闭集合。

这些原因码与 v0.1 原因码并集使用。T10 起应把新码加入对应终态的封闭集合（`ENVELOPE_VIOLATION`、`ADMISSION_DENIED`、`REUSE_MISMATCH`、`HARNESS_REJECTED` 按阻断或失败归属，`BUDGET_EXHAUSTED` 与 `BUILD_PROVENANCE_MISSING` 按上表归属）；`REVIEW_ENVELOPE_MISMATCH` 是审核调用的拒绝码，不进入 job 终态，也不新增 `reviews` 行。T09 不修改判定实现。

## 11. 证据引用语法

- **构建日志引用**：精确正则为 `^log/build:(vulnerable|fixed)#L[1-9][0-9]*(-[1-9][0-9]*)?$`，支持单行 `#Lx` 或闭区间 `#Lx-y`（不得写 `#Lx-Ly`；存在区间时必须满足 `x <= y`）；`version` 为 `vulnerable` 或 `fixed`。
- **fuzz 日志引用**：精确正则为 `^log/fuzz:(0|[1-9][0-9]*)#L[1-9][0-9]*$`，指向 fuzz 日志的单行。其中 **`log/fuzz:0#Lx` 指向 `job_kind='campaign'`（`round_no=null`）的 fuzz 日志**，非零正整数保留给未来按轮次 fuzz 扩展。
- 引用必须先校验摘要与行号范围，再返回内容；越界、日志缺失或摘要不符视为不可解析。
- 旧引用语法继续有效；新语法只出现在 v2 证据包中，v1 校验器不解释新语法。

## 12. 兼容与校验

1. v1 `manifest.schema_version=1` 由冻结的 v1 分支校验；该分支保留旧 `_extract_compile_args` 副本，不调用 v2 实现。v1 控制面只读取 v1 时代数据；回滚后 v2 终态证据由保留的 v2 只读 verifier/export 服务读取，不在 v1 代码中增加 v2 plan/evidence 解析。
2. v2 校验器按 `bundle_kind` 与 `reuse_origin` 条件校验：
   - `execution` 且 `reuse_origin=null`：`envelope_digest` 必填，`build_ref`、`reuse_origin` 必须为 null；
   - `execution` 且 `reuse_origin!=null`：`envelope_digest`、`build_ref`、`reuse_origin` 均必填；
   - `campaign`：`envelope_digest` 必填，`build_ref`、`reuse_origin` 必须为 null，`verdict`/`reason_code` 必须为 null；
   - `blocked`：不要求 `family_id`、`parent_job_id`、`round_no`、`envelope_digest`、`plan_digest`、`experiment_digest`、`build_provenance_rules_version`、`build_ref`、`reuse_origin`；仍要求 report、`verdict=BLOCKED`、属于 `BLOCKED` 集合的 `reason_code` 与 `created_at`。
3. 单轮包与 family 导出中的同一轮次摘要必须一致；family 导出不得重写单轮 manifest 或 report。
4. 既有 v1 job/plan 可 export、可 verify、不可 re-run；T10 不做在线回填。
5. 未知字段、重复键、非法枚举、越界引用与摘要不符一律失败关闭；不以“尽量兼容”为由放宽。
6. `job_contract_version`、证据 `schema_version` 与发布 `contract_version` 三者不得混用；发布 manifest 的 `contract_version` 本轮固定为 `1`，`release.CONTRACT_VERSION` 使用字面量或独立常量，不依赖 `contracts.SCHEMA_VERSION`。`contracts.SCHEMA_VERSION` 保持 `1`，v2 Request 使用 `contracts.SCHEMA_VERSION_V2 = 2`。
