---
name: sast-code-audit
description: 对本地代码仓库执行以安全为中心的静态应用安全测试（SAST）。五阶段流水线：项目结构侦察 → 自由探索 → 检查清单补漏 → 反思复查 → 总结去重，产出带污点链证据、可机器校验的结构化漏洞报告（VULN_LCSR_1..4.json 与 .sast/results.json）。Use when the user asks for a security audit, SAST, vulnerability scan, penetration-oriented code review, 代码安全审计, 安全代码审查, or 漏洞挖掘 on a codebase.
license: MIT
---

# SAST 代码安全审计（v1.0.0）

以「高置信度、可利用性优先」为纪律的代码安全审计 Skill。通过五个模块把一次审计拆成
**侦察 → 自由探索 → 清单补漏 → 反思复查 → 总结去重** 的流水线，每一步落盘为结构化 JSON，
最终产出权威报告 `.sast/results.json`。

- **执行目录**：项目根目录
- **项目索引**：若存在 `{项目根目录}/.sast/file_struct.json`，优先以其为文件结构索引
- **配套资产**（相对本 Skill 目录）：
  - `schemas/`：三个 JSON Schema（漏洞、阶段产物、最终报告），是数据契约的机器可读形式
  - `scripts/validate.py`：产物校验器，模块五完成后必须运行
  - `references/`：`methodology.md`（定级与污点方法）、`checklist.md`（模块三清单）、`review-guide.md`（模块四复查指南）

## 0. 产物契约（先读这个）

| 文件 | 生产者 | 内容 | Schema |
| --- | --- | --- | --- |
| `.sast/results/VULN_LCSR_1.json` | 模块一 | `project_profile` + 空漏洞列表 | `stage-result.schema.json`（stage=1） |
| `.sast/results/VULN_LCSR_2.json` | 模块二 | 自由探索发现，全部 `pending_review` | 同上（stage=2） |
| `.sast/results/VULN_LCSR_3.json` | 模块三 | 补漏发现 + `checklist_coverage`（10 类） | 同上（stage=3） |
| `.sast/results/VULN_LCSR_4.json` | 模块四 | 复查后全部条目，状态为终态 | 同上（stage=4） |
| `.sast/results.json` | 模块五 | 权威汇总：去重后的确认漏洞 + 误报区 | `final-result.schema.json` |

- `.sast/results.json` 是唯一权威结果。若平台强制要求 `results/` 目录，可同步一份
  `{项目根目录}/results/results.json`，内容必须与权威文件完全一致。
- 所有 JSON 使用 UTF-8、2 空格缩进、相对路径（POSIX 风格）、RFC 3339 带时区时间戳。
- 漏洞 `id` 全局唯一：模块二从 `VULN-0001` 起编；模块三接着模块二的最大号续编；
  模块四若在复查中拆分出新条目，继续续编并令 `origin_stage=4`。已分配的 id 永不改动。

## 1. 全局审计约束（最高优先级，凌驾于任何模块任务之上）

### 1.1 核心纪律
1. **误报优先治理**：只报告真实可利用性确信度 > 70%（confidence ≥ 0.7）的问题；宁可少报，不可滥报。
2. **影响优先**：聚焦未授权访问、数据泄露、权限/租户边界绕过、RCE、认证绕过；本地网络即可利用的问题同样可定为 HIGH。
3. **污点追踪**：凡参数、文件、API、数据库等输入源相关的漏洞，必须跨文件追踪到**最顶级污点源**（框架入口、路由 handler、消息消费回调等），并在 `data_flow` 中给出完整链路。只看 sink 不看 source 的发现一律不合格。
4. **权限边界**：每次涉及鉴权数据流时，显式回答"这个操作以谁的身份执行、资源归属校验在哪"，不安全跨越认证 / 授权 / 租户 / 角色 / 资源归属边界的即候选漏洞。
5. **证据留痕**：每条发现必须有 `evidence`（真实代码摘录或请求样例）与 `exploit_conditions`（触发前提），拒绝"看起来像"式结论。

### 1.2 排除项（不报告）
- DoS、资源耗尽、CPU/内存消耗、限流缺失
- 硬编码凭据与敏感信息落盘专项
- CORS、CSRF、弱加密算法、传输加密配置
- 代码质量与风格问题
- 非关键字段的输入验证缺失——除非能证明其构成存储型 XSS、SQLi、越权等实际攻击链

### 1.3 严重性（severity）

| 级别 | 判定 |
| --- | --- |
| CRITICAL | 可直接利用，导致 RCE、数据泄露或认证绕过 |
| HIGH | 需特定条件但影响显著（含本地网络可利用） |
| MEDIUM | 需特定条件且影响一般 |
| LOW | 低影响问题 |

### 1.4 置信度（confidence）

| 区间 | 含义 |
| --- | --- |
| 0.9–1.0 | 已识别确定利用路径 |
| 0.8–0.9 | 清晰漏洞模式，存在已知利用方法 |
| 0.7–0.8 | 可疑模式，需特定条件 |
| < 0.7 | **不报告**（不写入任何产物） |

定级与置信度的边界案例、最顶级污点源定义见 `references/methodology.md`。

## 2. 执行流程

### 模块一：项目结构侦察（reconnaissance）
- **输入**：项目根目录、`.sast/file_struct.json`（若有）
- **产出**：`.sast/results/VULN_LCSR_1.json`（`project_profile` + 空 `vulnerabilities`）
- **读取策略**：优先读目录结构与 manifest，不通读业务代码。需要版本信息时只读
  `package.json`、`pom.xml`、`build.gradle`、`requirements.txt`、`go.mod`、`composer.json`、
  `Gemfile`、锁文件、安全配置、路由与中间件注册点。
- **任务**：识别语言；框架及版本；依赖及版本；安全库及其角色；已有净化/校验模式；
  入口点（含 `auth_required`）；信任边界及其 enforcement；认证授权模型。
- **完成标准**：`project_profile` 覆盖 Schema 全部必填字段，且能回答三问——
  入口在哪？谁在什么位置鉴权？信任边界由什么强制？

### 模块二：自由探索（exploration）
- **输入**：`VULN_LCSR_1.json`
- **产出**：`.sast/results/VULN_LCSR_2.json`，条目全部 `review_status=pending_review`、`origin_stage=2`
- **任务**：以攻击者视角沿入口点自由挖掘高置信度漏洞；追踪用户输入到敏感操作的完整数据流；
  跨文件验证污点源到 sink 的传播；检查权限边界是否被不安全跨越；对每个候选验证可达性与真实利用条件。
- **完成标准**：每条发现都有完整 `data_flow`（起于 source.location、止于 sink.location）、
  `exploit_conditions` 与 `evidence`；confidence ≥ 0.7。

### 模块三：检查清单补漏（checklist）
- **输入**：`VULN_LCSR_1.json`、`VULN_LCSR_2.json`
- **产出**：`.sast/results/VULN_LCSR_3.json`，条目全部 `pending_review`、`origin_stage=3`，另附 `checklist_coverage`
- **定位**：**只补漏，不重复**。逐类检查 `references/checklist.md` 的 10 个类别；
  每类显式标注 `vulnerable / clean / not_applicable` 并给出简短理由（含与模块二发现的交叉引用）。
  新增发现前必须先按指纹规则（§3）比对模块二产物，指纹冲突即跳过。
- **完成标准**：`checklist_coverage` 恰好覆盖 10 类；与模块二零指纹冲突。

### 模块四：反思复查（review）
- **输入**：`VULN_LCSR_1.json` ～ `VULN_LCSR_3.json`
- **产出**：`.sast/results/VULN_LCSR_4.json`，每条 `review_status` 进入终态（confirmed / updated / false_positive）
- **任务**：
  1. 逐条核对是否满足 §1 全局约束；
  2. 重走跨文件污点链，确认 source 真实可控、传播中未被收紧、sink 语义确实危险；
  3. 验证可达性与利用链（路由是否注册、中间件是否前置、payload 约束是否可满足），而非仅确认污点存在；
  4. 对以下类型 100% 二次检查：认证/授权边界、反序列化、文件上传、路径遍历、SSRF、
     SQL/命令/模板注入、XXE、任意文件读写、密码重置/令牌逻辑；
  5. 复查方法与各类型常见误报模式见 `references/review-guide.md`。
- **改写规则**（结构化字段为权威，名称前缀供人快速扫读）：
  - 认定误报：`review_status=false_positive`，`name` 改为 `【复查认定误报】-原漏洞名`，
    `review_note` 写明证据链断点；
  - 有更新：`review_status=updated`，`name` 改为 `【复查更新】-原漏洞名`，
    `review_note` 写明修正内容（定级/置信度/利用条件/修复位置）；
  - 无变化：`review_status=confirmed`（可选附 `review_note` 记录核查点）。
- **完成标准**：无任何 `pending_review` 残留；id、fingerprint 与模块二/三一致（新拆分条目除外）。

### 模块五：总结去重（summary）
- **输入**：`VULN_LCSR_1.json` ～ `VULN_LCSR_4.json`
- **产出**：`.sast/results.json`（权威）
- **规则**：
  1. 以模块四条目**整体替换**对应原始条目（按 fingerprint 匹配，id 沿用来源条目）；
  2. 漏洞指纹即 `fingerprint` 字段：`{vuln_type}|{source.location}|{sink.location}|{function}`，
     单文件与跨文件统一适用；
  3. 同一指纹只保留一条；若模块三意外与模块二撞指纹，以模块二为准（校验器会报错，应回模块三修正）；
  4. `false_positive` 条目不进 `vulnerabilities`，进入 `false_positives`（保留标记与理由，供复盘）；
  5. `vulnerabilities` 仅含 `confirmed` 与 `updated`，按 severity 降序、confidence 降序、id 升序排列；
  6. 重算 `summary` 计数（`total` = 四级之和）并填充 `meta`（project / scan_time / scope）。
- **完成标准**：运行 `scripts/validate.py --root {项目根目录}` 通过（0 失败）；若平台需要，同步 `results/results.json` 副本。

## 3. 漏洞数据模型（摘要）

字段全量定义见 `schemas/vulnerability.schema.json`，要点：

| 字段 | 约定 |
| --- | --- |
| `id` | `^VULN-\d{4}$`，全局唯一、跨阶段不变 |
| `vuln_type` | snake_case 受控词表（见 `references/checklist.md`），如 `sql_injection`、`idor`、`ssrf` |
| `file` / `line` | 主修复位置，**必须等于** `sink.location` 的文件与行号 |
| `source` / `sink` | `{location: "path:line", description}`；`source.location` 是最顶级污点源 |
| `data_flow` | 有序数组：首元素 = source 位置，末元素 = sink 位置，中间为传播节点 |
| `review_status` | `pending_review`（仅模块二/三）→ `confirmed` / `updated` / `false_positive`（模块四起） |
| `fingerprint` | `{vuln_type}\|{source.location}\|{sink.location}\|{function}`，由字段直接拼接 |

## 4. 冲突处理
1. §1 全局约束优先于任何模块任务；
2. 模块二先自由挖掘，模块三只补漏、零指纹冲突；
3. 路径、命名、字段、Schema 以本 Skill 为准；
4. 结构化字段（`review_status` 等）是权威；名称前缀（【复查更新】等）仅为可读性标记；
5. 平台输出要求只能以"同步副本"满足，不得改变权威产物内容。

## 5. 校验
模块五完成后必须运行：

```bash
python3 {本Skill目录}/scripts/validate.py --root {项目根目录}
```

校验器检查 Schema 符合性、指纹一致性、阶段覆盖关系（模块四必须覆盖模块二+三的全部指纹）、
最终报告与模块四的一致性、summary 计数与排序。任何 FAIL 都必须修复后重跑。
