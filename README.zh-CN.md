# sast-code-audit-skill

**开源、模型无关的 Agent Skill：把 LLM 变成有纪律的 SAST 代码安全审计员，产出可通过机器校验的审计报告。**

English | [简体中文](README.zh-CN.md)

LLM 做安全审计的通病是噪音：猜测式结论、没有证据链、不去重、输出格式每次都变。本 Skill 用**五阶段流水线**解决：每个阶段落盘一个结构化产物、每个漏洞携带完整污点链、每个发现发布前必须经对抗性复查、最终报告用 JSON Schema + 校验器把关。

## 工作原理

```
 项目根目录
     │
     ▼
 ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
 │ 模块一      │   │ 模块二      │   │ 模块三      │   │ 模块四      │   │ 模块五      │
 │ 结构侦察    │──▶│ 自由探索    │──▶│ 清单补漏    │──▶│ 反思复查    │──▶│ 总结去重    │
 │ 画像/入口/  │   │ 污点链挖掘  │   │ 10 类逐项   │   │ 误报闸门    │   │ 排序/计数   │
 │ 信任边界    │   │             │   │ 显式结论    │   │             │   │             │
 └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
 VULN_LCSR_1.json    VULN_LCSR_2.json  VULN_LCSR_3.json  VULN_LCSR_4.json  .sast/results.json
```

| 阶段 | 产物 | 证明什么 |
| --- | --- | --- |
| 1 · 结构侦察 | `.sast/results/VULN_LCSR_1.json` | 语言、框架、安全库、带 `auth_required` 的入口点、信任边界——在读业务代码之前先建地图 |
| 2 · 自由探索 | `.sast/results/VULN_LCSR_2.json` | 攻击者视角的发现，每条污点链都追到**最顶级污点源**，附具体利用条件 |
| 3 · 清单补漏 | `.sast/results/VULN_LCSR_3.json` | 10 个漏洞类别逐类给出 `vulnerable / clean / not_applicable` 显式结论；与模块二零指纹重叠 |
| 4 · 反思复查 | `.sast/results/VULN_LCSR_4.json` | 每条发现按五步法复核，终态 `confirmed` / `updated` / `false_positive`，且必须写复查理由 |
| 5 · 总结去重 | `.sast/results.json` | 权威报告：仅含确认与更新条目，排序、计数；被否决的发现隔离到 `false_positives` 供复盘 |

### 核心机制

- **置信度门槛**：confidence < 0.7 的发现不进入任何产物。宁缺毋滥。
- **指纹去重**：`{vuln_type}|{source.location}|{sink.location}|{function}`，单文件与跨文件统一适用。
- **证据纪律**：每条发现必须摘录真实代码（`evidence`）、写明触发前提（`exploit_conditions`）、给出 source 到 sink 的完整 `data_flow`。
- **结构化 source/sink**：`path:line` 定位符，报告可直接跳转，指纹稳定。
- **复查是一等状态**：模块四把每条发现改为终态；`false_positive` 条目保留（注明证据链断在哪一跳），不静默丢弃。
- **可执行的契约**：三份 JSON Schema + 校验器，检查 Schema 符合性**和**跨阶段一致性（复查覆盖、最终报告镜像、summary 计数、排序）。

## 安装

**Claude Code / 兼容 Agent Skills 的平台：**

```bash
git clone https://github.com/TekkenSteve/sast-code-audit-skill.git
mkdir -p ~/.claude/skills
cp -r sast-code-audit-skill/sast-code-audit ~/.claude/skills/
```

**其他 Agent**（Claude API、DeepSeek、GLM、OpenAI、自建编排……）：把 `sast-code-audit/SKILL.md` 作为指令文档注入，保持 `schemas/`、`references/`、`scripts/` 目录与其同级，并让 Agent 以被审计仓库为工作目录。

## 使用

在被审计项目根目录对 Agent 说：

> 使用 sast-code-audit skill 对当前项目做安全审计，按五阶段流程执行并产出 .sast/results.json

Agent 按模块一至五顺序执行，每阶段写一个产物。建议被审计仓库把 `.sast/` 加入 `.gitignore`——审计产物属于本地。

## 输出契约

单条漏洞（见 [`schemas/vulnerability.schema.json`](sast-code-audit/schemas/vulnerability.schema.json)）：

```json
{
  "id": "VULN-0001",
  "name": "文章列表 sort 参数拼接导致 SQL 注入",
  "vuln_type": "sql_injection",
  "cwe": "CWE-89",
  "severity": "CRITICAL",
  "confidence": 0.9,
  "file": "src/routes/posts.js",
  "line": 34,
  "function": "listPosts",
  "source": { "location": "src/routes/posts.js:31", "description": "..." },
  "sink":   { "location": "src/routes/posts.js:34", "description": "..." },
  "data_flow": ["...source...", "...传播...", "...sink..."],
  "review_status": "confirmed",
  "origin_stage": 2,
  "fingerprint": "sql_injection|src/routes/posts.js:31|src/routes/posts.js:34|listPosts"
}
```

最终报告（见 [`schemas/final-result.schema.json`](sast-code-audit/schemas/final-result.schema.json)）：

```json
{
  "meta": { "project": "...", "scan_time": "...", "scope": "...", "generator": "sast-code-audit", "skill_version": "1.0.0" },
  "summary": { "critical": 1, "high": 1, "medium": 0, "low": 0, "total": 2 },
  "vulnerabilities": [],
  "false_positives": []
}
```

完整且通过校验器的样例在 [`examples/demo-project/`](examples/demo-project/.sast/)——其中包含一条被模块四正确否决的发现（SSRF 实际被域名白名单封装拦截）。

## 校验

```bash
pip install "jsonschema>=4.18"

# 全流水线检查（5 个产物 + 跨阶段契约）
python sast-code-audit/scripts/validate.py --root /path/to/audited/project

# 单文件检查
python sast-code-audit/scripts/validate.py --file .sast/results.json --kind final
```

校验器检查：Schema 符合性、指纹一致性（`fingerprint` 必须等于字段拼接）、`file/line` 与 sink 一致、复查标记前缀、模块三与模块二零重叠、模块四完整覆盖模块二+三、最终报告与模块四镜像、summary 计数、严重性/置信度排序。接入 CI：

```yaml
- run: pip install "jsonschema>=4.18"
- run: python sast-code-audit/scripts/validate.py --root examples/demo-project
```

## 范围与非目标

本 Skill **刻意不报告**：DoS/资源耗尽、限流缺失、硬编码凭据、CORS/CSRF/弱加密、代码质量、以及无法串成实际攻击链的输入校验缺失。聚焦未授权访问、数据泄露、权限/租户边界绕过、RCE、认证绕过——只报可利用、置信度 >70% 的问题。

## 仓库结构

```
sast-code-audit/          # 可安装的 Skill 本体
├── SKILL.md              # 流水线指令（Agent 读取此文件）
├── references/           # 方法论、10 类检查清单、复查指南
├── schemas/              # vulnerability / stage-result / final-result 三份 JSON Schema
└── scripts/validate.py   # 契约校验器
examples/demo-project/    # 完整五产物示例（虚构 Node.js API）
```

## Roadmap

- [ ] SARIF 2.1.0 导出（对接 GitHub Code Scanning）
- [ ] 分技术栈清单包（Java/PHP/Python/Go 专项）
- [ ] 定级校准语料（以真实已修复 CVE 为锚例）

## 参与贡献

欢迎 Issue 与 PR。改动 Schema 后必须保证示例通过校验：`python sast-code-audit/scripts/validate.py --root examples/demo-project`。

## 许可

[MIT](LICENSE)。方法论参考了 OWASP Code Review Guide、MITRE CWE 与开放的 Agent Skills 打包格式。
