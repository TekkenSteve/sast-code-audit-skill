# sast-code-audit-skill

**An open, model-agnostic agent skill that turns an LLM into a disciplined SAST code auditor — with a machine-checkable output contract.**

[简体中文](README.zh-CN.md) | English

LLM-driven security audits usually drown in noise: speculative findings, no evidence chain, no dedup, and results that change shape every run. This skill fixes that with a **five-stage pipeline** where every stage writes a structured artifact, every finding carries a full taint chain, every finding is re-reviewed before it ships, and the final report is validated against JSON Schemas.

## How it works

```
 project root
     │
     ▼
 ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
 │ Stage 1     │   │ Stage 2     │   │ Stage 3     │   │ Stage 4     │   │ Stage 5     │
 │ recon       │──▶│ free        │──▶│ checklist   │──▶│ adversarial │──▶│ merge +     │
 │ profile,    │   │ exploration │   │ gap-fill    │   │ review      │   │ dedup       │
 │ entrypoints │   │ taint flows │   │ 10 classes  │   │ FP gate     │   │ sort, tally │
 └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
 VULN_LCSR_1.json    VULN_LCSR_2.json  VULN_LCSR_3.json  VULN_LCSR_4.json  .sast/results.json
```

| Stage | Artifact | What it proves |
| --- | --- | --- |
| 1 · Reconnaissance | `.sast/results/VULN_LCSR_1.json` | Language, frameworks, security libs, entrypoints with `auth_required`, trust boundaries — before reading business code |
| 2 · Free exploration | `.sast/results/VULN_LCSR_2.json` | Attacker-view findings, each with a taint chain traced to the **top-level source** and concrete exploit conditions |
| 3 · Checklist gap-fill | `.sast/results/VULN_LCSR_3.json` | 10 vulnerability classes each get an explicit `vulnerable / clean / not_applicable` verdict; zero fingerprint overlap with stage 2 |
| 4 · Adversarial review | `.sast/results/VULN_LCSR_4.json` | Every finding re-verified (5-step method). Verdicts: `confirmed` / `updated` / `false_positive` with mandatory review notes |
| 5 · Merge & dedup | `.sast/results.json` | Authoritative report: confirmed + updated findings only, sorted, tallied; rejected findings quarantined in `false_positives` for retrospective |

### Key mechanics

- **Confidence gate** — findings below 0.7 confidence never enter any artifact. Fewer, real findings.
- **Fingerprint dedup** — `{vuln_type}|{source.location}|{sink.location}|{function}`, applied uniformly to single-file and cross-file flows.
- **Evidence discipline** — every finding must quote real code (`evidence`), name its trigger preconditions (`exploit_conditions`), and show the full `data_flow` from source to sink.
- **Structured source/sink** — `path:line` locators, so reports are jumpable and fingerprints are stable.
- **Review as a first-class state** — stage 4 rewrites findings to a terminal status; `false_positive` items are kept (with the exact broken hop of the evidence chain) instead of being silently dropped.
- **Executable contract** — three JSON Schemas + a validator that checks schema conformance *and* cross-stage consistency (review coverage, final-report mirroring, summary arithmetic, ordering).

## Install

**Claude Code / any Agent-Skills-compatible harness:**

```bash
git clone https://github.com/TekkenSteve/sast-code-audit-skill.git
mkdir -p ~/.claude/skills
cp -r sast-code-audit-skill/sast-code-audit ~/.claude/skills/
```

**Any other agent** (Claude API, DeepSeek, GLM, OpenAI, local orchestrators…): feed `sast-code-audit/SKILL.md` as the instruction document, keep the `schemas/`, `references/`, `scripts/` folders next to it, and run the agent with the audited repository as working directory.

## Use

From the project root of the repo you want audited, ask your agent:

> 使用 sast-code-audit skill 对当前项目做安全审计，按五阶段流程执行并产出 .sast/results.json

(or in English: *"Run the sast-code-audit skill against this repository and produce .sast/results.json"*)

The agent executes stages 1–5 in order, writing one artifact per stage. Tip for repo owners: add `.sast/` to your `.gitignore` — audit output is local.

## Output contract

Single finding (see [`schemas/vulnerability.schema.json`](sast-code-audit/schemas/vulnerability.schema.json)):

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
  "data_flow": ["...source...", "...propagation...", "...sink..."],
  "review_status": "confirmed",
  "origin_stage": 2,
  "fingerprint": "sql_injection|src/routes/posts.js:31|src/routes/posts.js:34|listPosts"
}
```

Final report (see [`schemas/final-result.schema.json`](sast-code-audit/schemas/final-result.schema.json)):

```json
{
  "meta": { "project": "...", "scan_time": "...", "scope": "...", "generator": "sast-code-audit", "skill_version": "1.0.0" },
  "summary": { "critical": 1, "high": 1, "medium": 0, "low": 0, "total": 2 },
  "vulnerabilities": [],
  "false_positives": []
}
```

A complete, validator-passing example set lives in [`examples/demo-project/`](examples/demo-project/.sast/) — including one finding that stage 4 correctly rejected (SSRF behind an allowlisted fetch wrapper).

## Validate

```bash
pip install "jsonschema>=4.18"

# full pipeline check (all 5 artifacts + cross-stage contract)
python sast-code-audit/scripts/validate.py --root /path/to/audited/project

# single artifact
python sast-code-audit/scripts/validate.py --file .sast/results.json --kind final
```

The validator verifies: schema conformance, fingerprint consistency (`fingerprint` must equal the field concatenation), `file/line` = sink location, review-marker prefixes, stage-3→stage-2 zero overlap, stage-4 full coverage of stage 2+3, final report mirroring stage 4, summary arithmetic, and severity/confidence ordering. Wire it into CI:

```yaml
- run: pip install "jsonschema>=4.18"
- run: python sast-code-audit/scripts/validate.py --root examples/demo-project
```

## Scope & non-goals

The skill deliberately **does not report**: DoS/resource exhaustion, rate limiting, hardcoded secrets, CORS/CSRF/weak-crypto, code quality, or input-validation nits that don't chain into a real attack. It focuses on unauthorized access, data exposure, authorization/tenant boundary bypasses, RCE, and auth bypass — exploitable issues, with a >70% confidence gate.

## Repository layout

```
sast-code-audit/          # the installable skill
├── SKILL.md              # pipeline instructions (the agent reads this)
├── references/           # methodology, 10-class checklist, review guide
├── schemas/              # vulnerability / stage-result / final-result JSON Schemas
└── scripts/validate.py   # contract validator
examples/demo-project/    # full five-artifact example (fictional Node.js API)
```

## Roadmap

- [ ] SARIF 2.1.0 export for GitHub Code Scanning
- [ ] Per-stack checklist packs (Java/PHP/Python/Go specifics)
- [ ] Severity calibration corpus (real fixed CVEs as anchor examples)

## Contributing

Issues and PRs welcome. Schema changes must keep `examples/demo-project/` validator-clean (`python sast-code-audit/scripts/validate.py --root examples/demo-project`).

## License

[MIT](LICENSE). Methodology draws on the OWASP Code Review Guide, MITRE CWE, and the open Agent Skills packaging format.
