# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-09

### Added

- Five-stage audit pipeline (reconnaissance → free exploration → checklist gap-fill →
  adversarial review → merge & dedup) with stage artifacts `VULN_LCSR_1..4.json`
  and the authoritative `.sast/results.json`.
- Agent Skills packaging: `SKILL.md` with frontmatter, `references/` (methodology,
  10-class checklist, review guide).
- JSON Schemas for vulnerability, stage result, and final report records
  (draft 2020-12), including review-state machine and marker constraints.
- Contract validator `scripts/validate.py`: schema conformance, fingerprint
  consistency, cross-stage coverage, final-report mirroring, summary arithmetic,
  and ordering checks; single-artifact and full-pipeline modes.
- Complete validator-clean example set for a fictional Node.js API
  (`examples/demo-project/`), including a correctly-rejected false positive.
- CI workflow validating the example artifacts on every push/PR.
