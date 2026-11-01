#!/usr/bin/env python3
"""Validate sast-code-audit output artifacts against the skill data contract.

Modes:
  validate.py --root PROJECT_ROOT          Full pipeline check:
                                          .sast/results/VULN_LCSR_1..4.json + .sast/results.json
                                          (schema conformance + cross-stage contract).
  validate.py --file FILE --kind KIND      Single artifact check; KIND is 'stage' or 'final'.

Exit code 0 = all checks passed, 1 = at least one FAIL.

Requires: python >= 3.9, jsonschema >= 4.18  (pip install "jsonschema>=4.18")
"""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

try:
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:  # pragma: no cover
    print(
        "error: jsonschema>=4.18 is required. Install with: pip install 'jsonschema>=4.18'",
        file=sys.stderr,
    )
    sys.exit(2)

SKILL = "sast-code-audit"
BASE = "https://sast-code-audit-skill.github.io/schemas/v1/"
STAGE_FILES = {1: "VULN_LCSR_1.json", 2: "VULN_LCSR_2.json", 3: "VULN_LCSR_3.json", 4: "VULN_LCSR_4.json"}
CATEGORIES = [
    "injection", "files-paths", "request-network", "auth-session", "authorization",
    "deserialization", "business-logic", "data-exposure", "client-side", "dependencies-config",
]
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
TERMINAL_STATUSES = {"confirmed", "updated", "false_positive"}
MARKERS = {
    "false_positive": "【复查认定误报】-",
    "updated": "【复查更新】-",
}
COMPARE_FIELDS = [
    "name", "severity", "confidence", "fingerprint", "file", "line",
    "risk_description", "recommendation",
]


class Report:
    def __init__(self) -> None:
        self.fails = 0
        self.warns = 0
        self.oks = 0

    def fail(self, check: str, detail: str) -> None:
        self.fails += 1
        print(f"[FAIL] {check}: {detail}")

    def warn(self, check: str, detail: str) -> None:
        self.warns += 1
        print(f"[WARN] {check}: {detail}")

    def ok(self, check: str) -> None:
        self.oks += 1


@contextmanager
def check_group(report: Report, name: str) -> Iterator[None]:
    """Mark a named group of checks OK when it produced no FAILs."""
    before = report.fails
    yield
    if report.fails == before:
        report.ok(name)


def load_json(path: Path, report: Optional[Report] = None) -> Optional[Any]:
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        message = f"file-missing: {path} does not exist"
    except json.JSONDecodeError as exc:
        message = f"json-parse: {path}: {exc}"
    if report is not None:
        report.fail(*message.split(": ", 1))
    else:
        print(f"[FAIL] {message}")
    return None


def build_registry(schema_dir: Path) -> tuple[Registry, dict[str, Any]]:
    resources: list[tuple[str, Resource]] = []
    schemas: dict[str, Any] = {}
    for path in sorted(schema_dir.glob("*.schema.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = BASE + path.name
        resources.append((uri, Resource(contents=doc, specification=DRAFT202012)))
        schemas[path.name] = doc
    return Registry().with_resources(resources), schemas


def schema_errors(instance: Any, schema_doc: dict[str, Any], registry: Registry) -> list[str]:
    validator = jsonschema.Draft202012Validator(
        schema_doc, registry=registry, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )
    messages = []
    for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        location = "$" + "".join(
            f"[{part!r}]" if isinstance(part, str) else f"[{part}]" for part in error.absolute_path
        )
        messages.append(f"{location}: {error.message}")
    return messages


# ---------------------------------------------------------------- item-level


def loc_parts(location: str) -> tuple[str, int]:
    file_part, line_part = location.rsplit(":", 1)
    return file_part, int(line_part)


def expected_fingerprint(v: dict[str, Any]) -> str:
    return (
        f"{v['vuln_type']}|{v['source']['location']}|{v['sink']['location']}|{v['function']}"
    )


def check_vulnerability(report: Report, v: Any, context: str) -> None:
    if not isinstance(v, dict):
        report.fail("item-shape", f"{context}: entry is not an object")
        return
    vid = v.get("id", "?")

    fp = v.get("fingerprint")
    if fp != expected_fingerprint(v):
        report.fail("fingerprint-consistency", f"{context} {vid}: '{fp}' != '{expected_fingerprint(v)}'")

    sink_file, sink_line = loc_parts(v["sink"]["location"])
    if v.get("file") != sink_file or v.get("line") != sink_line:
        report.fail(
            "primary-location",
            f"{context} {vid}: file/line ({v.get('file')}:{v.get('line')}) "
            f"must equal sink.location ({sink_file}:{sink_line})",
        )

    flow = v.get("data_flow") or []
    if not flow or v["source"]["location"] not in flow[0]:
        report.fail("data-flow-source", f"{context} {vid}: data_flow[0] must contain source.location")
    if not flow or v["sink"]["location"] not in flow[-1]:
        report.fail("data-flow-sink", f"{context} {vid}: data_flow[-1] must contain sink.location")

    status = v.get("review_status")
    if status in MARKERS and not str(v.get("name", "")).startswith(MARKERS[status]):
        report.fail("review-marker", f"{context} {vid}: name must start with '{MARKERS[status]}'")

    if v.get("severity") in ("CRITICAL", "HIGH") and not v.get("exploit_conditions"):
        report.warn("exploit-conditions", f"{context} {vid}: CRITICAL/HIGH without exploit_conditions")


def check_stage_common(report: Report, doc: dict[str, Any], path: Path, expected_stage: int) -> None:
    if doc.get("stage") != expected_stage:
        report.fail("stage-number", f"{path.name}: stage={doc.get('stage')} but filename implies {expected_stage}")
    for i, v in enumerate(doc.get("vulnerabilities", [])):
        check_vulnerability(report, v, f"{path.name}[{i}]")


def check_final_common(report: Report, doc: dict[str, Any], path: Path) -> None:
    for i, v in enumerate(doc.get("vulnerabilities", [])):
        check_vulnerability(report, v, f"{path.name}.vulnerabilities[{i}]")
    for i, v in enumerate(doc.get("false_positives", [])):
        check_vulnerability(report, v, f"{path.name}.false_positives[{i}]")

    vulns = doc.get("vulnerabilities", [])
    summary = doc.get("summary", {})
    tally = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        tally[v["severity"]] = tally.get(v["severity"], 0) + 1
    for level in ("critical", "high", "medium", "low"):
        if summary.get(level) != tally.get(level.upper()):
            report.fail(
                "summary-count",
                f"{path}: summary.{level}={summary.get(level)} but actual is {tally.get(level.upper())}",
            )
    if summary.get("total") != len(vulns):
        report.fail("summary-count", f"{path}: summary.total={summary.get('total')} but actual is {len(vulns)}")

    ids = [v["id"] for v in vulns]
    fps = [v["fingerprint"] for v in vulns]
    if len(set(ids)) != len(ids):
        report.fail("unique-ids", f"{path}: duplicate ids in vulnerabilities")
    if len(set(fps)) != len(fps):
        report.fail("unique-fingerprints", f"{path}: duplicate fingerprints in vulnerabilities")

    expected_sort = sorted(
        vulns, key=lambda v: (SEVERITY_ORDER[v["severity"]], -v["confidence"], v["id"])
    )
    if [v["id"] for v in vulns] != [v["id"] for v in expected_sort]:
        report.fail("ordering", f"{path}: vulnerabilities must be sorted by severity desc, confidence desc, id asc")


# ---------------------------------------------------------------- pipeline


def collect(stage_doc: dict[str, Any]) -> tuple[list[str], list[str]]:
    vulns = stage_doc.get("vulnerabilities", [])
    return [v["id"] for v in vulns], [v["fingerprint"] for v in vulns]


def check_pipeline(report: Report, root: Path, registry: Registry, schemas: dict[str, Any]) -> None:
    results_dir = root / ".sast" / "results"
    stage_docs: dict[int, dict[str, Any]] = {}
    for stage, name in STAGE_FILES.items():
        path = results_dir / name
        with check_group(report, f"stage{stage}"):
            doc = load_json(path, report)
            if doc is None:
                return
            for msg in schema_errors(doc, schemas["stage-result.schema.json"], registry):
                report.fail("schema", f"{name}: {msg}")
            check_stage_common(report, doc, path, stage)
        stage_docs[stage] = doc

    final_path = root / ".sast" / "results.json"
    with check_group(report, "final-report"):
        final = load_json(final_path, report)
        if final is None:
            return
        for msg in schema_errors(final, schemas["final-result.schema.json"], registry):
            report.fail("schema", f"results.json: {msg}")
        check_final_common(report, final, final_path)

    s2, s3, s4 = stage_docs[2], stage_docs[3], stage_docs[4]
    ids2, fps2 = collect(s2)
    ids3, fps3 = collect(s3)
    ids4, fps4 = collect(s4)

    with check_group(report, "uniqueness"):
        for label, ids in (("stage2", ids2), ("stage3", ids3), ("stage4", ids4)):
            if len(set(ids)) != len(ids):
                report.fail("unique-ids", f"{label}: duplicate ids {sorted(ids)}")
        for label, fps in (("stage2", fps2), ("stage3", fps3), ("stage4", fps4)):
            dupes = sorted({f for f in fps if fps.count(f) > 1})
            if dupes:
                report.fail("unique-fingerprints", f"{label}: duplicate fingerprints {dupes}")

    with check_group(report, "stage3-no-duplicates"):
        overlap = set(fps2) & set(fps3)
        if overlap:
            report.fail("stage3-no-duplicates", f"stage3 re-reports stage2 fingerprints: {sorted(overlap)}")

    with check_group(report, "checklist-coverage"):
        coverage = s3.get("checklist_coverage", [])
        cats = [c.get("category") for c in coverage]
        if sorted(c for c in cats if c) != sorted(CATEGORIES):
            report.fail(
                "checklist-coverage",
                f"stage3 categories {sorted(cats)} != required {sorted(CATEGORIES)}",
            )

    with check_group(report, "review-coverage"):
        missing = (set(fps2) | set(fps3)) - set(fps4)
        if missing:
            report.fail("review-coverage", f"stage4 does not cover fingerprints: {sorted(missing)}")

    with check_group(report, "origin-stage"):
        known_ids = set(ids2) | set(ids3)
        by_id4 = {v["id"]: v for v in s4.get("vulnerabilities", [])}
        for vid, v in by_id4.items():
            if vid not in known_ids:
                report.warn("review-split", f"stage4 introduces new id {vid} (allowed only for review splits)")
                if v.get("origin_stage") != 4:
                    report.fail("origin-stage", f"stage4 new id {vid} must have origin_stage=4")
            elif v.get("origin_stage") == 4:
                report.fail("origin-stage", f"stage4 id {vid} exists in stage2/3; origin_stage must stay 2/3")

    with check_group(report, "review-status"):
        for v in s4.get("vulnerabilities", []):
            if v.get("review_status") not in TERMINAL_STATUSES:
                report.fail("review-status", f"stage4 {v.get('id')} is still '{v.get('review_status')}'")

    with check_group(report, "final-vs-stage4"):
        by_fp4 = {v["fingerprint"]: v for v in s4.get("vulnerabilities", [])}
        keep = sorted(f for f, v in by_fp4.items() if v.get("review_status") in ("confirmed", "updated"))
        drop = sorted(f for f, v in by_fp4.items() if v.get("review_status") == "false_positive")

        final_vuln_fps = sorted(v["fingerprint"] for v in final.get("vulnerabilities", []))
        if final_vuln_fps != keep:
            report.fail(
                "final-vs-stage4",
                f"results.json fingerprints {final_vuln_fps} != stage4 confirmed/updated {keep}",
            )
        final_fp_fps = sorted(v["fingerprint"] for v in final.get("false_positives", []))
        if final_fp_fps != drop:
            report.fail(
                "final-vs-stage4",
                f"results.json false_positives {final_fp_fps} != stage4 false_positive {drop}",
            )

        for v in final.get("vulnerabilities", []) + final.get("false_positives", []):
            stage4_v = by_fp4.get(v["fingerprint"])
            if stage4_v is None:
                continue
            differing = [f for f in COMPARE_FIELDS if v.get(f) != stage4_v.get(f)]
            if differing:
                report.fail(
                    "final-vs-stage4",
                    f"{v['id']}: fields {differing} differ between results.json and stage4",
                )

    with check_group(report, "platform-copy"):
        copy_path = root / "results" / "results.json"
        if copy_path.exists():
            copy = load_json(copy_path, report)
            if copy is not None and copy != final:
                report.fail("platform-copy", f"{copy_path} differs from authoritative {final_path}")


# ---------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--root", type=Path, help="audited project root (full pipeline check)")
    group.add_argument("--file", type=Path, help="single artifact to check")
    parser.add_argument("--kind", choices=["stage", "final"], help="artifact kind when using --file")
    parser.add_argument(
        "--schema-dir", type=Path, default=Path(__file__).resolve().parent.parent / "schemas",
        help="directory containing the skill's *.schema.json files",
    )
    args = parser.parse_args()

    if args.file is not None and args.kind is None:
        parser.error("--file requires --kind stage|final")

    if not args.schema_dir.exists():
        print(f"error: schema directory not found: {args.schema_dir}", file=sys.stderr)
        return 2

    registry, schemas = build_registry(args.schema_dir)
    report = Report()

    if args.root is not None:
        check_pipeline(report, args.root, registry, schemas)
    else:
        doc = load_json(args.file, report)
        if doc is not None:
            schema_name = (
                "stage-result.schema.json" if args.kind == "stage" else "final-result.schema.json"
            )
            with check_group(report, "schema"):
                for msg in schema_errors(doc, schemas[schema_name], registry):
                    report.fail("schema", f"{args.file.name}: {msg}")
            with check_group(report, "invariants"):
                if args.kind == "stage":
                    check_stage_common(report, doc, args.file, doc.get("stage", -1))
                else:
                    check_final_common(report, doc, args.file)

    verdict = "PASS" if report.fails == 0 else "FAIL"
    print(f"\n{verdict}: {report.fails} failed, {report.warns} warnings, {report.oks} groups passed")
    return 1 if report.fails else 0


if __name__ == "__main__":
    sys.exit(main())
