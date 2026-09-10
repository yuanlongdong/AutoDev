"""Command-line interface (PHASE 27).

Backward-compatible with the v0.1.x invocations::

    vulnresearch /path --json out.json --sarif out.sarif

and extended with deep-analysis options:

* ``--report <path>``       write a fifteen-section Markdown report
* ``--ir [path]``           emit the project IR as JSON (stdout or file)
* ``--attack-surface [path]`` emit the attack-surface report
* ``--verbose`` / ``-v``    print full per-finding detail
* ``--format {text,json,sarif,report}`` output format
* ``--max-files N``         cap the number of scanned files
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .engine import ResearchEngine
from .models import Finding, dump_json, dump_sarif


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnresearch",
        description="AI Vulnerability Researcher - authorized source audit",
    )
    parser.add_argument("path", nargs="?", default=".", help="authorized local source tree")
    parser.add_argument("--json", dest="json_path", help="write findings as JSON")
    parser.add_argument("--sarif", dest="sarif_path", help="write findings as SARIF 2.1.0")
    # PHASE 27 additions
    parser.add_argument("--report", dest="report_path", help="write a Markdown report to PATH")
    parser.add_argument("--ir", dest="ir_path", nargs="?", const="-", default=None,
                        help="emit project IR as JSON (to PATH or stdout)")
    parser.add_argument("--attack-surface", dest="attack_surface_path", nargs="?",
                        const="-", default=None,
                        help="emit attack-surface report (to PATH or stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="detailed per-finding output")
    parser.add_argument("--format", dest="format", default="text",
                        choices=["text", "json", "sarif", "report"],
                        help="output format (default: text)")
    parser.add_argument("--max-files", dest="max_files", type=int, default=10000,
                        help="maximum number of files to scan")
    return parser


def _print_findings(findings: List[Finding], verbose: bool) -> None:
    for f in findings:
        print(f"[{f.severity}/{f.confidence}] {f.title} {f.path}:{f.line}")
        if verbose:
            print(f"  ID/Status: {f.status} | Evidence: {f.evidence_level}")
            print(f"  Source: {f.source or 'n/a'} | Sink: {f.sink or 'n/a'}")
            print(f"  Sanitizer: {f.sanitizer} | Reachability: {f.reachability}")
        print(f"  Evidence: {f.evidence}")
        print(f"  Code: {f.snippet}")
        print(f"  Fix: {f.remediation}")


def _emit(path_or_stdout: Optional[str], content: str) -> None:
    """Write *content* to *path_or_stdout* (``-`` means stdout)."""
    if path_or_stdout in (None, "-"):
        print(content)
    else:
        Path(path_or_stdout).write_text(content, encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.  Returns a process exit code (0 on success)."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    engine = ResearchEngine(str(root), max_files=args.max_files)

    print(f"Scanned: {root}", file=sys.stderr)

    # Deep artefacts (IR / attack surface) are produced on demand.
    if args.ir_path is not None:
        ir = engine.build_ir()
        _emit(args.ir_path, ir.dump_json())

    findings: List[Finding] = engine.run()
    print(f"Findings: {len(findings)}", file=sys.stderr)

    if args.attack_surface_path is not None:
        surface = engine.build_attack_surface()
        assets = getattr(surface, "assets", []) or []
        report_lines = [f"Attack surface for {root}",
                        f"Entry points: {len(getattr(surface, 'entry_points', []) or [])}",
                        f"Assets: {len(assets)}", ""]
        for a in assets:
            report_lines.append(
                f"- [{a.type}] {a.name} ({a.file}:{a.line}) "
                f"auth={a.auth_required}"
            )
        _emit(args.attack_surface_path, "\n".join(report_lines) + "\n")

    # Findings output by --format (skip when IR/attack-surface already own stdout)
    structured_stdout = args.ir_path == "-" or args.attack_surface_path == "-"
    if args.format == "json":
        print(dump_json(findings))
    elif args.format == "sarif":
        print(dump_sarif(findings))
    elif not structured_stdout:
        _print_findings(findings, verbose=args.verbose)

    # File sinks (backward compatible + new report)
    if args.json_path:
        Path(args.json_path).write_text(dump_json(findings), encoding="utf-8")
    if args.sarif_path:
        Path(args.sarif_path).write_text(dump_sarif(findings), encoding="utf-8")

    if args.report_path or args.format == "report":
        from .report import ReportGenerator
        deep = engine.run_deep()
        md = ReportGenerator().generate(
            deep["vulnerabilities"],
            project_model=deep.get("project_model"),
            attack_surface=deep.get("attack_surface"),
            families=deep.get("families"),
            chains=deep.get("chains"),
        )
        if args.report_path:
            Path(args.report_path).write_text(md, encoding="utf-8")
        if args.format == "report":
            print(md)

    return 0


if __name__ == "__main__":
    sys.exit(main())
