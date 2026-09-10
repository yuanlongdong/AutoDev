import argparse
from pathlib import Path
from .engine import ResearchEngine
from .models import dump_json, dump_sarif


def main():
    parser = argparse.ArgumentParser(description="AI Vulnerability Researcher - authorized source audit")
    parser.add_argument("path", nargs="?", default=".", help="authorized local source tree")
    parser.add_argument("--json", dest="json_path", help="write findings as JSON")
    parser.add_argument("--sarif", dest="sarif_path", help="write findings as SARIF 2.1.0")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    findings = ResearchEngine(str(root)).run()
    print(f"Scanned: {root}")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"[{f.severity}/{f.confidence}] {f.title} {f.path}:{f.line}")
        print(f"  Status: {f.status} | Evidence: {f.evidence_level}")
        print(f"  Evidence: {f.evidence}")
        print(f"  Code: {f.snippet}")
        print(f"  Fix: {f.remediation}")
    if args.json_path:
        Path(args.json_path).write_text(dump_json(findings), encoding="utf-8")
    if args.sarif_path:
        Path(args.sarif_path).write_text(dump_sarif(findings), encoding="utf-8")


if __name__ == "__main__":
    main()
