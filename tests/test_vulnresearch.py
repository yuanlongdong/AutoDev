import json
import tempfile
from pathlib import Path

from vulnresearch.engine import ResearchEngine
from vulnresearch.models import dump_sarif


def test_detects_sql_injection_and_deduplicates():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "app.py"
        p.write_text('db.execute(f"SELECT * FROM users WHERE id={user_id}")\n', encoding="utf-8")
        findings = ResearchEngine(d).run()
        assert len(findings) == 1
        assert findings[0].category == "sql-injection"
        assert findings[0].confidence == "Low"
        assert findings[0].status == "potential"
        assert findings[0].evidence_level == "E1"


def test_exports_sarif():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "app.py"
        p.write_text('db.execute(f"SELECT * FROM users WHERE id={user_id}")\n', encoding="utf-8")
        findings = ResearchEngine(d).run()
        sarif = json.loads(dump_sarif(findings))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["properties"]["evidenceLevel"] == "E1"
