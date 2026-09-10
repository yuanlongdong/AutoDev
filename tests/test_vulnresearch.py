import tempfile
from pathlib import Path
from vulnresearch.engine import ResearchEngine


def test_detects_sql_injection_and_deduplicates():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "app.py"
        p.write_text('db.execute(f"SELECT * FROM users WHERE id={user_id}")\n', encoding="utf-8")
        findings = ResearchEngine(d).run()
        assert len(findings) == 1
        assert findings[0].category == "sql-injection"
        assert findings[0].confidence == "Low"
