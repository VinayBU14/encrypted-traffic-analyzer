"""
Fixes findings column in alerts table.
Converts pipe-separated strings to JSON arrays so the API can parse them.
Run once: python fix_findings.py
"""
import sqlite3
import json

DB_PATH = "data/spectra.db"

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

rows = conn.execute("SELECT alert_id, findings FROM alerts").fetchall()
print(f"Total alerts to fix: {len(rows)}")

fixed = 0
skipped = 0
for row in rows:
    findings_raw = row["findings"]
    if not findings_raw:
        conn.execute("UPDATE alerts SET findings = ? WHERE alert_id = ?",
                     (json.dumps([]), row["alert_id"]))
        fixed += 1
        continue

    # Already valid JSON? Skip
    try:
        parsed = json.loads(findings_raw)
        if isinstance(parsed, list):
            skipped += 1
            continue
    except (json.JSONDecodeError, TypeError):
        pass

    # Convert pipe-separated string to JSON array
    findings_list = [f.strip() for f in str(findings_raw).split("|") if f.strip()]
    conn.execute("UPDATE alerts SET findings = ? WHERE alert_id = ?",
                 (json.dumps(findings_list), row["alert_id"]))
    fixed += 1

conn.commit()
conn.close()
print(f"Done — fixed: {fixed}, already JSON: {skipped}")