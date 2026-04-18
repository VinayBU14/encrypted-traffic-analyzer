"""
Fixes both findings (alerts) and tcp_flags (flows) columns in spectra.db.
Converts pipe/comma-separated strings to proper JSON so the API doesn't crash.
Run once: python fix_db_formats.py
"""
import sqlite3
import json

DB_PATH = "data/spectra.db"
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Fix alerts.findings  (pipe-separated -> JSON array)
rows = conn.execute("SELECT alert_id, findings FROM alerts").fetchall()
print(f"Fixing {len(rows)} alert findings...")
fixed = 0
for row in rows:
    raw = row["findings"]
    try:
        parsed = json.loads(raw) if raw else []
        if isinstance(parsed, list):
            continue  # already good
    except Exception:
        pass
    findings_list = [f.strip() for f in str(raw).split("|") if f.strip()] if raw else []
    conn.execute("UPDATE alerts SET findings = ? WHERE alert_id = ?",
                 (json.dumps(findings_list), row["alert_id"]))
    fixed += 1
print(f"  Fixed {fixed} rows")

# Fix flows.tcp_flags  (comma-separated -> JSON object)
rows = conn.execute("SELECT flow_id, tcp_flags FROM flows").fetchall()
print(f"Fixing {len(rows)} flow tcp_flags...")
fixed = 0
for row in rows:
    raw = row["tcp_flags"]
    try:
        parsed = json.loads(raw) if raw else {}
        if isinstance(parsed, dict):
            continue  # already good
    except Exception:
        pass
    # Convert "SYN,ACK,FIN" -> {"SYN": true, "ACK": true, ...}
    flags_dict = {}
    if raw:
        for flag in str(raw).split(","):
            flag = flag.strip()
            if flag:
                flags_dict[flag] = True
    conn.execute("UPDATE flows SET tcp_flags = ? WHERE flow_id = ?",
                 (json.dumps(flags_dict), row["flow_id"]))
    fixed += 1
print(f"  Fixed {fixed} rows")

conn.commit()
conn.close()
print("Done — restart uvicorn and refresh the dashboard.")