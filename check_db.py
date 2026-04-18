import sqlite3
conn = sqlite3.connect('data/spectra.db')
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print('Tables:', tables)
for (t,) in tables:
    count = conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
    print(f'  {t}: {count} rows')
    if count > 0 and t in ('alerts', 'flows'):
        sample = conn.execute(f'SELECT * FROM "{t}" LIMIT 2').fetchall()
        print(f'  sample: {sample}')
conn.close()