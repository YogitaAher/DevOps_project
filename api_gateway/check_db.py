import sqlite3

conn = sqlite3.connect("data/scans.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM scans")
rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()