import sqlite3
import os

# Always create DB inside writable project directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vuln_kb.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Create DB only if not exists
    if os.path.exists(DB_PATH):
        return

    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            impact TEXT,
            remediation TEXT,
            cwe TEXT,
            cvss_vector TEXT,
            likelihood TEXT,
            severity TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print(f"[*] Database initialized at {DB_PATH}")

if __name__ == "__main__":
    init_db()
