import sqlite3

from constants import resolve_workspace_root

_DEFAULT_DB = str(resolve_workspace_root() / "ids.db")


class DatabaseManager:
    def __init__(self, db_path: str = _DEFAULT_DB):
        self.conn = sqlite3.connect(db_path)
        self.c = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        self.c.execute('''CREATE TABLE IF NOT EXISTS targets
                    (id INTEGER PRIMARY KEY, ip_address TEXT, port INTEGER, status TEXT)''')
        self.c.execute('''CREATE TABLE IF NOT EXISTS sessions
                    (id INTEGER PRIMARY KEY, target_id INTEGER, payload TEXT, status TEXT, start_time DATETIME, end_time DATETIME, note TEXT,
                    FOREIGN KEY(target_id) REFERENCES targets(id))''')
        self.c.execute('''CREATE TABLE IF NOT EXISTS notes
                    (id INTEGER PRIMARY KEY, target_id INTEGER, note TEXT,
                    FOREIGN KEY(target_id) REFERENCES targets(id))''')
        self.conn.commit()


        
    def add_target(self, ip_address, port):
        try:
            self.c.execute("INSERT INTO targets (ip_address, port, status) VALUES (?, ?, 'active')", (ip_address, port))
            self.conn.commit()
        except sqlite3.Error as e:
            return f"Error adding target: {e}"
        return "Target added"

    def get_active_targets(self):
        try:
            self.c.execute("SELECT * FROM targets WHERE status = 'active'")
            return self.c.fetchall()
        except sqlite3.Error as e:
            return f"Error getting active targets: {e}"
    def get_target_by_ip(self, ip_address):
        try:
            self.c.execute("SELECT * FROM targets WHERE ip_address = ?", (ip_address,))
            return self.c.fetchall()
        except sqlite3.Error as e:
            return f"Error getting target by IP: {e}"

    def get_target_ips(self):
        try:
            self.c.execute("SELECT ip_address FROM targets")
            return [row[0] for row in self.c.fetchall()]
        except sqlite3.Error as e:
            return f"Error getting target IPs: {e}"

    def add_note(self, target_id, note):
        try:
            self.c.execute("INSERT INTO notes (target_id, note) VALUES (?, ?)", (target_id, note))
            self.conn.commit()
            return "Note added"
        except sqlite3.Error as e:
            return f"Error adding note: {e}"

    def add_session(self, target_id, payload):
        try:
            self.c.execute("INSERT INTO sessions (target_id, payload, status, start_time) VALUES (?, ?, 'active', CURRENT_TIMESTAMP)", (target_id, payload))
            self.conn.commit()
        except sqlite3.Error as e:
            return f"Error adding session: {e}"
        return "Session added"

    def close_db(self):
        self.conn.close()
        return "Database closed"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_db()
