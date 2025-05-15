import sqlite3


class URLStorage:
    def __init__(self, db_path=":memory:"):
        import sqlite3
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.init_db()

    def init_db(self):
        self.cursor.execute('''
                            CREATE TABLE IF NOT EXISTS urls
                            (
                                id
                                INTEGER
                                PRIMARY
                                KEY,
                                url
                                TEXT
                                UNIQUE,
                                params
                                TEXT,
                                risk_score
                                INTEGER,
                                visited
                                BOOLEAN
                            )
                            ''')
        self.conn.commit()

    def add_url(self, url, params=None, risk_score=0):
        params_str = ",".join(params) if params else ""
        try:
            self.cursor.execute(
                "INSERT OR IGNORE INTO urls (url, params, risk_score, visited) VALUES (?, ?, ?, ?)",
                (url, params_str, risk_score, False)
            )
            self.conn.commit()
            return True
        except:
            return False

    def get_urls(self, limit=100, offset=0, order_by="risk_score DESC"):
        self.cursor.execute(
            f"SELECT url, params, risk_score FROM urls ORDER BY {order_by} LIMIT ? OFFSET ?",
            (limit, offset)
        )
        return self.cursor.fetchall()

    def count_urls(self):
        self.cursor.execute("SELECT COUNT(*) FROM urls")
        return self.cursor.fetchone()[0]

    def count_param_urls(self):
        self.cursor.execute("SELECT COUNT(*) FROM urls WHERE params != ''")
        return self.cursor.fetchone()[0]