import sqlite3
from flask import current_app, g

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db(app):
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                score INTEGER NOT NULL,
                category TEXT NOT NULL,
                verdict TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                ai_summary TEXT NOT NULL DEFAULT ''
            )
        """)
        db.commit()
        app.teardown_appcontext(close_db)
