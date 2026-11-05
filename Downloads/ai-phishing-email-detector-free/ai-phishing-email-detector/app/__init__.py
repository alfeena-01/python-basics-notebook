import os
from flask import Flask
from .db import init_db

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "local-dev-change-me"),
        DATABASE=os.path.join(app.instance_path, "scans.sqlite3"),
        OLLAMA_URL=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
        OLLAMA_MODEL=os.environ.get("OLLAMA_MODEL", "llama3.2:3b"),
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)
    init_db(app)
    from .routes import bp
    app.register_blueprint(bp)
    return app
