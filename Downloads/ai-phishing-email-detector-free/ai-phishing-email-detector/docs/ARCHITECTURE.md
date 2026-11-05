# Architecture and workflow

1. The browser sends sender, subject and body to the Flask web application.
2. Flask validates required fields and input lengths.
3. The rule engine checks the message for documented warning signs.
4. The Ollama client sends the message to the local Ollama service. The model is prompted to return JSON.
5. The app validates the expected AI verdict and fields. If Ollama is unavailable or returns invalid data, the app shows a useful fallback instead of crashing.
6. The scoring function combines rule points and AI points, then assigns a category.
7. The result page displays the score, rule evidence, AI explanation, uncertainty and next steps.
8. The scan is stored in SQLite for later search, viewing, export or deletion.

## Main components

- `app/routes.py`: page routes, form validation, history and export.
- `app/rules.py`: deterministic rule checks and evidence.
- `app/ollama_client.py`: Ollama status and local model request.
- `app/scoring.py`: reproducible example score and risk category.
- `app/db.py`: SQLite connection and table creation.
- `app/templates/` and `app/static/`: dashboard interface.
- `tests/`: automated tests.

## Privacy and security

The app does not open URLs, send emails or download attachments. SQL uses placeholders for user-provided values. The database is local. Use synthetic or authorized email samples. This is a student demonstration and not a production security product.
