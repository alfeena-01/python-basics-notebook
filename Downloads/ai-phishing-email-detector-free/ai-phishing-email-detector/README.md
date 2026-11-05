# AI-Powered Phishing Email Detection System

A free, local-first student project built with Python, Flask, SQLite and Ollama. It checks an email's sender, subject and body using transparent rules and (when available) a local language model. It does not require a paid AI API key.

## Features

- Dark responsive web dashboard for entering email sender, subject and body.
- Rule checks for links, unusual URL formats, urgency, credential requests, payment requests and possible sender/organization mismatch.
- Optional local AI assessment through Ollama with structured JSON output.
- Combined 0–100 advisory score, Low/Medium/High/Critical category and explanations.
- SQLite scan history with search, risk filter, detail view, delete and clear-history confirmation.
- Downloadable JSON scan reports.
- Tests for rules, score boundaries, form validation and a mocked AI response.

## What is free?

Python, Flask, SQLite, pytest and Ollama are free/open-source. The language model runs on your own computer, so there is no per-request paid AI API. You need enough RAM and disk space to run the model. The app's Google Fonts import is only for styling; if you want fully offline UI assets too, remove the `@import` line in `app/static/style.css` and it will use system fonts.

## Requirements

- Python 3.11 or newer
- Ollama for local AI analysis (optional; rule-based analysis still runs without it)
- Internet only to install packages and download the local model. After installation/model download, scans can run locally.

## Setup on Windows

Open Command Prompt or PowerShell in this project folder:

```powershell
py -m venv .venv
.venv\\Scripts\\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Optional local AI setup

1. Install Ollama from its official website: https://ollama.com
2. Open a terminal and download the model:

```powershell
ollama pull llama3.2:3b
```

3. Ensure Ollama is running. Its local API is normally at `http://127.0.0.1:11434`.
4. If using a different model, set `OLLAMA_MODEL` in your environment before starting the app. Default: `llama3.2:3b`.

The model download may take several GB and needs a compatible computer. Ollama and the model are free; hardware and electricity are your own costs.

## Run

```powershell
python run.py
```

Open `http://127.0.0.1:5000` in your browser. Keep the terminal running while using the app. Visit `/health` to check the app and Ollama status.

## Tests

```powershell
pytest -q
```

Tests use a mocked local AI response and do not require the Ollama model to be running.

## Scoring

The rule engine contributes up to 60 points. The AI assessment contributes up to 40 points. The current example maps the AI verdict to a fixed contribution and adds a small capped contribution when suspicious verdicts include reasons. Categories are Low (0–24), Medium (25–49), High (50–74) and Critical (75–100). These thresholds are illustrative, not a validated security standard. Review `app/rules.py` and `app/scoring.py` to change or explain the scoring method.

## Safety and limitations

- Results are advisory and can be wrong. Legitimate messages may be flagged and phishing emails may be missed.
- The rule checks are intentionally simple and are not a replacement for an email security gateway.
- If Ollama is unavailable, the app falls back to rule signals and a neutral AI score contribution.
- Never automatically open links or attachments. Verify unexpected requests using a separate trusted channel.
- Use synthetic or authorized examples only. Avoid pasting passwords, OTPs or sensitive personal information.
- Scan history is stored in `instance/scans.sqlite3` on your computer. Use the history page to delete records; the local database is excluded from Git.
- Local AI processing reduces external transmission but does not guarantee your computer, logs or database are secure.

## Project structure

```text
ai-phishing-email-detector/
  app/
    __init__.py
    db.py
    ollama_client.py
    routes.py
    rules.py
    scoring.py
    static/style.css
    templates/
  tests/
  instance/             # created at runtime, ignored by Git
  .env.example
  .gitignore
  requirements.txt
  run.py
```

## GitHub delivery checklist

1. Create a repository named `ai-phishing-email-detector`.
2. Commit source code, tests, README and screenshots.
3. Do not commit `.env`, the SQLite database, secrets or real email content.
4. Include screenshots after running the app and share the repository URL with your instructor/team.
