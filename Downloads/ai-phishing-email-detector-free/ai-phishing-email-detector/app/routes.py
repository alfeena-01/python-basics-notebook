import json
import csv
import io
from flask import Blueprint, current_app, render_template, request, redirect, url_for, flash, jsonify, Response
from .db import get_db
from .rules import analyze_rules
from .scoring import calculate_score
from .ollama_client import check_ollama, analyze_with_ollama

bp = Blueprint("main", __name__)

def safe_text(value, limit):
    return " ".join((value or "").split())[:limit]

@bp.get("/")
def index():
    status = check_ollama(current_app.config["OLLAMA_URL"])
    return render_template("index.html", status=status, model=current_app.config["OLLAMA_MODEL"])

@bp.post("/analyze")
def analyze():
    sender = safe_text(request.form.get("sender"), 500)
    subject = safe_text(request.form.get("subject"), 500)
    body = (request.form.get("body") or "").strip()
    if not sender or not subject or not body:
        flash("Please fill in sender, subject and email body.", "error")
        return redirect(url_for("main.index"))
    if len(body) > 12000:
        flash("Email body is too long. Please keep it under 12,000 characters.", "error")
        return redirect(url_for("main.index"))

    rules = analyze_rules(sender, subject, body)
    ai_result = {
        "verdict": "Unable to determine",
        "reasons": [],
        "evidence": [],
        "uncertainty": "Local AI analysis was unavailable. The score uses rule checks plus a neutral fallback.",
        "next_steps": ["Do not click links or open attachments until verified.", "Contact the claimed organization using a trusted contact method."]
    }
    ai_error = None
    try:
        ai_result = analyze_with_ollama(sender, subject, body, current_app.config["OLLAMA_URL"], current_app.config["OLLAMA_MODEL"])
    except Exception as exc:
        ai_error = "Local AI could not complete analysis. Rule-based checks are still shown."
        current_app.logger.warning("Ollama analysis failed: %s", type(exc).__name__)

    score_data = calculate_score(rules["rule_points"], ai_result)
    findings = rules["findings"]
    verdict = ai_result["verdict"]
    record = {
        "sender": sender, "subject": subject, "score": score_data["score"],
        "category": score_data["category"], "verdict": verdict,
        "findings": findings, "ai": ai_result, "score_data": score_data, "ai_error": ai_error
    }
    db = get_db()
    cursor = db.execute(
        "INSERT INTO scans (sender, subject, score, category, verdict, findings_json, ai_summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (sender, subject, record["score"], record["category"], verdict,
         json.dumps({"rules": findings, "ai": ai_result}), score_data["summary"])
    )
    db.commit()
    record["id"] = cursor.lastrowid
    return render_template("result.html", result=record)

@bp.get("/history")
def history():
    q = safe_text(request.args.get("q"), 200)
    category = request.args.get("category", "")
    sql = "SELECT * FROM scans WHERE (sender LIKE ? OR subject LIKE ?)"
    params = [f"%{q}%", f"%{q}%"]
    if category in ("Low", "Medium", "High", "Critical"):
        sql += " AND category = ?"
        params.append(category)
    sql += " ORDER BY scanned_at DESC LIMIT 200"
    rows = get_db().execute(sql, params).fetchall()
    return render_template("history.html", rows=rows, q=q, category=category)

@bp.get("/scan/<int:scan_id>")
def scan_detail(scan_id):
    row = get_db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        flash("Scan not found.", "error")
        return redirect(url_for("main.history"))
    data = json.loads(row["findings_json"])
    result = {
        "id": row["id"], "sender": row["sender"], "subject": row["subject"],
        "score": row["score"], "category": row["category"], "verdict": row["verdict"],
        "findings": data.get("rules", []), "ai": data.get("ai", {}),
        "score_data": {"summary": row["ai_summary"]}, "ai_error": None
    }
    return render_template("result.html", result=result, historical=True)

@bp.post("/history/delete/<int:scan_id>")
def delete_scan(scan_id):
    get_db().execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    get_db().commit()
    flash("Scan deleted.", "success")
    return redirect(url_for("main.history"))

@bp.post("/history/clear")
def clear_history():
    if request.form.get("confirm") != "yes":
        flash("Please confirm before clearing history.", "error")
        return redirect(url_for("main.history"))
    get_db().execute("DELETE FROM scans")
    get_db().commit()
    flash("Scan history cleared.", "success")
    return redirect(url_for("main.history"))

@bp.get("/export/<int:scan_id>.json")
def export_json(scan_id):
    row = get_db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return jsonify({"error": "Scan not found"}), 404
    payload = dict(row)
    payload["findings"] = json.loads(payload.pop("findings_json"))
    return Response(json.dumps(payload, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=phishing-scan-{scan_id}.json"})

@bp.get("/health")
def health():
    status = check_ollama(current_app.config["OLLAMA_URL"])
    return jsonify({"app": "ok", "ollama": status, "model": current_app.config["OLLAMA_MODEL"]})
