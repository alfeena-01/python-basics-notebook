from app.rules import analyze_rules
from app.scoring import calculate_score

def test_urgent_credential_email_gets_signals():
    result = analyze_rules("help@example.com", "Urgent: verify now", "Your account is suspended. Enter your password and OTP immediately.")
    ids = {x["id"] for x in result["findings"]}
    assert "urgency" in ids
    assert "credential_request" in ids
    assert result["rule_points"] > 0

def test_plain_email_no_signals():
    result = analyze_rules("colleague@company.example", "Meeting notes", "Hello, attached are the notes from our meeting.")
    assert result["findings"] == []
    assert result["rule_points"] == 0

def test_score_category_is_bounded():
    result = calculate_score(60, {"verdict": "Likely phishing", "reasons": ["Urgency", "Credential request"]})
    assert 0 <= result["score"] <= 100
    assert result["category"] in {"Low", "Medium", "High", "Critical"}
