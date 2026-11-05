def calculate_score(rule_points, ai_result):
    # Rule contribution is capped at 60; AI contributes at most 40.
    verdict = (ai_result or {}).get("verdict", "Unable to determine")
    reasons = (ai_result or {}).get("reasons", [])
    ai_points = {
        "Likely phishing": 32,
        "Suspicious": 22,
        "Likely legitimate": 0,
        "Unable to determine": 10,
    }.get(verdict, 10)
    if reasons and verdict in ("Likely phishing", "Suspicious"):
        ai_points = min(40, ai_points + min(8, len(reasons) * 2))
    score = max(0, min(100, int(rule_points) + ai_points))
    if score <= 24:
        category = "Low"
    elif score <= 49:
        category = "Medium"
    elif score <= 74:
        category = "High"
    else:
        category = "Critical"
    if category in ("High", "Critical") or verdict == "Likely phishing":
        summary = "Treat this email as suspicious and verify it using a separate trusted channel."
    elif category == "Medium" or verdict == "Suspicious":
        summary = "Check the sender and any requests carefully before taking action."
    else:
        summary = "No strong warning was found, but this result cannot guarantee the email is safe."
    return {"score": score, "category": category, "summary": summary, "ai_points": ai_points}
