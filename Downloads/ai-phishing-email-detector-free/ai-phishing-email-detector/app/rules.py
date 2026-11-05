import re
from urllib.parse import urlparse

URGENT_TERMS = [
    "urgent", "immediately", "act now", "within 24 hours", "account suspended",
    "account will be closed", "final warning", "verify now", "limited time"
]
CREDENTIAL_TERMS = [
    "password", "one-time password", "otp", "login credentials", "security code",
    "confirm your identity", "verify your account"
]
PAYMENT_TERMS = ["wire transfer", "gift card", "payment overdue", "bank details", "send payment"]
URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def analyze_rules(sender, subject, body):
    text = f"{subject}\n{body}"
    lowered = text.lower()
    findings = []

    urls = URL_RE.findall(text)
    if urls:
        findings.append({
            "id": "links_present", "label": "Contains a link",
            "points": 8, "evidence": urls[:3],
            "explanation": "Links are not automatically malicious, but destinations should be checked carefully."
        })
    suspicious_urls = []
    for raw in urls:
        cleaned = raw.rstrip(".,);]")
        candidate = cleaned if cleaned.lower().startswith(("http://", "https://")) else "http://" + cleaned
        host = urlparse(candidate).hostname or ""
        if host and (IP_HOST_RE.match(host) or "xn--" in host.lower() or host.count(".") >= 4):
            suspicious_urls.append(cleaned)
    if suspicious_urls:
        findings.append({
            "id": "suspicious_url", "label": "Potentially suspicious URL format",
            "points": 22, "evidence": suspicious_urls[:3],
            "explanation": "An IP-address host, internationalized domain marker, or unusually deep subdomain can be a warning sign."
        })

    urgent = [term for term in URGENT_TERMS if term in lowered]
    if urgent:
        findings.append({
            "id": "urgency", "label": "Urgent or threatening language",
            "points": 12, "evidence": urgent[:4],
            "explanation": "Pressure to act quickly can be used to stop people from checking a message."
        })

    credentials = [term for term in CREDENTIAL_TERMS if term in lowered]
    if credentials:
        findings.append({
            "id": "credential_request", "label": "Account or credential language",
            "points": 20, "evidence": credentials[:4],
            "explanation": "Messages asking for passwords, OTPs, or account verification deserve extra caution."
        })

    payment = [term for term in PAYMENT_TERMS if term in lowered]
    if payment:
        findings.append({
            "id": "payment_request", "label": "Payment or financial request",
            "points": 16, "evidence": payment[:4],
            "explanation": "Unexpected payment or bank-detail requests should be verified through a trusted channel."
        })

    sender_match = re.search(r"<([^>]+)>", sender or "")
    sender_address = sender_match.group(1) if sender_match else (sender or "")
    sender_domain = sender_address.split("@")[-1].lower() if "@" in sender_address else ""
    if sender_domain and any(x in sender_domain for x in ["gmail.com", "outlook.com", "yahoo.com"]):
        organization_words = ["payroll", "security team", "it department", "your bank", "microsoft", "google"]
        if any(word in lowered for word in organization_words):
            findings.append({
                "id": "possible_sender_mismatch", "label": "Possible sender / organization mismatch",
                "points": 12, "evidence": [sender_domain],
                "explanation": "A free email domain paired with an organization claim may need verification; this is only a weak signal."
            })

    # Count each rule once. The total rule contribution is capped at 60.
    rule_points = min(60, sum(f["points"] for f in findings))
    return {"findings": findings, "rule_points": rule_points}
