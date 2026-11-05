import json
from app import create_app

class FakeResponse:
    def raise_for_status(self): pass
    def json(self):
        return {"response": json.dumps({
            "verdict": "Suspicious", "reasons": ["Urgent language"],
            "evidence": ["act now"], "uncertainty": "Could be legitimate.",
            "next_steps": ["Verify with the sender through a known contact method."]
        })}

def test_home_and_analysis(monkeypatch, tmp_path):
    import app.routes as routes
    monkeypatch.setattr(routes, "check_ollama", lambda *a, **k: {"available": True, "models": ["llama3.2:3b"]})
    monkeypatch.setattr(routes, "analyze_with_ollama", lambda *a, **k: {
        "verdict": "Suspicious", "reasons": ["Urgent language"], "evidence": ["act now"],
        "uncertainty": "Could be legitimate.", "next_steps": ["Verify through a known contact."]
    })
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.sqlite3")})
    client = app.test_client()
    assert client.get("/").status_code == 200
    response = client.post("/analyze", data={
        "sender": "security@example.com", "subject": "Act now",
        "body": "Please verify your account immediately."
    })
    assert response.status_code == 200
    assert b"Scan results" in response.data
    assert client.get("/history").status_code == 200

def test_missing_fields_rejected(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test2.sqlite3")})
    response = app.test_client().post("/analyze", data={"sender": "", "subject": "", "body": ""}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Please fill in" in response.data
