from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


def test_login_page_renders():
    response = client.get("/")
    assert response.status_code == 200
    assert "VISHWAS" in response.text
    assert "gov.css" in response.text or "VISHWAS" in response.text


def test_meta_endpoint():
    response = client.get("/api/v1/meta")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "VISHWAS"
    assert "not an official Government of India product" in body["disclaimer"].lower()


def test_healthz():
    response = client.get("/api/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_captcha_and_login_mfa():
    cap = client.get("/api/v1/captcha").json()
    answer = cap["challenge"].split("+")[0].strip()
    # challenge is "a + b = ?"
    parts = cap["challenge"].replace("=", "").replace("?", "").split("+")
    answer = str(int(parts[0].strip()) + int(parts[1].strip()))
    res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst@vishwas.local",
            "password": "Demo@123",
            "captcha_token": cap["token"],
            "captcha_answer": answer,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["mfa_required"] is True
    mfa = client.post(
        "/api/v1/auth/mfa",
        json={"pending_token": data["pending_token"], "otp": "123456", "method": "OTP"},
    )
    assert mfa.status_code == 200
    assert mfa.json()["user"]["role"] == "SECURITY_ANALYST"
