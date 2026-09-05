from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_login_page_renders():
    response = client.get("/")
    assert response.status_code == 200
    assert "Enterprise Threat Monitor" in response.text
