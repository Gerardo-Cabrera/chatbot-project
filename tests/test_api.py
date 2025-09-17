import os
from fastapi.testclient import TestClient
from backend.main import app
API_KEY = os.environ.get("API_KEY", "demo_super_secret_key_please_change")
client = TestClient(app)
def test_questions():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    res = client.get("/api/questions?limit=5", headers=headers)
    assert res.status_code == 200
