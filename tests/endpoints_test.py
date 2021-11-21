from app import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


def test_main_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "working"}

def test_unexist_root():
    response = client.get("/unexist-endpoint")
    assert response.status_code == 404
    assert response.json() == {"detail":"Not Found"}