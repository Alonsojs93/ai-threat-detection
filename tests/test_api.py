from fastapi.testclient import TestClient

from app.main import app


def normal_payload():
    return {
        "records": [
            {
                "timestamp": f"2026-07-18T10:30:{i:02d}Z",
                "ip": "203.0.113.10",
                "method": "GET",
                "path": "/shop" if i % 2 == 0 else "/product/shirt",
                "status_code": 200,
                "response_time_ms": 95 + i,
            }
            for i in range(6)
        ]
    }


def brute_force_payload():
    records = []
    for i in range(60):
        records.append(
            {
                "timestamp": f"2026-07-18T10:{30 + (i // 30):02d}:{i % 30:02d}Z",
                "ip": "198.51.100.99",
                "method": "POST",
                "path": "/wp-login.php",
                "status_code": 401,
                "response_time_ms": 120,
            }
        )
    return {"records": records}


def test_health():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_normal_batch_is_accepted():
    with TestClient(app) as client:
        response = client.post("/analyze", json=normal_payload())
        assert response.status_code == 200
        data = response.json()
        assert data["records_analyzed"] == 6
        assert data["entities_analyzed"] == 1
        assert data["action"] in {"ignorar", "alertar", "bloquear"}
        assert 0 <= data["confidence"] <= 1


def test_brute_force_is_detected():
    with TestClient(app) as client:
        response = client.post("/analyze", json=brute_force_payload())
        assert response.status_code == 200
        data = response.json()
        assert data["threat_detected"] is True
        assert data["action"] in {"alertar", "bloquear"}
        assert data["results"][0]["probable_behavior"] == "posible fuerza bruta"
