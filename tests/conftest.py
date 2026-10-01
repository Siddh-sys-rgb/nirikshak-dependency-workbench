import pytest

from desk import create_app
from desk.advisories import now


class MockOSV:
    def query(self, packages):
        return [{"state": "complete", "records": [], "retrieved_at": now(), "reason": ""}
                for _ in packages]


@pytest.fixture
def app(tmp_path):
    return create_app({"TESTING": True, "DATA_DIR": str(tmp_path),
        "SECRET_KEY": "unit-test-only", "BUNDLED_CACHE": True,
        "SEED_DEMO": True, "OSV_CLIENT": MockOSV(), "LIVE_COOLDOWN": 0})


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def token(client):
    return {"X-CSRF-Token": client.get('/api/bootstrap').json['csrf']}
