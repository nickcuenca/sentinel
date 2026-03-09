import uuid

from app.models.audit import AuditLog
from app.models.secret import Secret
from app.models.user import User


def _register(client, username: str, password: str) -> str:
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def _login(client, username: str, password: str) -> str:
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _set_role(db_session, username: str, role: str) -> uuid.UUID:
    user = db_session.query(User).filter(User.username == username).one()
    user.role = role
    db_session.commit()
    return user.id


def test_user_cannot_retrieve_other_users_secret(client, db_session, encryption_key):
    alice_token = _register(client, "alice", "password123")
    bob_token = _register(client, "bob", "password123")

    r = client.post(
        "/secrets",
        headers=_auth(alice_token),
        json={"key": "api_key", "value": "alice-secret"},
    )
    assert r.status_code == 201, r.text

    r = client.get("/secrets/api_key", headers=_auth(bob_token), params={"owner": "alice"})
    assert r.status_code == 403, r.text


def test_admin_can_retrieve_any_secret(client, db_session, encryption_key):
    _register(client, "alice", "password123")
    _register(client, "admin", "password123")

    _set_role(db_session, "admin", "admin")
    admin_token = _login(client, "admin", "password123")
    alice_token = _login(client, "alice", "password123")

    r = client.post(
        "/secrets",
        headers=_auth(alice_token),
        json={"key": "db_password", "value": "pw1"},
    )
    assert r.status_code == 201, r.text

    r = client.get(
        "/secrets/db_password",
        headers=_auth(admin_token),
        params={"owner": "alice"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["value"] == "pw1"


def test_audit_log_written_on_every_access(client, db_session, encryption_key):
    token = _register(client, "alice", "password123")
    actor_id = _set_role(db_session, "alice", "user")
    token = _login(client, "alice", "password123")

    assert db_session.query(AuditLog).count() == 0

    r = client.post("/secrets", headers=_auth(token), json={"key": "k", "value": "v1"})
    assert r.status_code == 201, r.text

    r = client.get("/secrets/k", headers=_auth(token))
    assert r.status_code == 200, r.text
    assert r.json()["value"] == "v1"

    r = client.put("/secrets/k", headers=_auth(token), json={"value": "v2"})
    assert r.status_code == 200, r.text

    r = client.delete("/secrets/k", headers=_auth(token))
    assert r.status_code == 204, r.text

    logs = db_session.query(AuditLog).order_by(AuditLog.created_at.asc()).all()
    assert [l.action for l in logs] == [
        "secret.create",
        "secret.read",
        "secret.rotate",
        "secret.delete",
    ]
    assert all(l.actor_id == actor_id for l in logs)
    assert all(l.resource == "k" for l in logs)


def test_rotation_updates_ciphertext(client, db_session, encryption_key):
    _register(client, "alice", "password123")
    token = _login(client, "alice", "password123")

    r = client.post("/secrets", headers=_auth(token), json={"key": "rot", "value": "v1"})
    assert r.status_code == 201, r.text

    secret1 = (
        db_session.query(Secret)
        .join(User, User.id == Secret.owner_id)
        .filter(User.username == "alice", Secret.key == "rot")
        .one()
    )
    ct1 = secret1.ciphertext
    assert "v1" not in ct1

    r = client.put("/secrets/rot", headers=_auth(token), json={"value": "v2"})
    assert r.status_code == 200, r.text

    db_session.expire_all()
    secret2 = (
        db_session.query(Secret)
        .join(User, User.id == Secret.owner_id)
        .filter(User.username == "alice", Secret.key == "rot")
        .one()
    )
    ct2 = secret2.ciphertext
    assert ct2 != ct1

    r = client.get("/secrets/rot", headers=_auth(token))
    assert r.status_code == 200, r.text
    assert r.json()["value"] == "v2"


def test_list_returns_keys_only(client, db_session, encryption_key):
    _register(client, "alice", "password123")
    token = _login(client, "alice", "password123")

    client.post("/secrets", headers=_auth(token), json={"key": "a", "value": "1"})
    client.post("/secrets", headers=_auth(token), json={"key": "b", "value": "2"})

    r = client.get("/secrets", headers=_auth(token))
    assert r.status_code == 200, r.text
    assert r.json() == [{"key": "a"}, {"key": "b"}]

