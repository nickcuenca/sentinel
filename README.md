# Sentinel

Sentinel is a secrets management service with AES-256-GCM encryption at rest, role-based access control, and immutable audit logging. A CLI client supports secret retrieval and rotation.

---

## Tech Stack

- **Backend:** Python, FastAPI, PostgreSQL, SQLAlchemy, Alembic
- **Security:** AES-256-GCM encryption (`cryptography`), bcrypt, JWT
- **Infrastructure:** Docker, Docker Compose, GitHub Actions

---

## Quick Start

### Generate required secrets

```bash
# Encryption key (32 bytes, base64-encoded)
python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"

# JWT secret
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Create `.env`

```env
POSTGRES_DB=sentinel
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=sentinel
DATABASE_URL=postgresql://sentinel:sentinel@db:5432/sentinel
SENTINEL_ENCRYPTION_KEY=<generated above>
JWT_SECRET_KEY=<generated above>
```

### Start the stack

```bash
docker compose up --build
docker compose exec api alembic upgrade head
```

API: http://localhost:8000  
Docs: http://localhost:8000/docs

---

## API Overview

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login and receive JWT |

### Secrets
| Method | Path | Description |
|--------|------|-------------|
| POST | `/secrets` | Create a secret (stored encrypted) |
| GET | `/secrets` | List own secret keys (no values) |
| GET | `/secrets/{key}` | Retrieve and decrypt a secret |
| PUT | `/secrets/{key}` | Rotate (update) a secret value |
| DELETE | `/secrets/{key}` | Delete a secret |

---

## RBAC

Three role tiers with least-privilege enforcement:

- **user** — own secrets only
- **manager** — can access secrets of other users
- **admin** — full access across all users

---

## Encryption

Every secret value is encrypted with **AES-256-GCM** before being written to the database:

- A random 12-byte nonce is generated per secret
- Ciphertext is stored as `nonce + ciphertext`, base64-encoded
- Plaintext is never written to disk or logs
- Key loaded from `SENTINEL_ENCRYPTION_KEY` environment variable

---

## Audit Logging

Every secret access writes an immutable audit log entry with:
- `actor_id` — who performed the action
- `action` — `secret.create`, `secret.read`, `secret.rotate`, `secret.delete`
- `resource` — the secret key
- `created_at` — timestamp

---

## CLI

```bash
pip install click httpx

python cli/sentinel.py register <username> <password>
python cli/sentinel.py login <username> <password>
python cli/sentinel.py set <key> <value>
python cli/sentinel.py get <key>
python cli/sentinel.py delete <key>
```

Base URL defaults to `http://localhost:8000`. Override with `SENTINEL_URL` env var.

---

## Running Tests

```bash
cd backend
python -m venv .venv
.venv/bin/pip install -r requirements.txt
SENTINEL_ENCRYPTION_KEY=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())") \
  .venv/bin/python -m pytest tests/ -v
```

8 tests covering:
- AES-256-GCM encryption/decryption roundtrip
- Cross-user access denied (403)
- Admin cross-user access allowed
- Audit log written on every action
- Rotation updates ciphertext
- List returns keys only, never values

---

## Project Layout

```
sentinel/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes/        # auth, secrets, health
│   │   │   └── deps.py        # JWT auth, RBAC enforcement
│   │   ├── core/
│   │   │   ├── crypto.py      # AES-256-GCM encrypt/decrypt
│   │   │   ├── security.py    # bcrypt, JWT
│   │   │   └── config.py
│   │   ├── models/            # User, Secret, AuditLog
│   │   └── main.py
│   ├── alembic/               # DB migrations
│   ├── tests/
│   │   ├── test_crypto.py
│   │   └── test_secrets_api.py
│   └── requirements.txt
├── cli/
│   └── sentinel.py            # Click CLI client
├── docker-compose.yml
└── .env                       # not committed
```
