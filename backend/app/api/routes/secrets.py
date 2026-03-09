from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, resolve_target_user
from app.api.schemas.secrets import (
    SecretCreateRequest,
    SecretKeyResponse,
    SecretRotateRequest,
    SecretValueResponse,
)
from app.core.crypto import decrypt, encrypt
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.secret import Secret

router = APIRouter(prefix="/secrets", tags=["secrets"])


def _audit(db: Session, *, actor_id, action: str, secret_key: str) -> None:
    db.add(AuditLog(actor_id=actor_id, action=action, resource=secret_key))


@router.post("", response_model=SecretKeyResponse, status_code=status.HTTP_201_CREATED)
def create_secret(
    payload: SecretCreateRequest,
    owner: str | None = Query(default=None, description="Owner username (admin/manager only)"),
    db: Session = Depends(get_db),
    actor=Depends(get_current_user),
):
    target_user = resolve_target_user(owner_username=owner, db=db, actor=actor)

    existing = (
        db.query(Secret)
        .filter(Secret.owner_id == target_user.id, Secret.key == payload.key)
        .first()
    )
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Secret already exists")

    ciphertext = encrypt(payload.value)
    secret = Secret(owner_id=target_user.id, key=payload.key, ciphertext=ciphertext)
    db.add(secret)
    _audit(db, actor_id=actor.id, action="secret.create", secret_key=payload.key)
    db.commit()
    return {"key": secret.key}


@router.get("", response_model=list[SecretKeyResponse])
def list_secrets(
    db: Session = Depends(get_db),
    actor=Depends(get_current_user),
):
    secrets = db.query(Secret).filter(Secret.owner_id == actor.id).order_by(Secret.key.asc()).all()
    return [{"key": s.key} for s in secrets]


@router.get("/{key}", response_model=SecretValueResponse)
def get_secret(
    key: str,
    owner: str | None = Query(default=None, description="Owner username (admin/manager only)"),
    db: Session = Depends(get_db),
    actor=Depends(get_current_user),
):
    target_user = resolve_target_user(owner_username=owner, db=db, actor=actor)
    secret = (
        db.query(Secret)
        .filter(Secret.owner_id == target_user.id, Secret.key == key)
        .first()
    )
    if not secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    value = decrypt(secret.ciphertext)
    _audit(db, actor_id=actor.id, action="secret.read", secret_key=key)
    db.commit()
    return {"key": key, "value": value}


@router.put("/{key}", response_model=SecretKeyResponse)
def rotate_secret(
    key: str,
    payload: SecretRotateRequest,
    owner: str | None = Query(default=None, description="Owner username (admin/manager only)"),
    db: Session = Depends(get_db),
    actor=Depends(get_current_user),
):
    target_user = resolve_target_user(owner_username=owner, db=db, actor=actor)
    secret = (
        db.query(Secret)
        .filter(Secret.owner_id == target_user.id, Secret.key == key)
        .first()
    )
    if not secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    secret.ciphertext = encrypt(payload.value)
    _audit(db, actor_id=actor.id, action="secret.rotate", secret_key=key)
    db.commit()
    return {"key": key}


@router.delete("/{key}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(
    key: str,
    owner: str | None = Query(default=None, description="Owner username (admin/manager only)"),
    db: Session = Depends(get_db),
    actor=Depends(get_current_user),
):
    target_user = resolve_target_user(owner_username=owner, db=db, actor=actor)
    secret = (
        db.query(Secret)
        .filter(Secret.owner_id == target_user.id, Secret.key == key)
        .first()
    )
    if not secret:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    db.delete(secret)
    _audit(db, actor_id=actor.id, action="secret.delete", secret_key=key)
    db.commit()
    return None

