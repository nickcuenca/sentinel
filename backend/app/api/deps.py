from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import settings

bearer = HTTPBearer()


def get_current_token(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict:
    token = creds.credentials
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        # payload should contain: sub, role, exp
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def require_role(*allowed_roles: str):
    def _inner(payload: dict = Depends(get_current_token)) -> dict:
        role = payload.get("role")
        if role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return payload
    return _inner