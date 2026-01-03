from fastapi import APIRouter, Depends

from app.api.deps import get_current_token

router = APIRouter(prefix="/me", tags=["me"])


@router.get("")
def me(payload: dict = Depends(get_current_token)):
    return {"sub": payload["sub"], "role": payload["role"]}