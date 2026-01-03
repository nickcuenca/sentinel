from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.api.routes.auth import router as auth_router
from app.api.routes.me import router as me_router

app = FastAPI(title="Sentinel")

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(me_router)
