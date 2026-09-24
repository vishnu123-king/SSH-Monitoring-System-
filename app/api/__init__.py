"""API routes package."""

from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.routes_health import router as health_router
from app.api.routes_events import router as events_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_stats import router as stats_router
from app.api.routes_sources import router as sources_router
from app.api.routes_maintenance import router as maintenance_router

api_router = APIRouter(prefix="/api")
api_router.include_router(auth_router)
api_router.include_router(health_router)
api_router.include_router(events_router)
api_router.include_router(alerts_router)
api_router.include_router(stats_router)
api_router.include_router(sources_router)
api_router.include_router(maintenance_router)

__all__ = ["api_router"]
