from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    dashboard,
    findings,
    health,
    reports,
    scan_modules,
    scan_profiles,
    scans,
    targets,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router, tags=["auth"])
api_router.include_router(targets.router, tags=["targets"])
api_router.include_router(scans.router, tags=["scans"])
api_router.include_router(scan_modules.router, tags=["scan-modules"])
api_router.include_router(findings.router, tags=["findings"])
api_router.include_router(dashboard.router, tags=["dashboard"])
api_router.include_router(scan_profiles.router, tags=["scan-profiles"])
api_router.include_router(reports.router, tags=["reports"])
