"""Import every model here so that:

1. `Base.metadata` is fully populated for Alembic autogenerate.
2. Relationship string references (e.g. Mapped["User"]) resolve correctly,
   regardless of which module is imported first.
"""

from app.models.report import Report, ReportFormat, ReportStatus
from app.models.scan import TERMINAL_SCAN_STATUSES, Scan, ScanStatus
from app.models.scan_event import ScanEvent, ScanEventType
from app.models.scan_finding import Confidence, FindingStatus, ScanFinding, Severity
from app.models.scan_module import ScanModule
from app.models.scan_module_run import ScanModuleRun, ScanModuleRunStatus
from app.models.scan_profile import ScanProfile
from app.models.target import Target
from app.models.user import User, UserRole
from app.models.user_session import UserSession

__all__ = [
    "User",
    "UserRole",
    "UserSession",
    "Target",
    "ScanModule",
    "Scan",
    "ScanStatus",
    "TERMINAL_SCAN_STATUSES",
    "ScanModuleRun",
    "ScanModuleRunStatus",
    "ScanFinding",
    "Severity",
    "Confidence",
    "FindingStatus",
    "ScanProfile",
    "ScanEvent",
    "ScanEventType",
    "Report",
    "ReportFormat",
    "ReportStatus",
]
