from datetime import datetime

from pydantic import BaseModel


class LivenessResponse(BaseModel):
    """Process is up and able to handle requests. Never touches the DB --
    if this fails, the process itself is the problem."""

    status: str
    service: str
    environment: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    """Process is up AND its dependencies (currently: the database) are
    reachable. This is the one an orchestrator should gate traffic on."""

    status: str
    database: str
    timestamp: datetime
