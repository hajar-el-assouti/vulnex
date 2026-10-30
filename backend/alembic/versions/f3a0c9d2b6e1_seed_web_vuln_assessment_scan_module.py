"""seed the web_vuln_assessment scan module

Data-only, idempotent seed (ON CONFLICT DO NOTHING on `slug`).
downgrade() deletes the `web_vuln_assessment` row by slug.

Revision ID: f3a0c9d2b6e1
Revises: c1a9f2b7e4d5
Create Date: 2026-10-19 00:00:00.000000
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f3a0c9d2b6e1"
down_revision: Union[str, Sequence[str], None] = "c1a9f2b7e4d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

scan_modules = sa.table(
    "scan_modules",
    sa.column("id", sa.Uuid()),
    sa.column("slug", sa.String()),
    sa.column("name", sa.String()),
    sa.column("description", sa.Text()),
    sa.column("version", sa.String()),
    sa.column("is_enabled", sa.Boolean()),
    sa.column("default_config", sa.JSON()),
)

_DESCRIPTION = (
    "Web Vulnerability Assessment: passive, non-destructive analysis of "
    "security headers, cookie flags, CORS configuration, TLS/HTTPS "
    "configuration, HTTP-methods exposure, information disclosure, "
    "passive XSS/SQLi surface indicators, and passive API-security "
    "controls. Independently selectable from Recon and Advanced Recon. "
    "The first module in this platform to populate real "
    "scan_findings rows -- see app/engines/web_vuln/findings.py."
)


def upgrade() -> None:
    bind = op.get_bind()
    values = dict(
        id=uuid.uuid4(),
        slug="web_vuln_assessment",
        name="Web Vulnerability Assessment",
        description=_DESCRIPTION,
        version="0.1.0",
        is_enabled=True,
        default_config={},
    )
    if bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        stmt = pg_insert(scan_modules).values(**values).on_conflict_do_nothing(
            index_elements=["slug"]
        )
    else:  # pragma: no cover - this migration only ever runs against Postgres
        stmt = sa.insert(scan_modules).values(**values)
    op.execute(stmt)


def downgrade() -> None:
    op.execute(scan_modules.delete().where(scan_modules.c.slug == "web_vuln_assessment"))
