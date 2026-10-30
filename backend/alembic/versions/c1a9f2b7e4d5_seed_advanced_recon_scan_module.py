"""seed the advanced_recon scan module

Data-only, idempotent seed (ON CONFLICT DO NOTHING on `slug`).
downgrade() deletes the `advanced_recon` row by slug.

Revision ID: c1a9f2b7e4d5
Revises: adbd30582209
Create Date: 2026-10-19 00:00:00.000000
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c1a9f2b7e4d5"
down_revision: Union[str, Sequence[str], None] = "adbd30582209"
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
    "Advanced web & network reconnaissance: authorized ports/services "
    "check (explicit allowlist, no sweep), deep TLS analysis, passive "
    "WAF/CDN detection, and -- only when explicitly enabled by the "
    "operator -- an experimental visual snapshot. Independently "
    "selectable from the fundamental Recon module. Produces "
    "OBSERVATIONS, never offensive findings -- see "
    "app/engines/recon/schemas.py."
)


def upgrade() -> None:
    bind = op.get_bind()
    values = dict(
        id=uuid.uuid4(),
        slug="advanced_recon",
        name="Advanced Recon",
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
    op.execute(scan_modules.delete().where(scan_modules.c.slug == "advanced_recon"))
