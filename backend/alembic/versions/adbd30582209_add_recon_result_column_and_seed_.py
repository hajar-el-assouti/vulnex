"""add scan_module_runs.result JSONB and seed the recon scan module

- Adds a nullable `result` JSONB column so module output can be stored.
  NULL is correct for existing rows, so no backfill is needed.
- Registers the `recon` module (idempotent, ON CONFLICT DO NOTHING on
  `slug`).

downgrade() deletes the `recon` row by slug, then drops the column.

Revision ID: adbd30582209
Revises: 98bb048d3723
Create Date: 2026-10-19 00:30:00.000000
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "adbd30582209"
down_revision: Union[str, Sequence[str], None] = "98bb048d3723"
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
    "Passive web reconnaissance: HTTP/headers/cookies/technology/metadata, "
    "DNS/email-security/IP-ASN/RDAP/TLS infrastructure, external assets and "
    "API endpoint discovery, and run-over-run fingerprint comparison. "
    "Produces OBSERVATIONS, never offensive findings -- see "
    "app/engines/recon/schemas.py."
)


def upgrade() -> None:
    # Additive, nullable -- every existing scan_module_runs row gets
    # NULL automatically; no backfill, no table rewrite requiring a
    # lock beyond the one Postgres already takes for ADD COLUMN.
    op.add_column(
        "scan_module_runs",
        sa.Column("result", JSONB(), nullable=True),
    )

    bind = op.get_bind()
    values = dict(
        id=uuid.uuid4(),
        slug="recon",
        name="Recon (Web Reconnaissance Engine v1)",
        description=_DESCRIPTION,
        version="1.0.0",
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
    op.execute(scan_modules.delete().where(scan_modules.c.slug == "recon"))
    op.drop_column("scan_module_runs", "result")
