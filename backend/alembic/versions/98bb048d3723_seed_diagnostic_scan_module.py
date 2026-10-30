"""seed the diagnostic scan module

Data-only migration: inserts one row into `scan_modules` for the
non-offensive diagnostic module (app/tasks/diagnostic.py), used to
check the orchestration path end to end.

ON CONFLICT DO NOTHING on the unique `slug` makes it safe to re-run.

Revision ID: 98bb048d3723
Revises: 7d54134c62fe
Create Date: 2026-10-17 00:05:00.000000
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "98bb048d3723"
down_revision: Union[str, Sequence[str], None] = "7d54134c62fe"
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
    "Not a security engine. Exercises the scan orchestration pipeline "
    "end to end (dispatch, status transitions, progress events, "
    "cooperative cancellation) without performing any network request "
    "and without ever producing a finding."
)


def upgrade() -> None:
    bind = op.get_bind()
    values = dict(
        id=uuid.uuid4(),
        slug="diagnostic",
        name="Diagnostic (orchestration self-test)",
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
    op.execute(scan_modules.delete().where(scan_modules.c.slug == "diagnostic"))
