"""seed the active_web_testing scan module

Data-only, idempotent seed (ON CONFLICT DO NOTHING on `slug`), same
pattern as the other module seeds.

Unlike the earlier modules, this one is seeded with `is_enabled=False`:
active testing must be explicitly turned on by an operator. It is also
gated by Settings.active_web_testing_enabled, the per-scan
active_testing_confirmed flag and the lab allowlist (see
app/core/config.py).

downgrade() deletes the `active_web_testing` row by slug.

Revision ID: a7c4e1f9d3b2
Revises: f3a0c9d2b6e1
Create Date: 2026-10-20 00:00:00.000000
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a7c4e1f9d3b2"
down_revision: Union[str, Sequence[str], None] = "f3a0c9d2b6e1"
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
    "Active Web Testing: controlled, non-destructive ACTIVE vulnerability testing "
    "(reflected-XSS marker injection, differential SQL-injection probing, HTTP "
    "parameter testing, active API-security checks) against an explicitly "
    "authorized lab target. Sends real test requests to the target, unlike every "
    "other module. Disabled by default -- requires an operator to explicitly "
    "enable this row, the deployment-level active_web_testing_enabled setting, the "
    "target's presence in active_web_testing_lab_allowlist, AND the scan owner's "
    "per-scan active_testing_confirmed=true -- before it can run at all. "
    "Independently selectable from Recon, Advanced Recon, and Web Vulnerability "
    "Assessment. Never auto-confirms a finding (CONFIRMED confidence is never "
    "used by this module's checks)."
)


def upgrade() -> None:
    bind = op.get_bind()
    values = dict(
        id=uuid.uuid4(),
        slug="active_web_testing",
        name="Active Web Testing",
        description=_DESCRIPTION,
        version="0.1.0",
        is_enabled=False,
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
    op.execute(scan_modules.delete().where(scan_modules.c.slug == "active_web_testing"))
