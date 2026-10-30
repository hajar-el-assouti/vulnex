"""seed the discovery_fuzzing scan module

Data-only, idempotent seed (ON CONFLICT DO NOTHING on `slug`).

Like active_web_testing, this module is seeded with:
- `is_enabled=False`: an operator must enable it explicitly (see
  Settings.discovery_fuzzing_enabled).
- `requires_active_confirmation=True`: it sends requests for paths the
  user never asked for by name, so it counts as active testing even
  though it only uses GET.

downgrade() deletes the `discovery_fuzzing` row by slug.

Revision ID: e5a2c8f1b7d4
Revises: d8e1f4a6c3b9
Create Date: 2026-10-25 00:00:00.000000
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e5a2c8f1b7d4"
down_revision: Union[str, Sequence[str], None] = "d8e1f4a6c3b9"
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
    sa.column("requires_active_confirmation", sa.Boolean()),
    sa.column("default_config", sa.JSON()),
)

_DESCRIPTION = (
    "Discovery & Fuzzing: content/path discovery against a SecLists-derived "
    "wordlist (Discovery/Web-Content/common.txt, MIT-licensed, see "
    "app/engines/discovery_fuzzing/wordlists/README.md). GET-only, never follows "
    "a redirect, soft-404-aware. Disabled by default -- requires an operator to "
    "explicitly enable this row, the deployment-level discovery_fuzzing_enabled "
    "setting, the target's presence in discovery_fuzzing_lab_allowlist, AND the "
    "scan owner's per-scan active_testing_confirmed=true -- before it can run at "
    "all. Independently selectable from every other module. Never records a "
    "discovered path as a security Finding automatically -- observations only."
)


def upgrade() -> None:
    bind = op.get_bind()
    values = dict(
        id=uuid.uuid4(),
        slug="discovery_fuzzing",
        name="Discovery & Fuzzing",
        description=_DESCRIPTION,
        version="0.1.0",
        is_enabled=False,
        requires_active_confirmation=True,
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
    op.execute(scan_modules.delete().where(scan_modules.c.slug == "discovery_fuzzing"))
