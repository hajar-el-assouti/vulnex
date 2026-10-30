"""add requires_active_confirmation to scan_modules

Replaces the hardcoded "is this module 'active_web_testing'?" check in
app/services/scans.py::create_scan() with a column any module can set.

The column defaults to true (fail closed): a future seed that forgets
to set it will require confirmation instead of skipping it. The
existing passive modules (diagnostic, recon, advanced_recon,
web_vuln_assessment) are then set back to false; active_web_testing
stays true.

downgrade() drops the column.

Revision ID: d8e1f4a6c3b9
Revises: c7f2a9d4b8e3
Create Date: 2026-10-25 00:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d8e1f4a6c3b9"
down_revision: Union[str, Sequence[str], None] = "c7f2a9d4b8e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

scan_modules = sa.table(
    "scan_modules",
    sa.column("slug", sa.String()),
    sa.column("requires_active_confirmation", sa.Boolean()),
)

_PASSIVE_SLUGS = ("diagnostic", "recon", "advanced_recon", "web_vuln_assessment")
_ACTIVE_SLUGS = ("active_web_testing",)


def upgrade() -> None:
    op.add_column(
        "scan_modules",
        sa.Column(
            "requires_active_confirmation",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )

    for slug in _PASSIVE_SLUGS:
        op.execute(
            scan_modules.update()
            .where(scan_modules.c.slug == slug)
            .values(requires_active_confirmation=False)
        )

    for slug in _ACTIVE_SLUGS:
        op.execute(
            scan_modules.update()
            .where(scan_modules.c.slug == slug)
            .values(requires_active_confirmation=True)
        )


def downgrade() -> None:
    op.drop_column("scan_modules", "requires_active_confirmation")
