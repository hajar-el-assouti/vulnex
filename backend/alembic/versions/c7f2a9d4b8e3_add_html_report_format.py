"""add HTML to the report_format enum

Reports can be generated as PDF or HTML. ALTER TYPE ... ADD VALUE must
run outside a transaction (autocommit_block) and uses IF NOT EXISTS so
it can be re-run. Postgres cannot drop an enum value, so downgrade()
cannot remove it.

Revision ID: c7f2a9d4b8e3
Revises: b4c9e7f1a2d6
Create Date: 2026-10-20 00:00:01.000000
"""
from typing import Sequence, Union

from alembic import op

revision: str = "c7f2a9d4b8e3"
down_revision: Union[str, Sequence[str], None] = "b4c9e7f1a2d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE report_format ADD VALUE IF NOT EXISTS 'HTML'")


def downgrade() -> None:
    # Not reversible -- see 7d54134c62fe's own downgrade() comment for
    # why this is a documented, accepted limitation (Postgres has no
    # ALTER TYPE ... DROP VALUE) rather than a bug. No report can exist
    # with format='HTML' without this revision's application code
    # running in the first place.
    pass
