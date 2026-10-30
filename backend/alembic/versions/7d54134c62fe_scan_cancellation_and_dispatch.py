"""scan cancellation and reliable-dispatch columns

Adds the CANCELLING value to the scan_status enum and three new columns
on `scans` (cancel_requested_at, dispatched_at, dispatch_attempts).
Additive on top of the initial schema; the baseline migration is not
modified.

Revision ID: 7d54134c62fe
Revises: 5b57b97cd8c2
Create Date: 2026-10-17 00:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "7d54134c62fe"
down_revision: Union[str, Sequence[str], None] = "5b57b97cd8c2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Adding a value to a native Postgres enum type cannot run inside the
    # same transaction as other DDL (ALTER TYPE ... ADD VALUE requires
    # its own transaction before PG 12, and even on modern PG must not
    # share a transaction with code that might already have read the
    # type) -- autocommit_block() runs this one statement outside the
    # migration's normal transaction. IF NOT EXISTS makes re-running this
    # safe (e.g. after a partial failure) without erroring on a value
    # that's already there.
    # NOTE on casing: SQLAlchemy's Enum(SomePyEnum, ...), with no
    # values_callable override, persists each member's *name*
    # (ScanStatus.PENDING -> 'PENDING'), not its .value ('pending') --
    # confirmed against the existing rows this migration runs on top of.
    # 'CANCELLING' (matching ScanStatus.CANCELLING.name) is therefore the
    # correct string to add, not the lowercase .value.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'CANCELLING'")

    op.add_column("scans", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scans",
        sa.Column("dispatch_attempts", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("scans", "dispatch_attempts")
    op.drop_column("scans", "dispatched_at")
    op.drop_column("scans", "cancel_requested_at")
    # NOT reversed: Postgres has no ALTER TYPE ... DROP VALUE. A scan
    # left in 'cancelling' by a downgrade would violate the (Python-side
    # only, as of this revision) ScanStatus enum, but no row can reach
    # that value without this revision's application code running in the
    # first place, so this is a documented, accepted limitation rather
    # than a bug -- consistent with how the baseline migration's own
    # downgrade() handles enum types (see its trailing comment).
