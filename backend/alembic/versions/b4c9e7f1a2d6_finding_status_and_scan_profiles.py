"""finding status workflow + scan profiles

1. `scan_findings.status`: new `finding_status` enum
   (OPEN/IN_REVIEW/RESOLVED/FALSE_POSITIVE), default OPEN. Existing
   rows become OPEN through the server default.
2. `scan_profiles` table, seeded with three built-in profiles
   (Recon, Passive Assessment, Authorized Active Assessment).
   `owner_id IS NULL` marks a built-in profile.

Both changes are additive.

Revision ID: b4c9e7f1a2d6
Revises: a7c4e1f9d3b2
Create Date: 2026-10-20 00:00:00.000000
"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b4c9e7f1a2d6"
down_revision: Union[str, Sequence[str], None] = "a7c4e1f9d3b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FINDING_STATUS_VALUES = ("OPEN", "IN_REVIEW", "RESOLVED", "FALSE_POSITIVE")

scan_profiles = sa.table(
    "scan_profiles",
    sa.column("id", sa.Uuid()),
    sa.column("owner_id", sa.Uuid()),
    sa.column("name", sa.String()),
    sa.column("description", sa.String()),
    sa.column("module_slugs", sa.JSON()),
    sa.column("active_testing_confirmed_default", sa.Boolean()),
    sa.column("is_builtin", sa.Boolean()),
)

_BUILTIN_PROFILES = [
    dict(
        name="Recon",
        description="Passive reconnaissance only -- the 'recon' and 'advanced_recon' modules. "
        "No vulnerability assessment, no active testing.",
        module_slugs=["recon", "advanced_recon"],
        active_testing_confirmed_default=False,
    ),
    dict(
        name="Passive Assessment",
        description="Full passive assessment -- reconnaissance plus the passive "
        "'web_vuln_assessment' module (security headers, cookies, CORS, TLS, "
        "information disclosure, ...). Never sends a crafted test payload to the target.",
        module_slugs=["recon", "advanced_recon", "web_vuln_assessment"],
        active_testing_confirmed_default=False,
    ),
    dict(
        name="Authorized Active Assessment",
        description="Everything in Passive Assessment plus 'active_web_testing' -- sends real "
        "test requests (reflected-XSS markers, differential SQLi probes, HTTP parameter "
        "testing, active API-security checks) to an explicitly authorized lab target. "
        "Selecting this profile still requires every existing active_web_testing gate: the "
        "module must be enabled, the target must be in the lab allowlist, and the scan "
        "request must still carry active_testing_confirmed=true.",
        module_slugs=["recon", "advanced_recon", "web_vuln_assessment", "active_web_testing"],
        active_testing_confirmed_default=True,
    ),
]


def upgrade() -> None:
    bind = op.get_bind()

    # --- 1. scan_findings.status -----------------------------------
    finding_status_enum = sa.Enum(*_FINDING_STATUS_VALUES, name="finding_status")
    finding_status_enum.create(bind, checkfirst=True)
    op.add_column(
        "scan_findings",
        sa.Column(
            "status",
            sa.Enum(*_FINDING_STATUS_VALUES, name="finding_status", create_type=False),
            nullable=False,
            server_default="OPEN",
        ),
    )
    op.create_index(
        op.f("ix_scan_findings_status"), "scan_findings", ["status"], unique=False
    )

    # --- 2. scan_profiles --------------------------------------------
    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("module_slugs", sa.JSON(), nullable=False),
        sa.Column("active_testing_confirmed_default", sa.Boolean(), nullable=False),
        sa.Column("is_builtin", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_profiles_owner_id"), "scan_profiles", ["owner_id"], unique=False)
    op.create_index(op.f("ix_scan_profiles_is_builtin"), "scan_profiles", ["is_builtin"], unique=False)

    for profile in _BUILTIN_PROFILES:
        values = dict(
            id=uuid.uuid4(),
            owner_id=None,
            is_builtin=True,
            **profile,
        )
        if bind.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            # No unique constraint to key an ON CONFLICT off of here
            # (two different users could otherwise never both be
            # allowed a profile named "Recon"), so idempotency for the
            # three seeded rows specifically is instead enforced by
            # name-checking first -- see the guard below.
            stmt = pg_insert(scan_profiles).values(**values)
        else:  # pragma: no cover - this migration only ever runs against Postgres
            stmt = sa.insert(scan_profiles).values(**values)

        already_seeded = bind.execute(
            sa.select(scan_profiles.c.id).where(
                scan_profiles.c.is_builtin.is_(True), scan_profiles.c.name == profile["name"]
            )
        ).first()
        if already_seeded is None:
            bind.execute(stmt)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_profiles_is_builtin"), table_name="scan_profiles")
    op.drop_index(op.f("ix_scan_profiles_owner_id"), table_name="scan_profiles")
    op.drop_table("scan_profiles")

    op.drop_index(op.f("ix_scan_findings_status"), table_name="scan_findings")
    op.drop_column("scan_findings", "status")
    bind = op.get_bind()
    sa.Enum(name="finding_status").drop(bind, checkfirst=True)
