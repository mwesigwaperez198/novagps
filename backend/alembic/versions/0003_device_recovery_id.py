"""Add devices.recovery_id (generated once at device registration).

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-09
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("recovery_id", sa.String(length=32), nullable=True),
    )
    op.create_index("ix_devices_recovery_id", "devices", ["recovery_id"])


def downgrade() -> None:
    op.drop_index("ix_devices_recovery_id", table_name="devices")
    op.drop_column("devices", "recovery_id")