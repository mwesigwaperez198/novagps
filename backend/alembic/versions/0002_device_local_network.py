"""Add local network context columns (local_ip, carrier) to devices.

Reports now carry the device-side network identity alongside the
server-observed public IP.

Revision ID: 0002_device_local_network
Revises: 0001_initial
Create Date: 2026-09-08
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_device_local_network"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("local_ip", sa.String(length=45), nullable=True))
    op.add_column("devices", sa.Column("carrier", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "carrier")
    op.drop_column("devices", "local_ip")