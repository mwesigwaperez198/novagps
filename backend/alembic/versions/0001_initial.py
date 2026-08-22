"""Initial consent-first GPS tracking schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-30
"""

from alembic import op
import geoalchemy2
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


device_type = postgresql.ENUM(
    "vehicle",
    "motorcycle",
    "phone",
    "laptop",
    "other",
    name="device_type",
    create_type=False,
)
consent_status = postgresql.ENUM(
    "active",
    "revoked",
    "deleted",
    name="consent_status",
    create_type=False,
)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS postgis")
    # Create ENUM types if they don't exist (compatible with PostgreSQL 18)
    op.execute(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_type') THEN CREATE TYPE device_type AS ENUM ('vehicle', 'motorcycle', 'phone', 'laptop', 'other'); END IF; END $$;"
    )
    op.execute(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'consent_status') THEN CREATE TYPE consent_status AS ENUM ('active', 'revoked', 'deleted'); END IF; END $$;"
    )

    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("phone", sa.String(length=64), nullable=False),
        sa.Column("identifier", sa.String(length=160), nullable=False),
        sa.Column("serial", sa.String(length=160), nullable=True),
        sa.Column("device_type", device_type, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_devices_email", "devices", ["email"])
    op.create_index("ix_devices_identifier", "devices", ["identifier"], unique=True)

    op.create_table(
        "locations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("latitude", sa.Float(), nullable=False),
        sa.Column("longitude", sa.Float(), nullable=False),
        sa.Column("altitude", sa.Float(), nullable=True),
        sa.Column("speed", sa.Float(), nullable=True),
        sa.Column("heading", sa.Float(), nullable=True),
        sa.Column("accuracy", sa.Float(), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="http"),
        sa.Column("geom", geoalchemy2.Geometry(geometry_type="POINT", srid=4326, spatial_index=False), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("raw_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_index("ix_locations_device_id", "locations", ["device_id"])
    op.create_index("ix_locations_device_recorded_at", "locations", ["device_id", "recorded_at"])
    op.create_index("ix_locations_geom", "locations", ["geom"], postgresql_using="gist")
    op.create_index("ix_locations_received_at", "locations", ["received_at"])

    op.create_table(
        "consents",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_email", sa.String(length=320), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("status", consent_status, nullable=False, server_default="active"),
        sa.Column("consented_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("proof_hash", sa.String(length=128), nullable=True),
    )
    op.create_index("ix_consents_device_id", "consents", ["device_id"])
    op.create_index("ix_consents_device_status", "consents", ["device_id", "status"])
    op.create_index("ix_consents_user_email", "consents", ["user_email"])

    op.create_table(
        "imported_users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("phone", sa.String(length=64), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("source", "email", name="uq_imported_users_source_email"),
    )
    op.create_index("ix_imported_users_email", "imported_users", ["email"])

    op.create_table(
        "broadcast_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("channel", sa.String(length=120), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("scope", sa.String(length=80), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_broadcast_sessions_channel", "broadcast_sessions", ["channel"])
    op.create_index("ix_broadcast_sessions_token_hash", "broadcast_sessions", ["token_hash"], unique=True)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("actor", sa.String(length=160), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("command_id", sa.String(length=120), nullable=True),
        sa.Column("args_hash", sa.String(length=128), nullable=True),
        sa.Column("output_hash", sa.String(length=128), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("broadcast_sessions")
    op.drop_table("imported_users")
    op.drop_table("consents")
    op.drop_table("locations")
    op.drop_table("devices")
    consent_status.drop(op.get_bind(), checkfirst=True)
    device_type.drop(op.get_bind(), checkfirst=True)
