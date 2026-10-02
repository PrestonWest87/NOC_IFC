"""Track invalidated registration invitations without deleting history.

Revision ID: 20261002_0002
Revises: 20261002_0001
Create Date: 2026-10-02
"""
from alembic import op
from sqlalchemy import Column, DateTime, inspect


revision = "20261002_0002"
down_revision = "20261002_0001"
branch_labels = None
depends_on = None


def upgrade():
    if "revoked_at" not in {column["name"] for column in inspect(op.get_bind()).get_columns("registration_invites")}:
        op.add_column("registration_invites", Column("revoked_at", DateTime(), nullable=True))


def downgrade():
    if "revoked_at" in {column["name"] for column in inspect(op.get_bind()).get_columns("registration_invites")}:
        op.drop_column("registration_invites", "revoked_at")
