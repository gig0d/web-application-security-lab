"""Initial relational schema, deliberately explicit and stable."""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(80), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("display_name", sa.String(80), nullable=False),
        sa.Column("session_version", sa.Integer(), nullable=False),
    )
    op.create_table(
        "tickets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("assignee_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
    )
    op.create_table(
        "comments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("tickets.id"), nullable=False),
        sa.Column("author_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("private", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("tickets.id"), nullable=False),
        sa.Column("filename", sa.String(160), nullable=False),
        sa.Column("storage_key", sa.String(80), nullable=False, unique=True),
        sa.Column("content", sa.LargeBinary(), nullable=False),
    )
    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("csrf", sa.String(100), nullable=False),
        sa.Column("expires", sa.Float(), nullable=False),
        sa.Column("user_version", sa.Integer(), nullable=False),
    )
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("at", sa.Float(), nullable=False),
    )
    op.create_index("ix_login_attempts_key", "login_attempts", ["key"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("at", sa.Float(), nullable=False),
        sa.Column("event", sa.String(80), nullable=False),
        sa.Column("actor_id", sa.Integer()),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("resource", sa.String(100), nullable=False),
        sa.Column("request_id", sa.String(40), nullable=False),
    )


def downgrade() -> None:
    for table in (
        "audit_events",
        "login_attempts",
        "sessions",
        "attachments",
        "comments",
        "tickets",
        "users",
    ):
        op.drop_table(table)
