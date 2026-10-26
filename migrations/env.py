"""Configure Alembic's online/offline SQLite migration environments."""

from alembic import context

from src.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline():
    """Configure Alembic SQL rendering without opening a database connection."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run revisions through an injected connection or the shared SQLite engine."""
    connection = config.attributes.get("connection")
    close_connection = connection is None
    if connection is None:
        from src.core.db import engine

        connection = engine.connect()

    try:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    finally:
        if close_connection:
            connection.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
