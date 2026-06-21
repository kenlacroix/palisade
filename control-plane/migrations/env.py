from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

# Make `app` importable when alembic is invoked via the CLI.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import DATABASE_URL  # noqa: E402
from app.db import Base  # noqa: E402
from app import models  # noqa: F401,E402  (registers tables on Base.metadata)

config = context.config
config.set_main_option("sqlalchemy.url", DATABASE_URL)

target_metadata = Base.metadata

_IS_SQLITE = DATABASE_URL.startswith("sqlite")


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=_IS_SQLITE,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connect_args = {"check_same_thread": False} if _IS_SQLITE else {}
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=connect_args,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=_IS_SQLITE,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
