from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect

from .config import DATABASE_URL
from .db import engine


def migrate() -> None:
    """Bring the database schema to head. Idempotent; safe to re-run.

    Ops should run this ONCE as a pre-start step (e.g. `python -m app.migrate`)
    before launching app replicas, so N booting processes don't race to migrate.
    """
    root = Path(__file__).resolve().parents[1]  # control-plane/
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)

    # A DB created before alembic stamping has the tables but no version row;
    # `upgrade head` would re-run 0001 and crash on "table org already exists".
    # Detect that case and stamp instead so we adopt the existing schema.
    with engine.connect() as conn:
        current = MigrationContext.configure(conn).get_current_revision()
        has_schema = inspect(conn).has_table("org")
    if has_schema and current is None:
        command.stamp(cfg, "head")
        return
    command.upgrade(cfg, "head")


if __name__ == "__main__":
    migrate()
