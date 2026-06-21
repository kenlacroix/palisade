from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # Migrations are the schema source of truth. Startup upgrades to head, so
    # sqlite dev, the smoke test, and the compose api all converge on the same
    # schema (idempotent — re-running is a no-op).
    # TODO(prod): for multi-replica deploys, run `alembic upgrade head` as a
    #   one-shot step before starting the app instead of at startup, and add
    #   Postgres Row-Level Security keyed on org_id (SPEC section 6).
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect

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
