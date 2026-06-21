import os

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
    # Migrations are the schema source of truth. By default (PALISADE_AUTO_MIGRATE
    # unset/"1") startup upgrades to head, so sqlite dev, the smoke test, and the
    # single-process compose api all converge on the same schema with no manual
    # step. For multi-replica prod, run migrations as a one-shot pre-start step
    # (`python -m app.migrate`) and set PALISADE_AUTO_MIGRATE=0 so N booting
    # replicas don't race to migrate.
    if os.environ.get("PALISADE_AUTO_MIGRATE", "1").lower() in ("1", "true", "yes"):
        from .migrate import migrate

        migrate()
