from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from . import config, mtls, observability, preflight
from .catalog import seed_detections
from .config import cors_origins
from .db import SessionLocal, init_db
from .models import DEMO_ORG_ID, EnrollToken, Membership, Org, User
from .queue import close_pool, init_pool
from .routers import agents, alerts, auth_routes, catalog, detections, members, read, scans
from .tenancy import hash_password


def _bootstrap() -> None:
    # Fail closed on insecure defaults in production (raises before we serve);
    # only warns on the SQLite dev/test path and the public demo.
    preflight.enforce()
    init_db()
    db = SessionLocal()
    try:
        # Seed the demo org so the demo logs in with one click; real tenants are
        # created via signup/invite flows on top of this same shape.
        if db.get(Org, DEMO_ORG_ID) is None:
            db.add(Org(id=DEMO_ORG_ID, name="demo", plan="free"))
            db.commit()

        demo = db.execute(
            select(User).where(User.email == config.DEMO_USER_EMAIL)
        ).scalar_one_or_none()
        if demo is None:
            demo = User(
                email=config.DEMO_USER_EMAIL,
                name="Demo",
                password_hash=hash_password(config.DEMO_USER_PASSWORD),
            )
            db.add(demo)
            db.flush()
        if db.execute(
            select(Membership).where(
                Membership.user_id == demo.id, Membership.org_id == DEMO_ORG_ID
            )
        ).scalar_one_or_none() is None:
            db.add(Membership(user_id=demo.id, org_id=DEMO_ORG_ID, role="owner"))

        # Seed single-use enroll tokens from env into the demo org.
        for tok in config.enroll_tokens():
            if db.get(EnrollToken, tok) is None:
                db.add(EnrollToken(token=tok, org_id=DEMO_ORG_ID, label="seed"))
        db.commit()

        # Ensure the platform-wide agent CA exists on first boot.
        mtls.ensure_ca(db)

        seed_detections(db)

        # Populate the demo org with a believable dataset so a fresh deploy looks
        # live. Idempotent; references the just-seeded detection catalog.
        if config.seed_demo():
            from .seed import seed_demo

            seed_demo(db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _bootstrap()
    await init_pool()
    try:
        yield
    finally:
        await close_pool()


app = FastAPI(title="Palisade Control Plane", version="0.1.0", lifespan=lifespan)

# Structured JSON logging, request-id + per-request Prometheus metrics, /metrics.
observability.install(app)

# CORS open for localhost so the existing web/ prototype can point at it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(agents.router)
app.include_router(catalog.router)
app.include_router(detections.router)
app.include_router(scans.router)
app.include_router(read.router)
app.include_router(alerts.router)
app.include_router(members.router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
