from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .catalog import seed_detections
from .config import cors_origins
from .db import SessionLocal, init_db
from .models import DEMO_ORG_ID, Org
from .routers import agents, catalog, detections, read, scans


def _bootstrap() -> None:
    init_db()
    db = SessionLocal()
    try:
        # Single hardcoded demo org for the scaffold.
        if db.get(Org, DEMO_ORG_ID) is None:
            db.add(Org(id=DEMO_ORG_ID, name="demo", plan="free"))
            db.commit()
        seed_detections(db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _bootstrap()
    yield


app = FastAPI(title="Palisade Control Plane", version="0.1.0", lifespan=lifespan)

# CORS open for localhost so the existing web/ prototype can point at it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(agents.router)
app.include_router(catalog.router)
app.include_router(detections.router)
app.include_router(scans.router)
app.include_router(read.router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
