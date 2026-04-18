"""Spectra FastAPI application entry point."""
from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routers import alerts, entities, flows, health
from src.api.routers.capture import router as capture_router

log = logging.getLogger("spectra.api")

# Path to spectra.db — override with SPECTRA_DB env var if needed
DB_PATH = os.getenv("SPECTRA_DB", "data/spectra.db")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: ensure the database schema exists before the first request.
    This is the fix for 'no such table: alerts' on cold start.
    """
    from init_db import init_db
    log.info("SPECTRA startup — initialising database at %s", DB_PATH)
    init_db(DB_PATH)
    log.info("Database ready.")
    yield
    log.info("SPECTRA shutdown.")


app = FastAPI(
    title="Spectra — Encrypted Traffic Analyzer",
    description="AI-based detection of malicious activity in encrypted network traffic.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health.router)
app.include_router(flows.router)
app.include_router(alerts.router)
app.include_router(entities.router)
app.include_router(capture_router)   # /capture/*


@app.get("/")
def root() -> dict:
    return {
        "service": "Spectra Encrypted Traffic Analyzer",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": ["/health", "/flows", "/alerts", "/entities", "/capture"],
    }