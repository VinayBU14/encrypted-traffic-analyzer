"""Spectra FastAPI application entry point."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routers import alerts, entities, flows, health

app = FastAPI(
    title="Spectra — Encrypted Traffic Analyzer",
    description="AI-based detection of malicious activity in encrypted network traffic.",
    version="1.0.0",
)

# Allow Streamlit dashboard to call the API
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


@app.get("/")
def root() -> dict:
    """Root endpoint — returns service info."""
    return {
        "service": "Spectra Encrypted Traffic Analyzer",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": ["/health", "/flows", "/alerts", "/entities"],
    }
