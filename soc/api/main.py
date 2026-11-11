"""Minimal SOC API application."""

from fastapi import FastAPI

app = FastAPI(title="IDPS SOC API")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
