"""FastAPI application entry point for the AI Security Triage Service."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from routes.triage import router as triage_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.patches_dir.mkdir(parents=True, exist_ok=True)
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Deterministic security finding pipeline with LLM-assisted "
            "explanation, prioritization enrichment, and draft remediation."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(triage_router)

    @app.get("/")
    async def root():
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "endpoints": {
                "health": "/health",
                "triage": "POST /triage",
                "triage_file": "POST /triage/file",
            },
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
