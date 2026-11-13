"""SOC API application.

Run (after setting IDPS_SOC_JWT_SECRET and creating an admin with `python -m soc.api create-user`):
    uvicorn soc.api.main:app --reload

Run a single process (no --workers): the live alert feed is an in-process broadcaster.
See docs/soc.md for settings, endpoints and the auth model.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from soc.api import auth
from soc.api.broadcast import AlertBroadcaster
from soc.api.db import init_db, make_engine, make_session_factory
from soc.api.geo import GeoLocator
from soc.api.routes import (
    actions,
    admin,
    alerts,
    assistant,
    blocks,
    cases,
    geo,
    live,
    metrics,
    sensors,
)
from soc.api.security import LoginThrottle
from soc.api.settings import SocSettings, get_settings


def create_app(settings: SocSettings | None = None) -> FastAPI:
    settings = settings or get_settings()
    # The interactive docs are unauthenticated, so they are off unless IDPS_SOC_ENABLE_DOCS=true.
    docs = {} if settings.enable_docs else {"docs_url": None, "redoc_url": None,
                                           "openapi_url": None}
    app = FastAPI(title="IDPS SOC API", **docs)
    app.state.settings = settings
    engine = make_engine(settings.database_url)
    init_db(engine)
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.geo = GeoLocator(settings.geoip_db, settings.geo_demo)
    # The assistant is off (None) when no Anthropic credentials are configured.
    from soc.assistant.llm import make_llm

    app.state.assistant_llm = make_llm(settings.assistant_model, settings.assistant_effort)
    app.state.assistant_limiter = None
    app.state.assistant_slots = None
    app.state.broadcaster = AlertBroadcaster(settings.ws_max_connections, settings.ws_queue_size)
    app.state.login_throttle = LoginThrottle(
        settings.login_max_failures, settings.login_max_failures_per_ip,
        settings.login_lockout_minutes * 60)

    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"])

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default echoes each bad input back. That fails to serialise for NaN
        # (a 500) and would send a rejected 16 KB explanation straight back, so leave it out.
        detail = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]}
                  for e in exc.errors()]
        return JSONResponse({"detail": detail}, status_code=422)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth.router)
    for module in (alerts, live, blocks, actions, cases, metrics, geo, assistant, admin, sensors):
        app.include_router(module.router)
    return app


def __getattr__(name: str):
    # `uvicorn soc.api.main:app` builds the app on first access, so importing this module
    # (e.g. in tests) doesn't require IDPS_SOC_JWT_SECRET to be set.
    if name == "app":
        globals()["app"] = application = create_app()
        return application
    raise AttributeError(name)
