"""PhishScope Backend - FastAPI entrypoint."""
import logging

from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api import alerts, analyze, auth, misc
from app.core.config import settings
from app.core.database import Base, engine
from app.core.logging import setup_logging

setup_logging()
log = logging.getLogger("phishscope")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PhishScope API", version="0.1.0",
              description="Cybersecurity Analysis & Automation - One Link. Full Investigation.")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)
app.include_router(auth.users_router)
app.include_router(analyze.router)
app.include_router(misc.router)
app.include_router(alerts.router)
app.include_router(alerts.public_router)


@app.on_event("startup")
def startup() -> None:
    # على SQLite (dev) بنبني الجداول من الـ models.
    # على PostgreSQL الـ schema.sql بيتطبق من docker-entrypoint-initdb.d.
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(engine)
        log.info("SQLite dev database ready (models.create_all)")
    else:
        # جداول التنبيهات الجديدة فقط (additive، checkfirst): من غير لمس الجداول الموجودة
        from app import models as m
        Base.metadata.create_all(engine, tables=[
            m.AlertPrefs.__table__, m.Alert.__table__, m.TelegramLinkCode.__table__])
    log.info("PhishScope backend started. Docs: /docs")


# Request Limits (متطلب 12): rate limiting على endpoint الفحص
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# تطبيق الـ rate limit على analyze عبر decorator بعد التعريف
analyze.analyze = limiter.limit(settings.rate_limit_analyze)(analyze.analyze)


# تقديم الموقع الثابت same-origin — آخر حاجة خالص عشان /api والـ docs ميتغطّوش
from fastapi.staticfiles import StaticFiles
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
