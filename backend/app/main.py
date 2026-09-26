from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from collections import defaultdict
from typing import Annotated

import httpx
from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import Boolean, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

logger = logging.getLogger("securegate")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_env: str = "development"
    database_url: str = "sqlite:///./securegate.db"
    cors_origins: str = "http://localhost:4173"
    hibp_api_url: str = "https://api.pwnedpasswords.com/range"
    hibp_timeout_seconds: float = 5
    admin_token: str = "change-me-in-development"
    rate_limit_per_minute: int = 30

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
password_hasher = PasswordHasher()


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    verifier_hash: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


Base.metadata.create_all(engine)


class PrefixRequest(BaseModel):
    prefix: str = Field(min_length=5, max_length=5)

    @field_validator("prefix")
    @classmethod
    def uppercase_hex(cls, value: str) -> str:
        value = value.upper()
        if not re.fullmatch(r"[0-9A-F]{5}", value):
            raise ValueError("prefix must be five hexadecimal characters")
        return value


class AccountRequest(BaseModel):
    email: EmailStr
    verifier: str = Field(min_length=32, max_length=128)

    @field_validator("verifier")
    @classmethod
    def verifier_is_hex(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]+", value):
            raise ValueError("verifier must be hexadecimal")
        return value


class SuffixMatch(BaseModel):
    suffix: str
    count: int


class RateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        self.events[key] = [event for event in self.events[key] if now - event < 60]
        if len(self.events[key]) >= settings.rate_limit_per_minute:
            return False
        self.events[key].append(now)
        return True


limiter = RateLimiter()
app = FastAPI(title="SecureGate API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Demo-Admin"],
)


def rate_limit(request: Request) -> None:
    if not limiter.allow(request.client.host if request.client else "unknown"):
        raise HTTPException(status_code=429, detail="Too many requests; try again shortly")


def parse_hibp_response(text: str) -> list[SuffixMatch]:
    matches: list[SuffixMatch] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        suffix, count = line.strip().split(":", 1)
        if re.fullmatch(r"[0-9A-F]{35}", suffix.upper()) and count.isdigit():
            matches.append(SuffixMatch(suffix=suffix.upper(), count=int(count)))
    return matches


async def fetch_range(prefix: str) -> list[SuffixMatch]:
    # The prefix is the only password-derived value crossing this boundary.
    async with httpx.AsyncClient(timeout=settings.hibp_timeout_seconds) as client:
        response = await client.get(
            f"{settings.hibp_api_url}/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "SecureGate-Demo/1.0"},
        )
        response.raise_for_status()
        return parse_hibp_response(response.text)


@app.get("/health")
def health() -> dict[str, str]:
    try:
        with SessionLocal() as db:
            db.execute(select(1))
        return {"status": "ok", "database": "ok"}
    except Exception:
        logger.exception("health database check failed")
        raise HTTPException(status_code=503, detail="service unavailable")


@app.post("/api/password/check", dependencies=[Depends(rate_limit)])
async def password_check(payload: PrefixRequest) -> dict[str, object]:
    try:
        return {"source": "hibp", "suffixes": await fetch_range(payload.prefix)}
    except (httpx.HTTPError, ValueError):
        logger.warning("HIBP range lookup unavailable")
        raise HTTPException(status_code=503, detail="Password safety service unavailable")


def save_account(payload: AccountRequest) -> None:
    with SessionLocal() as db:
        existing = db.scalar(select(Account).where(Account.email == str(payload.email).lower()))
        verifier_hash = password_hasher.hash(payload.verifier)
        if existing:
            existing.verifier_hash = verifier_hash
        else:
            db.add(Account(email=str(payload.email).lower(), verifier_hash=verifier_hash))
        db.commit()


@app.post("/api/accounts/signup", dependencies=[Depends(rate_limit)])
def signup(payload: AccountRequest) -> dict[str, str]:
    save_account(payload)
    return {"status": "created", "message": "Demo account created"}


@app.post("/api/accounts/reset", dependencies=[Depends(rate_limit)])
def reset(payload: AccountRequest) -> dict[str, str]:
    save_account(payload)
    return {"status": "accepted", "message": "If the account exists, reset instructions are available"}


@app.get("/api/admin/metrics")
def metrics(x_demo_admin: Annotated[str | None, Header()] = None) -> dict[str, object]:
    if not x_demo_admin or x_demo_admin != settings.admin_token:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {
        "synthetic": True,
        "period": "last_24_hours",
        "checks": 1842,
        "breach_rejections": 219,
        "hibp_unavailable": 3,
        "rate_limited_requests": 17,
        "note": "Synthetic demo data; not production telemetry",
    }


@app.middleware("http")
async def redacted_request_log(request: Request, call_next):
    response = await call_next(request)
    logger.info("request method=%s path=%s status=%s", request.method, request.url.path, response.status_code)
    return response
