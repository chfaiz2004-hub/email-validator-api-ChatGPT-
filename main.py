"""Email Validation API built with FastAPI.

Endpoints
---------
GET  /validate        Validate an email address.
POST /keys            Create a new API key (demo / self-service).
GET  /usage           Check how many requests the current key has used this month.
GET  /docs            Auto-generated Swagger UI (provided by FastAPI).
GET  /redoc           Alternative ReDoc documentation.
"""

import re
from contextlib import asynccontextmanager

import dns.resolver
from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel

from database import (
    FREE_TIER_LIMIT,
    create_api_key,
    get_monthly_usage,
    increment_usage,
    init_db,
    is_valid_key,
)

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(application: FastAPI):  # noqa: ARG001
    init_db()
    yield


app = FastAPI(
    title="Email Validator API",
    description=(
        "Validate email addresses by checking format and domain existence. "
        "Each API key is granted **100 free requests per calendar month**."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# RFC-5322 simplified pattern – catches the vast majority of real-world cases.
_EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


def _valid_format(email: str) -> bool:
    return bool(_EMAIL_REGEX.match(email))


def _domain_exists(email: str) -> bool:
    """Return True if the domain has at least one MX or A record."""
    try:
        domain = email.split("@", 1)[1]
    except IndexError:
        return False

    # Try MX first, fall back to A record.
    for record_type in ("MX", "A"):
        try:
            dns.resolver.resolve(domain, record_type, lifetime=5)
            return True
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
    return False


def _authenticate(api_key: str) -> None:
    """Validate *api_key* and enforce the monthly rate-limit.

    Raises HTTPException(401) for an unknown key and HTTPException(429) when
    the free-tier limit has been reached.
    """
    if not is_valid_key(api_key):
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_api_key",
                "message": "The API key provided is invalid or does not exist.",
            },
        )

    usage = get_monthly_usage(api_key)
    if usage >= FREE_TIER_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": (
                    f"You have reached the free-tier limit of "
                    f"{FREE_TIER_LIMIT} requests per month."
                ),
                "limit": FREE_TIER_LIMIT,
                "used": usage,
            },
        )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ValidationResult(BaseModel):
    email: str
    valid_format: bool
    domain_exists: bool
    status: str


class KeyCreatedResponse(BaseModel):
    api_key: str
    owner: str
    limit_per_month: int


class UsageResponse(BaseModel):
    api_key: str
    used_this_month: int
    limit_per_month: int
    remaining: int


class KeyRequest(BaseModel):
    owner: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get(
    "/validate",
    response_model=ValidationResult,
    summary="Validate an email address",
    tags=["Validation"],
)
def validate_email(
    email: str = Query(..., description="The email address to validate."),
    api_key: str = Query(..., description="Your API key."),
) -> ValidationResult:
    """Check whether *email* has a valid format and whether its domain exists.

    **status** will be one of:
    - `valid` – correct format **and** domain found
    - `invalid_format` – the address does not match email syntax rules
    - `domain_not_found` – correct format but the domain has no MX / A record
    """
    _authenticate(api_key)

    fmt_ok = _valid_format(email)

    if not fmt_ok:
        domain_ok = False
        status = "invalid_format"
    else:
        domain_ok = _domain_exists(email)
        status = "valid" if domain_ok else "domain_not_found"

    # Only count the request against the quota after successful authentication.
    increment_usage(api_key)

    return ValidationResult(
        email=email,
        valid_format=fmt_ok,
        domain_exists=domain_ok,
        status=status,
    )


@app.post(
    "/keys",
    response_model=KeyCreatedResponse,
    status_code=201,
    summary="Create a new API key",
    tags=["API Keys"],
)
def create_key(body: KeyRequest) -> KeyCreatedResponse:
    """Generate a new API key for the given *owner* name.

    The key is immediately usable and starts with **0 requests used**.
    """
    key = create_api_key(body.owner)
    return KeyCreatedResponse(
        api_key=key,
        owner=body.owner,
        limit_per_month=FREE_TIER_LIMIT,
    )


@app.get(
    "/usage",
    response_model=UsageResponse,
    summary="Check monthly usage for an API key",
    tags=["API Keys"],
)
def check_usage(
    api_key: str = Query(..., description="Your API key."),
) -> UsageResponse:
    """Return how many requests have been made with *api_key* this month."""
    if not is_valid_key(api_key):
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_api_key",
                "message": "The API key provided is invalid or does not exist.",
            },
        )

    used = get_monthly_usage(api_key)
    return UsageResponse(
        api_key=api_key,
        used_this_month=used,
        limit_per_month=FREE_TIER_LIMIT,
        remaining=max(0, FREE_TIER_LIMIT - used),
    )
