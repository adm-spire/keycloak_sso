"""
SSO-lab protected resource server (the "API").

This is NOT a browser-facing app.  It accepts an OAuth 2.0 access token as a
Bearer token, validates it locally, and authorizes the request.

The API is deliberately independent from the identity provider:

  * It learns the JWKS URL (public signing keys) from OIDC discovery.
  * It verifies the JWT signature itself with those public keys.
  * It checks the expected issuer and audience itself.
  * It never calls Keycloak to introspect the token (stateless validation).

That is what lets thousands of APIs validate tokens without a round trip to the
authorization server on every request.  The trade-off is that a revoked token
remains valid until it expires, which is why access tokens are short-lived
(5 minutes in this lab).

Run it with:

    uvicorn api:app --port 7000

Try it with:

    curl -i http://localhost:7000/public
    curl -i http://localhost:7000/notes
    curl -i -H "Authorization: Bearer $TOKEN" http://localhost:7000/notes
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
)
logger = logging.getLogger("notes-api")

ISSUER = os.environ.get("ISSUER", "http://localhost:8080/realms/demo")
AUDIENCE = os.environ.get("AUDIENCE", "notes-api")
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
REQUIRED_SCOPE = "notes.read"

# One clock-skew allowance for `exp`/`iat`/`nbf`.  A small leeway avoids false
# rejections when the API host clock is a few seconds behind Keycloak.  Too much
# leeway extends the life of an expired token, so keep it small.
CLOCK_LEEWAY_SECONDS = 30

app = FastAPI(
    title="SSO Lab Notes API",
    description="Protected resource server validating Keycloak access tokens.",
)

# auto_error=False so WE choose the 401 response body/header.  FastAPI's default
# error for a missing bearer token is a 403, which is the wrong semantic here.
bearer_scheme = HTTPBearer(
    auto_error=False,
    description="Keycloak access token (audience: notes-api)",
)

# ---------------------------------------------------------------------------
# Discovery + JWKS (cached)
# ---------------------------------------------------------------------------

_discovery_metadata: dict[str, Any] | None = None
_jwks_client: PyJWKClient | None = None


def get_discovery_metadata() -> dict[str, Any]:
    """Fetch and cache {ISSUER}/.well-known/openid-configuration."""

    global _discovery_metadata
    if _discovery_metadata is None:
        logger.info("Loading OIDC discovery document from %s", DISCOVERY_URL)
        try:
            response = httpx.get(DISCOVERY_URL, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Could not load discovery document: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="Identity provider discovery endpoint is unreachable.",
            ) from exc
        _discovery_metadata = response.json()
        logger.info(
            "Discovery loaded; issuer=%s jwks_uri=%s",
            _discovery_metadata.get("issuer"),
            _discovery_metadata.get("jwks_uri"),
        )

        # Defense in depth: the discovery document must describe the issuer we
        # expect.  Otherwise a misconfigured URL could make us trust the wrong
        # realm's keys and issuer.
        if _discovery_metadata.get("issuer") != ISSUER:
            logger.error(
                "Discovery issuer mismatch: configured %s, received %s",
                ISSUER,
                _discovery_metadata.get("issuer"),
            )
            raise HTTPException(
                status_code=503,
                detail="Identity provider issuer does not match configuration.",
            )
    return _discovery_metadata


def get_jwks_client() -> PyJWKClient:
    """Build a key client for the realm's public signing keys.

    PyJWKClient fetches the JWKS once and caches the keys; if a token references
    an unknown `kid` (for example after Keycloak rotates its signing key), the
    client re-fetches the key set.
    """

    global _jwks_client
    if _jwks_client is None:
        metadata = get_discovery_metadata()
        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise HTTPException(
                status_code=503,
                detail="Discovery document has no jwks_uri.",
            )
        logger.info("Using JWKS endpoint %s", jwks_uri)
        _jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
    return _jwks_client


# ---------------------------------------------------------------------------
# Error helpers: 401 vs 403
# ---------------------------------------------------------------------------
#
# 401 Unauthorized = "I could not authenticate you."
#   The token is missing, malformed, expired, has a bad signature, came from the
#   wrong issuer, or was minted for a different API (wrong audience).  The client
#   may be able to fix this by obtaining a new/better token.
#
# 403 Forbidden = "I know who you are, but you may not do this."
#   The token is valid, but it lacks the required scope or role.  Obtaining
#   another token with the same permissions will not help.
#
# Both carry a WWW-Authenticate header as required by RFC 6750.  The `error`
# code tells OAuth-aware clients what went wrong.


def unauthorized(description: str) -> HTTPException:
    logger.warning("401 invalid_token: %s", description)
    return HTTPException(
        status_code=401,
        detail={"error": "invalid_token", "error_description": description},
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def forbidden(description: str) -> HTTPException:
    logger.warning("403 insufficient_scope: %s", description)
    return HTTPException(
        status_code=403,
        detail={"error": "insufficient_scope", "error_description": description},
        headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
    )


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


def validate_access_token(raw_token: str) -> dict[str, Any]:
    """Verify and decode a Keycloak access token, or raise a 401.

    Security checks, and why each one exists:

      * `RS256` only.  Accepting `alg: none` or HMAC algorithms would let an
        attacker forge tokens or use the public key as an HMAC secret.
      * Signature from the realm's JWKS.  Proves Keycloak issued the token and
        that its claims were not modified in transit or by the client.
      * `iss` must be exactly our realm's issuer.  Prevents tokens from another
        realm/IdP being accepted by this API.
      * `aud` must contain "notes-api".  Prevents a token issued for a different
        service (even in the same realm) from being replayed against this API.
      * `exp` must be in the future (plus a small leeway).  Limits the damage
        from a stolen token; access tokens are short-lived for this reason.
      * `iat` must be present and sane.  Rejects tokens with an impossible
        issuance time.
      * Required claims are enforced explicitly, so a token missing `exp`,
        `iat`, `iss`, `aud` or `sub` is rejected instead of silently accepted.
    """

    # 1. Find the correct public key.  Keycloak puts the key id in the JWT
    #    header (`kid`); PyJWKClient chooses the matching key from the JWKS.
    try:
        signing_key = get_jwks_client().get_signing_key_from_jwt(raw_token)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - translate to a clean 401
        raise unauthorized(
            f"could not resolve a signing key / malformed JWT header "
            f"({type(exc).__name__}: {exc})"
        ) from exc

    try:
        claims = jwt.decode(
            raw_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUDIENCE,             # rejects tokens for other APIs
            issuer=ISSUER,                 # rejects tokens from other realms
            leeway=CLOCK_LEEWAY_SECONDS,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise unauthorized("token expired (exp claim is in the past)") from exc
    except jwt.InvalidAudienceError as exc:
        raise unauthorized(
            f"bad audience: token aud does not contain {AUDIENCE!r}"
        ) from exc
    except jwt.InvalidIssuerError as exc:
        raise unauthorized(
            f"bad issuer: token iss is not {ISSUER!r}"
        ) from exc
    except jwt.InvalidSignatureError as exc:
        raise unauthorized(
            "bad signature: token was not signed by this realm's key"
        ) from exc
    except jwt.InvalidAlgorithmError as exc:
        raise unauthorized(
            "unexpected signing algorithm (only RS256 is accepted)"
        ) from exc
    except jwt.ImmatureSignatureError as exc:
        raise unauthorized("token is not valid yet (nbf/iat in the future)") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise unauthorized(f"missing required claim: {exc}") from exc
    except jwt.InvalidTokenError as exc:
        raise unauthorized(f"invalid token: {exc}") from exc

    logger.info(
        "Accepted token: sub=%s username=%s scopes=%r roles=%r",
        claims.get("sub"),
        claims.get("preferred_username"),
        claims.get("scope"),
        claims.get("realm_access", {}).get("roles", []),
    )
    return claims


# ---------------------------------------------------------------------------
# Reusable FastAPI dependencies
# ---------------------------------------------------------------------------


def get_current_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any]:
    """Dependency: authenticate the request and return the validated claims."""

    if credentials is None:
        raise unauthorized(
            "missing bearer token: send 'Authorization: Bearer <access_token>'"
        )
    if credentials.scheme.lower() != "bearer":
        raise unauthorized(
            f"unsupported authorization scheme {credentials.scheme!r}; use Bearer"
        )
    return validate_access_token(credentials.credentials)


def require_scope(required_scope: str) -> Callable[..., dict[str, Any]]:
    """Dependency factory: require a scope *inside* a valid token.

    Scopes are coarse-grained permissions (here: "may read notes").  They are
    granted to the client at the authorization request and copied into the
    access token's `scope` claim.  Missing scope on a valid token => 403.
    """

    def dependency(
        claims: dict[str, Any] = Depends(get_current_claims),
    ) -> dict[str, Any]:
        granted = str(claims.get("scope", "")).split()
        if required_scope not in granted:
            raise forbidden(
                f"token is valid but lacks required scope {required_scope!r} "
                f"(granted: {' '.join(granted) or 'none'})"
            )
        return claims

    return dependency


def require_role(required_role: str) -> Callable[..., dict[str, Any]]:
    """Dependency factory: require a realm role inside a valid token.

    Roles describe who the user is (admin/viewer) and are added by Keycloak to
    the access token as realm_access.roles.  Missing role on a valid token => 403.
    """

    def dependency(
        claims: dict[str, Any] = Depends(get_current_claims),
    ) -> dict[str, Any]:
        roles = claims.get("realm_access", {}).get("roles", [])
        if required_role not in roles:
            raise forbidden(
                f"token is valid but lacks required realm role "
                f"{required_role!r} (granted: {', '.join(roles) or 'none'})"
            )
        return claims

    return dependency


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/")
def index() -> dict[str, Any]:
    """Tiny discovery page for humans poking at the API."""

    return {
        "service": "notes-api",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "endpoints": {
            "/public": "no token required",
            "/notes": f"requires scope {REQUIRED_SCOPE}",
            "/admin": "requires realm role admin",
        },
    }


@app.get("/public")
def public() -> dict[str, Any]:
    """No authentication at all.  Useful as a baseline/health check."""

    return {
        "message": "This endpoint is public. No access token was required.",
        "auth_required": False,
    }


@app.get("/notes")
def notes(
    claims: dict[str, Any] = Depends(require_scope(REQUIRED_SCOPE)),
) -> dict[str, Any]:
    """Requires a valid token *and* the notes.read scope.

    The data is filtered by the token's `sub` claim, so a user can only see the
    notes that belong to their own identity.  This is the API's own authorization
    decision, independent of whatever the UI happens to display.
    """

    subject = claims.get("sub", "unknown-subject")
    username = claims.get("preferred_username", "unknown-user")
    now = int(time.time())

    owner_tag = str(subject).replace("-", "")[:8]
    return {
        "requested_by": username,
        "sub": subject,
        "notes": [
            {
                "id": f"{owner_tag}-1",
                "owner_sub": subject,
                "title": "Welcome to the notes API",
                "body": f"Only {username} can read this note.",
                "updated_at": now - 3600,
            },
            {
                "id": f"{owner_tag}-2",
                "owner_sub": subject,
                "title": "Scope check",
                "body": f"This response required the {REQUIRED_SCOPE} scope.",
                "updated_at": now - 1800,
            },
            {
                "id": f"{owner_tag}-3",
                "owner_sub": subject,
                "title": "Audience check",
                "body": f"This API accepted a token whose aud contains {AUDIENCE}.",
                "updated_at": now - 60,
            },
        ],
    }


@app.get("/admin")
def admin(
    claims: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Requires a valid token *and* the realm role admin.

    `alice` has the admin role; `bob` only has viewer, so bob gets a 403 here
    even though his token is perfectly valid.
    """

    return {
        "message": f"Welcome, administrator {claims.get('preferred_username')}!",
        "sub": claims.get("sub"),
        "realm_roles": claims.get("realm_access", {}).get("roles", []),
        "admin_only": [
            "rotate API keys",
            "read the audit log",
            "manage other users' notes",
        ],
    }
