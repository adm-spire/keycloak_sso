"""
LeetCode-style app that signs in with "Google" through Keycloak.

This is the single browser-facing app in the broker lab. It plays the role of
LeetCode: the user arrives, clicks "Sign in with Google", authenticates at the
simulated Google IdP, and is returned to this app already signed in.

The important twist is that this app NEVER talks to Google directly. It is an
OIDC client of the Keycloak broker realm (`demo`). Keycloak, in turn, brokers
the login to the upstream simulated Google realm (`google`):

    Browser -> this app -> Keycloak (demo realm)
                              -> Google (simulated realm)  [login form]
                              <- Google redirects back to Keycloak
              this app <- Keycloak redirects back with a code
              this app -> Keycloak token endpoint
              this app <- tokens issued by the broker realm (`demo`)

So the app sees only tokens from the broker realm. The `iss` claim is
`http://localhost:8080/realms/demo`, not the Google realm. This mirrors a real
setup where your application trusts Entra ID / Keycloak, and Keycloak handles
the federation to Google.

The OIDC flow implemented here is the Authorization Code flow with PKCE, state
and nonce:

    1. /login          -> redirect to the broker realm with kc_idp_hint=google
    2. user signs in   -> Keycloak brokers to the simulated Google realm
    3. /callback       -> broker realm redirects back with a one-time ?code=...
    4. token exchange  -> our server POSTs the code + client secret + PKCE verifier
                          to the broker realm's token endpoint
    5. ID token        -> Authlib validates signature, issuer, audience, nonce, exp
    6. session         -> tokens are kept server-side; the browser only holds a
                          random session id
    7. /call-api/...   -> our server calls the notes API with the access token

Authlib (https://docs.authlib.org/) implements the protocol mechanics.  The
comments below point at WHERE each security control happens so you can follow
the flow while reading.
"""

from __future__ import annotations

import base64
import html
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.datastructures import MutableHeaders

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------


def require_env(name: str) -> str:
    """Fail fast with a useful message instead of a KeyError."""

    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable {name}. "
            "See README.md for the exact run commands."
        )
    return value


CLIENT_ID = require_env("CLIENT_ID")
CLIENT_SECRET = require_env("CLIENT_SECRET")
APP_NAME = require_env("APP_NAME")
PORT = int(require_env("PORT"))

# The issuer is the realm's base URL.  Everything else (authorization endpoint,
# token endpoint, JWKS endpoint, end-session endpoint) comes from OIDC discovery.
ISSUER = os.environ.get("ISSUER", "http://localhost:8080/realms/demo")

# The redirect URI must match one of the client's registered redirect URIs
# EXACTLY.  Keycloak compares scheme, host, port and path.  This is an important
# security control: a stolen authorization code cannot be sent to an attacker's
# server because Keycloak will refuse to redirect anywhere else.
REDIRECT_URI = f"http://localhost:{PORT}/callback"

# Keycloak only allows post-logout redirects that are registered on the client.
POST_LOGOUT_REDIRECT_URI = f"http://localhost:{PORT}/"

# The alias of the identity provider configured in the Keycloak broker realm.
# Sending `kc_idp_hint=google` makes Keycloak skip its own login page and go
# straight to the simulated Google IdP. That is what makes the app behave like
# LeetCode's "Sign in with Google" button instead of showing a local login form.
IDP_HINT = os.environ.get("IDP_HINT", "google")

# Our protected resource server (api.py).
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:7000")

# Requested scopes.  `openid` activates OIDC (ID token + discovery).  The custom
# `notes.read` scope is a Keycloak client scope that is copied into the access
# token's `scope` claim.  `profile` and `email` give us name/email claims.
SCOPE = "openid profile email notes.read"

# Cookies are keyed by (host, path, name), not by app. Naming the cookie after
# the app (`leetcode_session`) avoids collisions if you later run more apps on
# other localhost ports and keeps the lab's sessions easy to identify.
COOKIE_NAME = f"{APP_NAME}_session"

# ---------------------------------------------------------------------------
# 2. Server-side session store
# ---------------------------------------------------------------------------

# The browser must never hold the access/refresh/id tokens.  In this lab they
# live in this in-memory dictionary, keyed by an unguessable session id.  The
# cookie contains only that id.  (A real deployment would use Redis/a database
# so sessions survive restarts and are shared by multiple app instances.)
SESSIONS: dict[str, dict[str, Any]] = {}


class ServerSideSessionMiddleware:
    """Give Starlette/Authlib a `request.session` dict backed by SESSIONS.

    Authlib's Starlette integration stores the OAuth `state`, `nonce`,
    `code_verifier` and redirect URI in `request.session` between the
    authorization redirect and the callback.  Starlette normally supplies that
    dict via SessionMiddleware, which signs the whole session into a cookie.
    We want the data to stay on the server instead, so this middleware:

      1. reads the random session id from our cookie,
      2. looks up (or creates) the matching dict in SESSIONS,
      3. exposes it as scope["session"] (where Request.session reads from),
      4. writes the cookie only when a new session was created.
    """

    def __init__(self, app, cookie_name: str, max_age: int = 3600) -> None:
        self.app = app
        self.cookie_name = cookie_name
        self.max_age = max_age

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        # Load the session id.  If it is missing or unknown (server restarted,
        # expired, or forged), start a brand-new empty session.
        session_id = request.cookies.get(self.cookie_name)
        is_new = False
        if not session_id or session_id not in SESSIONS:
            session_id = secrets.token_urlsafe(32)  # 256 bits of entropy
            SESSIONS[session_id] = {}
            is_new = True

        # Starlette's Request.session property returns scope["session"].
        scope["session"] = SESSIONS[session_id]
        scope["session_id"] = session_id

        async def send_with_cookie(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if scope.pop("expire_session_cookie", False):
                    # /logout asked us to forget the browser cookie too.
                    headers.append(
                        "set-cookie",
                        f"{self.cookie_name}=; Path=/; HttpOnly; "
                        f"SameSite=Lax; Max-Age=0",
                    )
                elif is_new:
                    # Only the opaque id goes into the browser.  HttpOnly stops
                    # JavaScript from reading it; SameSite=Lax still allows the
                    # cookie on the top-level redirect from Keycloak back to us.
                    headers.append(
                        "set-cookie",
                        f"{self.cookie_name}={session_id}; Path=/; HttpOnly; "
                        f"SameSite=Lax; Max-Age={self.max_age}",
                    )
            await send(message)

        await self.app(scope, receive, send_with_cookie)


# ---------------------------------------------------------------------------
# 3. Authlib OIDC client
# ---------------------------------------------------------------------------

app = FastAPI(title=f"LeetCode Broker Lab ({APP_NAME})")
app.add_middleware(ServerSideSessionMiddleware, cookie_name=COOKIE_NAME)

oauth = OAuth()

# Discovery: Authlib fetches {ISSUER}/.well-known/openid-configuration and uses
# the published endpoints and the realm's signing keys.  Hard-coding endpoints
# would drift; discovery is the OIDC-standard way to find them.
#
# `code_challenge_method="S256"` turns on PKCE.  Authlib generates a random
# code_verifier, sends only its SHA-256 hash (code_challenge) to Keycloak, keeps
# the verifier in the server-side session, and sends the verifier during the
# token exchange.  Keycloak requires PKCE for these clients.  Why it matters:
# the authorization code travels through the browser (and can leak via
# history/referrer); PKCE makes a stolen code useless without the verifier.
oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    client_kwargs={
        "scope": SCOPE,
        "code_challenge_method": "S256",
    },
)


# ---------------------------------------------------------------------------
# 4. Small helpers
# ---------------------------------------------------------------------------


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url JWT segment, adding the padding JSON encoders drop."""

    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def decode_jwt_for_display(token: str | None) -> dict[str, Any]:
    """Decode a JWT payload WITHOUT verifying it, purely for the HTML page.

    This is safe for display because real validation already happened:
      * the ID token was validated by Authlib during /callback, and
      * the API validates the access token before trusting it.

    Never make authorization decisions from this function's output.
    """

    if not token:
        return {}
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {"error": "not a JWT (no payload segment)"}
        return json.loads(b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001 - display must never crash the page
        return {"error": f"could not decode token for display: {exc}"}


def id_token_claims(token: dict[str, Any] | None) -> dict[str, Any]:
    """Prefer Authlib's validated `userinfo` (parsed ID token) over raw decode."""

    if not token:
        return {}
    userinfo = token.get("userinfo")
    if userinfo:
        return dict(userinfo)
    return decode_jwt_for_display(token.get("id_token"))


def access_token_claims(token: dict[str, Any] | None) -> dict[str, Any]:
    if not token:
        return {}
    return decode_jwt_for_display(token.get("access_token"))


def roles_from(token: dict[str, Any] | None) -> list[str]:
    """Realm roles live under realm_access.roles in the access token."""

    claims = access_token_claims(token)
    return list(claims.get("realm_access", {}).get("roles", []))


def as_utc(epoch: float | int | None) -> str:
    if not epoch:
        return "unknown"
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def esc(value: Any) -> str:
    """Escape every dynamic value before putting it into HTML."""

    return html.escape("" if value is None else str(value))


def pretty_json(value: Any) -> str:
    return esc(json.dumps(value, indent=2, sort_keys=True, default=str))


def page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    """Tiny shared HTML shell; the body is assembled from pre-escaped fragments."""

    return HTMLResponse(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)}</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif;
            max-width: 980px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
    h1, h2 {{ line-height: 1.2; }}
    .pill {{ display: inline-block; padding: .15rem .55rem; border-radius: 999px;
             background: #2563eb; color: white; font-size: .85rem; }}
    .pill.off {{ background: #6b7280; }}
    .ok {{ color: #15803d; }} .bad {{ color: #b91c1c; }}
    nav a {{ margin-right: .9rem; }}
    pre {{ background: #111827; color: #e5e7eb; padding: 1rem; border-radius: .5rem;
           overflow-x: auto; font-size: .82rem; }}
    .card {{ border: 1px solid #9ca3af55; border-radius: .6rem; padding: 1rem; margin: 1rem 0; }}
    table {{ border-collapse: collapse; }} td, th {{ border: 1px solid #9ca3af55;
             padding: .35rem .6rem; text-align: left; }}
    code {{ font-size: .9em; }}
    .btn {{ display: inline-block; padding: .65rem 1.2rem; border-radius: .5rem;
            background: #2563eb; color: white; text-decoration: none;
            font-weight: 600; }}
    .btn:hover {{ background: #1d4ed8; }}
  </style>
</head>
<body>
{body}
</body>
</html>""",
        status_code=status_code,
    )


def nav(logged_in: bool) -> str:
    login_or_logout = (
        '<a href="/logout">Logout</a>'
        if logged_in
        else '<a href="/login">Sign in with Google</a>'
    )
    return f"""
    <nav>
      <a href="/">Home</a>
      {login_or_logout}
      <a href="/call-api/public">API /public</a>
      <a href="/call-api/notes">API /notes</a>
      <a href="/call-api/admin">API /admin</a>
      <a href="/refresh">Refresh token</a>
    </nav>
    """


# ---------------------------------------------------------------------------
# 5. Routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Landing page: session status, claims, and links to every demo route."""

    token = request.session.get("token")
    logged_in = token is not None

    id_claims = id_token_claims(token)
    access_claims = access_token_claims(token)
    roles = roles_from(token)

    name = id_claims.get("name") or id_claims.get("preferred_username") or "—"
    email = id_claims.get("email") or "—"
    username = id_claims.get("preferred_username") or "—"

    session_rows = f"""
      <div class="card">
        <h2>Session</h2>
        <p><strong>App:</strong> {esc(APP_NAME)} on http://localhost:{esc(PORT)}</p>
        <p><strong>Identity provider:</strong> Google (simulated realm
          <code>google</code>, brokered by Keycloak)</p>
        <p><strong>Broker issuer:</strong> <code>{esc(ISSUER)}</code></p>
        <p><strong>Status:</strong>
          <span class="pill {'on' if logged_in else 'off'}">
            {'logged in' if logged_in else 'logged out'}
          </span>
        </p>
        <p><strong>User:</strong> {esc(name)} (<code>{esc(username)}</code>)</p>
        <p><strong>Email:</strong> {esc(email)}</p>
        <p><strong>Realm roles:</strong>
          {esc(', '.join(roles)) if roles else '—'}
        </p>
        <p><strong>Server-side session id:</strong>
          <code>{esc(request.scope.get("session_id"))}</code> (only this id is in
          the <code>{esc(COOKIE_NAME)}</code> cookie)</p>
      </div>
    """

    id_display = (
        pretty_json(id_claims)
        if logged_in
        else '<em>Not logged in yet. Click "Sign in with Google".</em>'
    )
    access_display = (
        pretty_json(access_claims)
        if logged_in
        else '<em>No access token yet.</em>'
    )

    signin_card = "" if logged_in else f"""
      <div class="card" style="text-align:center">
        <h2>Welcome to LeetCode (simulated)</h2>
        <p>
          This app has no password form of its own. It trusts Keycloak, and
          Keycloak brokers the login to a simulated Google IdP.
        </p>
        <p><a class="btn" href="/login">Sign in with Google</a></p>
        <p>Try <code>alice</code> / <code>alice123</code> (admin) or
          <code>bob</code> / <code>bob123</code> (viewer) at the Google screen.</p>
      </div>
    """

    body = f"""
      <h1>LeetCode (simulated) — Keycloak broker demo</h1>
      {nav(logged_in)}

      {signin_card}

      {session_rows}

      <div class="card">
        <h2>How the brokered login works</h2>
        <ol>
          <li>This app redirects to the <strong>Keycloak broker realm</strong>
              (<code>demo</code>) with <code>kc_idp_hint={esc(IDP_HINT)}</code>.</li>
          <li>Keycloak redirects to the <strong>simulated Google realm</strong>
              (<code>google</code>), where you see the login form.</li>
          <li>After Google authenticates you, Keycloak creates/links a local user,
              maps the Google roles, and redirects back here with a code.</li>
          <li>This app exchanges that code with the <strong>broker realm</strong>.
              All tokens below were issued by <code>demo</code>, not by Google.</li>
        </ol>
        <p>
          Look at the ID token <code>iss</code>: it is
          <code>{esc(ISSUER)}</code>. The app never sees a Google token. That is
          the point of brokering — the app trusts one IdP, and that IdP handles
          the federation.
        </p>
      </div>

      <div class="card">
        <h2>ID token claims (validated by Authlib at /callback)</h2>
        <p>Decoded for display only; validation has already happened.</p>
        <pre>{id_display}</pre>
      </div>

      <div class="card">
        <h2>Access token claims</h2>
        <p>
          Notice <code>aud</code> contains <code>notes-api</code> (audience mapper),
          <code>scope</code> contains <code>notes.read</code> (client scope), and
          <code>realm_access.roles</code> contains the roles that Keycloak mapped
          from the simulated Google user.
        </p>
        <pre>{access_display}</pre>
      </div>

      <div class="card">
        <h2>Raw tokens (learning aid)</h2>
        <p>
          Copy these into <a href="https://jwt.io" target="_blank"
          rel="noopener noreferrer">jwt.io</a> to inspect them, or use them with
          <code>curl</code>. A production app would never render tokens into
          HTML — this page exists to teach the flow.
        </p>
        <details><summary>ID token</summary>
          <pre>{esc(token.get("id_token", "(none)")) if token else "(not logged in)"}</pre>
        </details>
        <details><summary>Access token</summary>
          <pre>{esc(token.get("access_token", "(none)")) if token else "(not logged in)"}</pre>
        </details>
        <details><summary>Refresh token</summary>
          <pre>{esc(token.get("refresh_token", "(none)")) if token else "(not logged in)"}</pre>
        </details>
      </div>

      <div class="card">
        <h2>Try the flow</h2>
        <ol>
          <li>Click <strong>Sign in with Google</strong>.</li>
          <li>Sign in as <code>alice</code> / <code>alice123</code> (admin + viewer)
              or <code>bob</code> / <code>bob123</code> (viewer) at the simulated
              Google screen.</li>
          <li>You return here already signed in; Keycloak brokered the login.</li>
          <li>Call <code>/notes</code> (needs scope <code>notes.read</code>).</li>
          <li>Call <code>/admin</code> (needs realm role <code>admin</code>).
              Bob should get <code>403</code>.</li>
          <li>Log out. This ends the broker session, not your simulated Google
              session, so signing in again may be silent — just like logging out
              of LeetCode does not log you out of Google.</li>
        </ol>
      </div>
    """
    return page(f"{APP_NAME} home", body)


@app.get("/login")
async def login(request: Request):
    """Kick off Authorization Code + PKCE.

    Authlib generates:
      * `state` — a random, unguessable value echoed back by Keycloak.  We store
        it in the server-side session.  On /callback, a missing/mismatched state
        means the response did not originate from a flow we started -> possible
        CSRF / login-CSRF, so the callback is rejected.
      * `nonce` — a random value placed inside the ID token request.  It comes
        back inside the ID token and is bound to this browser session, stopping
        an attacker from replaying an ID token obtained elsewhere.
      * `code_verifier` — the PKCE secret; its S256 hash is sent now and the
        verifier is sent at token exchange, making a stolen code useless.

    Authlib also includes the registered redirect URI and requested scopes.

    The extra `kc_idp_hint` is a Keycloak extension. It tells the broker realm
    to skip its own login page and immediately start the `google` identity
    provider flow. This is what makes the app's button behave like LeetCode's
    "Sign in with Google": the browser lands on Google, not on a local Keycloak
    username/password form.
    """

    try:
        return await oauth.keycloak.authorize_redirect(
            request,
            REDIRECT_URI,
            code_challenge_method="S256",
            kc_idp_hint=IDP_HINT,
        )
    except Exception as exc:  # noqa: BLE001 - show a readable error page
        return page(
            "Login error",
            f"""<h1 class="bad">Could not reach Keycloak</h1>
            <p>{esc(exc)}</p>
            <p>Is the Keycloak container running at {esc(ISSUER)}?</p>
            <p><a href="/">Back</a></p>""",
            status_code=502,
        )


@app.get("/callback")
async def callback(request: Request):
    """Receive ?code & ?state, validate them, and exchange the code for tokens.

    Brokering note: between the browser leaving /login and arriving back here,
    Keycloak ran a *second* OIDC flow with the simulated Google IdP. This app
    never sees that flow or Google's tokens. We exchange our own code with the
    broker realm, so every token below has `iss = demo`.

    What Authlib does inside `authorize_access_token`:

      1. Reads `code` and `state` from the query string.
      2. Looks up the saved state data in our server-side session.
         - No state record, or a different state => MismatchingStateError.
         - The state record is single-use and removed afterwards.
      3. POSTs to Keycloak's token endpoint with:
         - grant_type=authorization_code,
         - the one-time authorization code,
         - the exact redirect_uri used in step 1,
         - client_id + client_secret (confidential client authentication),
         - the PKCE code_verifier (Keycloak checks SHA-256(verifier) == challenge).
      4. Validates the returned ID token:
         - JWS signature against the realm's JWKS (so the token really is from
           this Keycloak realm and has not been altered),
         - `iss` equals the discovered issuer,
         - `aud` contains this client id,
         - `exp`/`iat` are within the allowed window (with leeway),
         - `nonce` equals the nonce we generated for this session,
         - `at_hash` binds the ID token to the access token.

    If any check fails Authlib raises OAuthError and we do NOT create a session.
    """

    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except OAuthError as exc:
        return page(
            "Callback rejected",
            f"""<h1 class="bad">Token exchange rejected</h1>
            <p><strong>{esc(exc.error)}</strong>: {esc(exc.description)}</p>
            <p>Common causes: expired/used code, wrong redirect URI, bad client
            secret, missing PKCE verifier, or a stale state value.</p>
            <p><a href="/login">Try again</a> · <a href="/">Home</a></p>""",
            status_code=400,
        )
    except Exception as exc:  # noqa: BLE001 - show a readable error page
        return page(
            "Callback error",
            f"""<h1 class="bad">Unexpected callback error</h1>
            <p>{esc(exc)}</p>
            <p><a href="/login">Try again</a> · <a href="/">Home</a></p>""",
            status_code=502,
        )

    # Keep the tokens server-side.  Never put them in a cookie or localStorage.
    request.session["token"] = dict(token)

    # 303 turns the POST-like callback navigation into a clean GET of "/".
    return RedirectResponse("/", status_code=303)


@app.get("/call-api/{endpoint}")
async def call_api(request: Request, endpoint: str):
    """Call the resource server with (or without) the access token.

    The browser never calls the API directly.  Our server acts as the OAuth
    client and presents the bearer token, which is why the API can be on a
    different origin without CORS.
    """

    if endpoint not in {"public", "notes", "admin"}:
        return page(
            "Unknown endpoint",
            """<h1 class="bad">Unknown API endpoint</h1>
            <p>Use <code>public</code>, <code>notes</code> or <code>admin</code>.</p>
            <p><a href="/">Back</a></p>""",
            status_code=404,
        )

    token = request.session.get("token")
    headers: dict[str, str] = {}
    sent_token = bool(token and token.get("access_token"))
    if sent_token:
        headers["Authorization"] = f"Bearer {token['access_token']}"

    url = f"{API_BASE_URL}/{endpoint}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return page(
            "API call failed",
            f"""<h1 class="bad">Could not reach the API</h1>
            <p>{esc(exc)}</p>
            <p>Is api.py running at {esc(API_BASE_URL)}?</p>
            <p><a href="/">Back</a></p>""",
            status_code=502,
        )

    try:
        body_text = json.dumps(response.json(), indent=2, sort_keys=True)
    except Exception:  # noqa: BLE001 - non-JSON responses are still useful
        body_text = response.text

    status_class = "ok" if response.status_code < 400 else "bad"
    www_auth = response.headers.get("www-authenticate", "(not present)")
    sent_text = (
        "yes — Authorization: Bearer &lt;access_token&gt;"
        if sent_token
        else "no — request was sent without an Authorization header"
    )

    return page(
        f"API /{endpoint}",
        f"""<h1>API call: <code>GET /{endpoint}</code></h1>
        {nav(token is not None)}
        <div class="card">
          <p><strong>Request URL:</strong> <code>{esc(url)}</code></p>
          <p><strong>Access token sent:</strong> {sent_text}</p>
          <p><strong>Response status:</strong>
            <span class="{status_class}">{esc(response.status_code)}</span></p>
          <p><strong>WWW-Authenticate:</strong> <code>{esc(www_auth)}</code></p>
        </div>
        <div class="card">
          <h2>Response body</h2>
          <pre>{esc(body_text)}</pre>
        </div>
        <p><a href="/">Back</a></p>""",
    )


@app.get("/refresh")
async def refresh(request: Request):
    """Use the refresh token to get a new access token without re-login.

    A refresh token is long-lived (relative to the access token) and is bound to
    the user's Keycloak SSO session.  The token endpoint checks the client
    credentials and the refresh token itself, then issues a fresh short-lived
    access token.  Keycloak may rotate the refresh token; we keep the new one
    when present and otherwise retain the old one.

    Refreshing does NOT bypass the SSO session: if the user logged out at
    Keycloak, the refresh token stops working.
    """

    token = request.session.get("token")
    if not token:
        return page(
            "Refresh failed",
            """<h1 class="bad">Not logged in</h1>
            <p><a href="/login">Log in first</a> · <a href="/">Home</a></p>""",
            status_code=400,
        )

    current_refresh_token = token.get("refresh_token")
    if not current_refresh_token:
        return page(
            "Refresh failed",
            """<h1 class="bad">No refresh token in this session</h1>
            <p>The authorization server did not issue one (check the client's
            offline/refresh settings).</p>
            <p><a href="/logout">Log in again</a> · <a href="/">Home</a></p>""",
            status_code=400,
        )

    old_expires_at = token.get("expires_at")
    old_claims = access_token_claims(token)

    try:
        new_token = await oauth.keycloak.fetch_access_token(
            grant_type="refresh_token",
            refresh_token=current_refresh_token,
        )
    except Exception as exc:  # noqa: BLE001 - show a readable error page
        return page(
            "Refresh failed",
            f"""<h1 class="bad">Refresh token rejected</h1>
            <p>{esc(exc)}</p>
            <p>The refresh token may be expired, revoked, or the SSO session may
            have ended. <a href="/login">Log in again</a> · <a href="/">Home</a></p>""",
            status_code=400,
        )

    # Merge, because a refresh response normally contains access_token,
    # expires_in, refresh_token and maybe id_token — but not every field.
    merged = dict(token)
    merged.update(dict(new_token))
    if "refresh_token" not in new_token and current_refresh_token:
        merged["refresh_token"] = current_refresh_token
    request.session["token"] = merged

    new_expires_at = merged.get("expires_at")
    new_claims = access_token_claims(merged)
    rotated = "refresh_token" in new_token and new_token.get(
        "refresh_token"
    ) != current_refresh_token

    return page(
        "Refresh result",
        f"""<h1>Refresh token grant</h1>
        {nav(True)}
        <div class="card">
          <h2>Access token expiry: old vs new</h2>
          <table>
            <tr><th></th><th>Old access token</th><th>New access token</th></tr>
            <tr>
              <td>Stored <code>expires_at</code></td>
              <td>{esc(as_utc(old_expires_at))}</td>
              <td>{esc(as_utc(new_expires_at))}</td>
            </tr>
            <tr>
              <td>JWT <code>exp</code> claim</td>
              <td>{esc(as_utc(old_claims.get("exp")))}</td>
              <td>{esc(as_utc(new_claims.get("exp")))}</td>
            </tr>
            <tr>
              <td>JWT <code>iat</code> claim</td>
              <td>{esc(as_utc(old_claims.get("iat")))}</td>
              <td>{esc(as_utc(new_claims.get("iat")))}</td>
            </tr>
          </table>
          <p><strong>Refresh token rotated:</strong>
            {'yes — the old refresh token is now invalid' if rotated else 'no — same refresh token kept'}</p>
          <p>The new access token was stored in this app's server-side session.
             The old one is no longer used.</p>
        </div>
        <div class="card">
          <h2>New access token claims</h2>
          <pre>{pretty_json(new_claims)}</pre>
        </div>
        <p><a href="/">Back</a></p>""",
    )


@app.get("/logout")
async def logout(request: Request):
    """Clear our local session, then end the broker realm's SSO session.

    Three sessions are involved in a brokered login:

      1. This app's session (the SESSIONS entry + browser cookie). We delete it.
      2. The Keycloak broker realm's SSO session. We end it by redirecting to
         the broker's end_session_endpoint with `id_token_hint`, so Keycloak
         knows which session to terminate.
      3. The simulated Google realm's SSO session. This is a **separate** IdP
         session and is intentionally not ended here — logging out of LeetCode
         does not log you out of Google.

    Because the Google session survives, a later "Sign in with Google" may be
    silent (no Google password) until that upstream session expires. In
    production you would decide whether to propagate logout upstream (Google
    end-session), which is outside this lab's scope.
    """

    token = request.session.get("token") or {}
    id_token = token.get("id_token")

    try:
        logout_data = await oauth.keycloak.create_logout_url(
            post_logout_redirect_uri=POST_LOGOUT_REDIRECT_URI,
            id_token_hint=id_token,
            client_id=CLIENT_ID,
        )
        end_session_url = logout_data["url"]
    except Exception:  # noqa: BLE001 - still clear local session if IdP is down
        end_session_url = POST_LOGOUT_REDIRECT_URI

    # Forget the server-side session and ask the middleware to expire the cookie.
    session_id = request.scope.get("session_id")
    request.session.clear()
    if session_id:
        SESSIONS.pop(session_id, None)
    request.scope["expire_session_cookie"] = True

    return RedirectResponse(end_session_url, status_code=303)
