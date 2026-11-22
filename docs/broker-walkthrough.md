# Broker Walkthrough — “Sign in with Google” via Keycloak

This lab simulates the pattern you described:

> Open LeetCode → click **Sign in with Google** → sign in at Google → LeetCode
> logs you in automatically.

The real-world equivalent is:

- **LeetCode** = `leetcode_app.py` (one browser app, port 8000).
- **Google** = a second Keycloak realm (`google`) that acts as a simulated
  upstream identity provider.
- **The broker** = the Keycloak realm `demo`. The app trusts **only** this realm.
  Keycloak handles the federation to the simulated Google realm.

The app never talks to Google directly and never receives a Google-issued token.
It receives tokens from the **broker realm**, with `iss = .../realms/demo`.

---

## 1. The two realms

| Realm | Role | Why it exists |
| --- | --- | --- |
| `demo` | Broker / IdP for the app | The app’s OIDC client (`leetcode-app`) lives here. It also has the brokered identity provider alias `google`. |
| `google` | Simulated Google | Has the “Google” login page, users `alice`/`bob`, and the client (`leetcode-broker`) that Keycloak uses during brokering. |

The app is registered **only** in `demo`. Configured in
`keycloak/realms/demo-realm.json`:

- client `leetcode-app`, secret `leetcode-secret`,
  redirect `http://localhost:8000/callback`
- PKCE required (S256)
- scopes `openid profile email notes.read`
- audience mapper: access token gets `aud = notes-api`
- identity provider alias `google` with `providerId: keycloak-oidc`
- role mappers from Google roles to broker roles

The simulated Google realm is in `keycloak/realms/google-realm.json`:

- users `alice` (admin + viewer) and `bob` (viewer)
- client `leetcode-broker`, secret `broker-secret`, redirect
  `http://localhost:8080/realms/demo/broker/google/endpoint`
- normal OIDC scopes (`basic`, `profile`, `email`, `roles`)

---

## 2. The full flow, step by step

### Step 1 — The app has no session

`GET /` runs `home()` (`leetcode_app.py:356–501`). The session middleware
(`leetcode_app.py:123–195`) creates a random server-side session id, stores it in
`SESSIONS` (`leetcode_app.py:120`), and sets a cookie named `leetcode_session`
containing only that opaque id.

The page shows a **Sign in with Google** button and no local password form. This
is intentional: the app has no local accounts.

### Step 2 — Clicking the button starts a normal OIDC flow with the broker

`GET /login` (`leetcode_app.py:502–541`) calls
`oauth.keycloak.authorize_redirect(...)` (`leetcode_app.py:526–532`) with:

- `kc_idp_hint=google` (`IDP_HINT`, `leetcode_app.py:94–97`)
- `code_challenge_method="S256"`

Authlib generates and stores `state`, `nonce`, and the PKCE `code_verifier` in
the server-side session, then redirects to the broker realm:

```
http://localhost:8080/realms/demo/protocol/openid-connect/auth
  ?response_type=code
  &client_id=leetcode-app
  &redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback
  &scope=openid+profile+email+notes.read
  &state=...
  &nonce=...
  &code_challenge=...
  &code_challenge_method=S256
  &kc_idp_hint=google
```

`kc_idp_hint` is a Keycloak extension: it tells the broker to skip its own login
page and start the `google` identity-provider flow immediately. This is what
makes the button behave like LeetCode’s social login button.

### Step 3 — The broker redirects to the simulated Google realm

The broker realm returns a `302` to the Google realm’s authorization endpoint:

```
http://localhost:8080/realms/google/protocol/openid-connect/auth
  ?response_type=code
  &client_id=leetcode-broker
  &redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fdemo%2Fbroker%2Fgoogle%2Fendpoint
  &scope=openid+profile+email
  &state=...
  &nonce=...
```

This is a **second OIDC flow**, but started by Keycloak, not by the app. The app
is not involved in it and never sees its authorization code.

### Step 4 — You sign in at “Google”

The Google realm shows its login page. Enter:

| User | Password | Google realm roles |
| --- | --- | --- |
| `alice` | `alice123` | `admin`, `viewer` |
| `bob` | `bob123` | `viewer` |

After a successful login, Google redirects to the broker callback:

```
http://localhost:8080/realms/demo/broker/google/endpoint?code=...&state=...
```

At this point the broker:

1. Exchanges Google’s code at the Google token endpoint using the
   `leetcode-broker` client secret.
2. Validates Google’s ID token (signature, issuer, audience, nonce, expiry).
3. Creates a local `demo` user if this is the first login, or links to the
   existing one.
4. Maps Google roles to broker roles using the IdP mappers.
5. Issues its **own** authorization code and redirects the browser back to the
   app.

The Google tokens remain inside Keycloak. The app receives only a `demo` code.

### Step 5 — The app exchanges the broker code

The browser lands on `GET /callback` (`leetcode_app.py:544–602`), which calls
`authorize_access_token()` (`leetcode_app.py:578`). Authlib:

1. Validates and consumes the `state` from the server-side session (CSRF defense,
   single use).
2. Sends the code, exact redirect URI, client secret, and PKCE verifier to the
   **demo** token endpoint.
3. Validates the returned ID token:
   - signature via the demo realm JWKS,
   - `iss = http://localhost:8080/realms/demo` (the broker, not Google),
   - `aud` includes `leetcode-app`,
   - `nonce` matches,
   - `exp` / `iat` are valid.
4. Stores the tokens server-side (`leetcode_app.py:599`) and redirects to `/`.

The browser cookie never contains the tokens — only the session id.

### Step 6 — What the app sees

The home page shows:

- `alice@gmail.com` — the identity that came from Google through the broker,
- roles `admin` + `viewer` — mapped from Google to the broker,
- the broker issuer `http://localhost:8080/realms/demo`,
- the ID token and access token claims,
- raw tokens for jwt.io/curl (a learning aid).

The ID token’s `iss` is `demo`, not `google`. The app never sees a Google token.
That is the central lesson of brokering.

### Step 7 — Calling the notes API

`GET /call-api/<endpoint>` (`leetcode_app.py:605–673`) sends the **demo** access
token as a Bearer token to `api.py` on port 7000.

The API validates locally (`api.py:183–271`):

- signature with the demo realm JWKS (`api.py:83–133`),
- `iss = http://localhost:8080/realms/demo`,
- `aud` contains `notes-api`,
- `exp` / `iat` and required claims,
- `scope` contains `notes.read` for `/notes` (`api.py:289–309`),
- `realm_access.roles` contains `admin` for `/admin` (`api.py:311–335`).

Alice gets `200` on `/admin`; Bob gets `403 insufficient_scope`. Missing or
tampered tokens get `401 invalid_token`.

### Step 8 — Refresh

`GET /refresh` (`leetcode_app.py:675–776`) calls the **broker** token endpoint
with `grant_type=refresh_token` (`leetcode_app.py:713`). Keycloak rotates the
refresh token and issues a new short-lived access token. The page shows old vs
new expiry.

The upstream Google session is not involved in refresh; the broker session is.

### Step 9 — Logout

`GET /logout` (`leetcode_app.py:778–818`) clears the app’s own session and
redirects to the **broker** realm’s `end_session_endpoint` with
`id_token_hint` and `post_logout_redirect_uri`.

Two sessions matter:

1. **Broker session** — ended by this logout.
2. **Google session** — intentionally **not** ended. This mirrors real life:
   logging out of LeetCode does not log you out of Google.

Because the Google session survives, clicking **Sign in with Google** again can
silently re-authenticate you until the Google session expires. To see the Google
password form again, end the Google session too (or recreate the Keycloak
container with `docker compose ... down` / `up`).

> The IdP config deliberately has **no `logoutUrl`**. If it did, Keycloak would
> try to propagate logout to the Google realm and the browser could end on a
> Google logout error. “Logout everywhere” is a separate design decision.

---

## 3. Why broker instead of integrating Google directly?

| Direct integration | Brokered integration (this lab) |
| --- | --- |
| App trusts Google (or Entra ID) directly | App trusts one broker (Keycloak) |
| App implements each provider’s quirks | Keycloak handles providers |
| Each app configures Google client id/secret | One broker holds the upstream secrets |
| Role mapping is app-specific | Broker maps upstream roles to local roles |
| Adding another IdP changes every app | Add an IdP in the broker once |

For your work project, the same shape applies: the React SPA/API trusts Entra ID
or a Keycloak broker; Keycloak can federate to Entra ID, Google, etc. The app
only needs one issuer, one JWKS, and one set of role/scope rules.

---

## 4. How roles are mapped

`demo-realm.json` defines two IdP mappers
(`identityProviderMappers`, near `demo-realm.json:469`):

```json
{
  "identityProviderMapper": "keycloak-oidc-role-to-role-idp-mapper",
  "config": {
    "external.role": "admin",
    "role": "admin",
    "syncMode": "INHERIT"
  }
}
```

and the same for `viewer`.

The mapper reads the **validated access token** from the Google realm and checks
`realm_access.roles`. If the external role is present, it grants the local role
of the same name to the broker user. On first login this creates the local user;
on later logins the roles are synchronized.

Result:

| Google user | Google token roles | Broker user roles | `/admin` |
| --- | --- | --- | --- |
| alice | `admin`, `viewer` | `admin`, `viewer` | 200 |
| bob | `viewer` | `viewer` | 403 |

The broker’s `roles` client scope (`demo-realm.json:328–377`) then puts those
mapped roles into the app’s access token as `realm_access.roles`.

---

## 5. Watching the redirects in DevTools

Open the LeetCode app, DevTools → **Network** → enable **Preserve log**, then click
**Sign in with Google**:

| # | Request | What to notice |
| --- | --- | --- |
| 1 | `GET http://localhost:8000/login` | `302` to the broker with `kc_idp_hint=google`, `state`, `nonce`, `code_challenge` |
| 2 | `GET http://localhost:8080/realms/demo/protocol/openid-connect/auth?...` | `302` to the Google realm |
| 3 | `GET http://localhost:8080/realms/google/protocol/openid-connect/auth?...` | `200` Google login page |
| 4 | `POST http://localhost:8080/realms/google/login-actions/authenticate` | `302` to `.../realms/demo/broker/google/endpoint?code=...` |
| 5 | `GET .../realms/demo/broker/google/endpoint?code=...` | `302` to the app’s `/callback?code=...` |
| 6 | `GET http://localhost:8000/callback?code=...&state=...` | `303` to `/`; tokens never appear in the URL |
| 7 | `GET http://localhost:8000/` | `200`; home shows the broker-issued claims |

Notice that there are **two** authorization-code flows: the broker↔Google flow
(invisible to the app) and the app↔broker flow. The app only participates in the
second one.

On **Logout**, the chain goes to the broker’s end-session endpoint, then back to
`http://localhost:8000/?state=...` — the Google realm is not logged out.

---

## 6. Inspecting tokens on jwt.io

1. Log in as Alice.
2. On the app home page, expand **Raw tokens → Access token**.
3. Paste it into <https://jwt.io>.
4. Verify the signature with the **demo** JWKS:

   ```
   http://localhost:8080/realms/demo/protocol/openid-connect/certs
   ```

Look for:

| Claim | Expected |
| --- | --- |
| `iss` | `http://localhost:8080/realms/demo` (broker, not Google) |
| `aud` | includes `notes-api` |
| `azp` | `leetcode-app` |
| `preferred_username` | `alice` |
| `email` | `alice@gmail.com` |
| `scope` | `openid notes.read profile email` |
| `realm_access.roles` | includes `admin` and `viewer` |

If you copy the **ID token**, its `iss` is still `demo` and its `aud` is
`leetcode-app`. The app never receives a token with `iss = .../realms/google`.

---

## 7. Code map

| Flow step | Implementation | Lines |
| --- | --- | --- |
| Config (`CLIENT_ID`, `PORT`, issuer, redirect URI) | `leetcode_app.py` | 64–110 |
| `kc_idp_hint=google` | `leetcode_app.py` | 94–97 |
| Server-side session store | `leetcode_app.py:SESSIONS` | 120 |
| Session middleware + cookie | `leetcode_app.py:ServerSideSessionMiddleware` | 123–195 |
| OIDC client + discovery + PKCE | `leetcode_app.py:oauth.register` | 206–218 |
| Decode tokens for display only | `leetcode_app.py:decode_jwt_for_display` | 230–248 |
| Home page, broker explanation | `leetcode_app.py:home` | 356–501 |
| `/login` → broker with IdP hint | `leetcode_app.py:login` | 502–541 |
| `/callback` → state + code exchange + ID-token validation | `leetcode_app.py:callback` | 544–602 |
| Token storage server-side | `leetcode_app.py` | 599 |
| API call with Bearer token | `leetcode_app.py:call_api` | 605–673 |
| Refresh-token grant | `leetcode_app.py:refresh` | 675–776 |
| Logout via broker end-session | `leetcode_app.py:logout` | 778–818 |
| Broker realm: client + IdP + mappers | `keycloak/realms/demo-realm.json` | 389–491 |
| LeetCode app client, PKCE, audience mapper | `keycloak/realms/demo-realm.json` | 389–438 |
| Brokered Google IdP config | `keycloak/realms/demo-realm.json` | 440–467 |
| Google→broker role mappers | `keycloak/realms/demo-realm.json` | 469–490 |
| Simulated Google realm users/roles | `keycloak/realms/google-realm.json` | 15–66 |
| Simulated Google scopes | `keycloak/realms/google-realm.json` | 68–414 |
| Simulated Google broker client | `keycloak/realms/google-realm.json` | 416–446 |
| API discovery + JWKS | `api.py:get_discovery_metadata`, `get_jwks_client` | 83–133 |
| API JWT validation | `api.py:validate_access_token` | 183–271 |
| API 401/403 helpers | `api.py:unauthorized`, `forbidden` | 145–179 |
| Scope/role dependencies | `api.py:require_scope`, `require_role` | 289–335 |
| API endpoints | `api.py` `/notes`, `/admin` | 363–426 |

Line numbers refer to the generated files; use function names as the stable
reference.

---

## 8. Configuration gotchas (important)

1. **Keycloak 26 realm import does not create built-in client scopes.**
   That is why `demo-realm.json` and `google-realm.json` explicitly define
   `basic` (for `sub`), `profile`, `email`, and `roles`. Without them, tokens
   would lack `sub`, email, or roles.
2. **The Google client redirect URI must be the broker endpoint**, not the app
   callback:
   `http://localhost:8080/realms/demo/broker/google/endpoint`.
3. **`updateProfileFirstLoginMode` can remain “on”, but the Review Profile page
   is skipped** when the upstream user has first/last name, email, and
   `emailVerified=true` because the flow’s review config is “only when missing”.
4. **No `logoutUrl` on the brokered IdP** — otherwise Keycloak tries to
   propagate logout to Google and can end on a Google logout error. Leaving it
   out matches “log out of LeetCode, stay logged in to Google”.
5. **Browsers allow `Secure` cookies on `http://localhost`; curl/httpx do not.**
   If you script the flow with a minimal HTTP client, you may see
   `cookie_not_found`. Use a browser or relax the Secure flag in the test client.
6. **Role changes in Google are re-synchronized on later logins** according to
   `syncMode: INHERIT`. If you change a Google user’s roles, log out of the
   broker (and optionally recreate the local user) and log in again.

---

## 9. Verification checklist

- [ ] `GET /login` redirects to `.../realms/demo/...` with `kc_idp_hint=google`.
- [ ] The next hop is `.../realms/google/...` (the simulated Google login).
- [ ] After Google login, the broker callback path is
      `.../realms/demo/broker/google/endpoint`.
- [ ] The app home shows the broker issuer, `alice@gmail.com`, and mapped roles.
- [ ] ID token `iss` is `demo` and `aud` is `leetcode-app`.
- [ ] Access token `iss` is `demo`, `aud` contains `notes-api`, and `scope`
      contains `notes.read`.
- [ ] Alice `/notes` and `/admin` are `200`; Bob `/notes` is `200` and `/admin`
      is `403`.
- [ ] Refresh rotates the refresh token and updates the access-token expiry.
- [ ] Logout clears the app session and broker session; the Google session
      remains, so a later login may be silent.
- [ ] Missing token → `401 invalid_token`; tampered token → `401`; ID token sent
      to the API → `401` wrong audience.

---

## 10. Out of scope

- Real Google/Entra ID integration (this lab simulates the upstream IdP with a
  second Keycloak realm).
- Upstream logout propagation / “logout everywhere”.
- Back-channel and front-channel logout between apps.
- Token introspection, revocation, DPoP, PAR/JAR/JARM.
- A hand-written IdP (`mini_idp/` is reserved for a later phase).
