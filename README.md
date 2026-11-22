# SSO Lab — Keycloak Identity Broker + LeetCode-style App

A local simulation of this real-world pattern:

> You open LeetCode, click **“Sign in with Google”**, sign in at Google, and
> LeetCode logs you in automatically.

In this lab, **Keycloak is the broker**, not the final identity source:

- **Realm `demo`** — the broker realm. It is the only identity provider the app
  trusts. It has a client for the app and a brokered identity provider named
  `google`.
- **Realm `google`** — a second Keycloak realm that **simulates Google**. It has
  its own users, login page, roles, and SSO session.
- **`leetcode_app.py`** — one browser app on `:8000`. It has a
  **“Sign in with Google”** button and never talks to Google directly.
- **`api.py`** — the protected notes API on `:7000`. It validates tokens issued
  by the **broker** realm (`iss = .../realms/demo`).

The important result: the app receives tokens from Keycloak (`demo`), not from
Google. Keycloak performs the “second” OIDC flow with Google, creates/links a
local user, and maps the Google roles to broker roles. That is identity
brokering.

Flow at a glance:

```
Browser -> LeetCode app -> Keycloak demo (broker)
                              -> Google demo realm (login)
                              <- Google redirects back to Keycloak
          LeetCode app <- Keycloak redirects back with a code
          LeetCode app -> Keycloak demo token endpoint
          LeetCode app <- ID/access/refresh tokens issued by demo
          LeetCode app -> notes API (Bearer access token)
```

Quick links:

- Commands only: [`STARTUP.md`](STARTUP.md)
- Full flow, security rationale, and code map: [`docs/broker-walkthrough.md`](docs/broker-walkthrough.md)
- Mermaid architecture/sequence diagrams: [`docs/diagrams.md`](docs/diagrams.md)

---

## Layout

```
sso-lab/
  keycloak/
    docker-compose.yml          # Keycloak 26, imports both realms on boot
    realms/
      demo-realm.json           # broker realm: app client + brokered Google IdP
      google-realm.json         # simulated Google IdP realm
  leetcode_app.py               # the single browser app (:8000)
  api.py                        # notes API (:7000), validates broker tokens
  mini_idp/                     # reserved for a later hand-written IdP phase
  docs/
    broker-walkthrough.md
    diagrams.md
  requirements.txt
  README.md
  STARTUP.md
```

---

## Prerequisites

- Docker Engine + Docker Compose v2 (`docker compose ...`)
- Python 3.11 or newer
- A browser

> Use `http://localhost:...` everywhere, not `127.0.0.1`. The realms, redirect
> URIs, issuer values, and cookies are configured for `localhost`.

---

## 1. Start Keycloak (broker + simulated Google)

From `sso-lab/`:

```bash
docker compose -f keycloak/docker-compose.yml up
```

PowerShell is identical:

```powershell
docker compose -f keycloak/docker-compose.yml up
```

Wait for:

```
Listening on: http://0.0.0.0:8080
```

Then:

- Broker realm discovery:
  <http://localhost:8080/realms/demo/.well-known/openid-configuration>
- Simulated Google realm discovery:
  <http://localhost:8080/realms/google/.well-known/openid-configuration>
- Admin console: <http://localhost:8080> — `admin` / `admin`

> The realm import runs only when a realm does not exist. To re-import after
> editing either JSON file:
>
> ```bash
> docker compose -f keycloak/docker-compose.yml down
> docker compose -f keycloak/docker-compose.yml up
> ```

---

## 2. Create the Python environment

### bash / macOS / Linux / WSL

```bash
cd sso-lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows PowerShell

```powershell
cd sso-lab
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If activation is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

---

## 3. Start the API — terminal A (port 7000)

### bash

```bash
source .venv/bin/activate
uvicorn api:app --port 7000 --reload
```

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn api:app --port 7000 --reload
```

Optional environment variables (defaults shown):

```bash
ISSUER=http://localhost:8080/realms/demo
AUDIENCE=notes-api
```

---

## 4. Start the LeetCode-style app — terminal B (port 8000)

### bash

```bash
source .venv/bin/activate
CLIENT_ID=leetcode-app \
CLIENT_SECRET=leetcode-secret \
PORT=8000 \
APP_NAME=leetcode \
uvicorn leetcode_app:app --port 8000 --reload
```

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
$env:CLIENT_ID="leetcode-app"
$env:CLIENT_SECRET="leetcode-secret"
$env:PORT="8000"
$env:APP_NAME="leetcode"
uvicorn leetcode_app:app --port 8000 --reload
```

Optional app variables (defaults shown):

```bash
ISSUER=http://localhost:8080/realms/demo
IDP_HINT=google
API_BASE_URL=http://localhost:7000
```

`IDP_HINT` is the Keycloak broker IdP alias. It is added to the authorization
request as `kc_idp_hint=google`, so clicking **Sign in with Google** skips the
broker’s own login page and goes straight to the simulated Google realm.

---

## 5. Open the lab

| What | URL |
| --- | --- |
| LeetCode app | <http://localhost:8000> |
| Notes API | <http://localhost:7000/public> |
| Keycloak admin | <http://localhost:8080> (`admin` / `admin`) |

Users live in the **simulated Google realm**, not in the broker realm:

| User | Password | Google roles | Broker roles after mapping |
| --- | --- | --- | --- |
| `alice` | `alice123` | `admin`, `viewer` | `admin`, `viewer` |
| `bob` | `bob123` | `viewer` | `viewer` |

On the first successful Google login, Keycloak creates a local broker user with
the same username/email and maps the roles through the IdP mappers. The Google
realm remains the source of truth for authentication.

---

## Manual test checklist

### Brokered login

- [ ] Open <http://localhost:8000>. You see **Sign in with Google** and no local
      password form.
- [ ] Click it. The browser lands on the **simulated Google realm** login page
      (`/realms/google/...`), not on the broker realm’s username/password form.
- [ ] Sign in as `alice` / `alice123`.
- [ ] You return to the app already logged in.
- [ ] The page shows `alice@gmail.com`, roles `admin` + `viewer`, and the broker
      issuer `http://localhost:8080/realms/demo`.
- [ ] The ID token’s `iss` is **`demo`**, not `google`. The app never received a
      Google token.
- [ ] The access token has `aud=notes-api`, `scope` contains `notes.read`, and
      `realm_access.roles` contains the mapped roles.

### API authorization

- [ ] **API /public** → `200`.
- [ ] **API /notes** → `200` (scope `notes.read`).
- [ ] **API /admin** → `200` (Alice is an admin).
- [ ] As Bob: `/notes` → `200`, `/admin` → `403 insufficient_scope`.

### Refresh

- [ ] Click **Refresh token**. The page shows old vs new access-token expiry and
      refresh-token rotation.
- [ ] `/notes` still works with the new access token.

### Logout vs Google

- [ ] Click **Logout**. The app’s session is cleared and the broker realm’s SSO
      session ends.
- [ ] The **simulated Google session is not ended**. This is realistic: logging
      out of LeetCode does not log you out of Google.
- [ ] Click **Sign in with Google** again. Because the Google session still
      exists, you may be signed back in silently without a password.
- [ ] To see the Google password form again, use a private/incognito window
      (fresh cookies) or restart Keycloak with `docker compose ... down` and
      `up`. The Google SSO session is a browser cookie, so a new browser profile
      has none.

### Missing / tampered tokens

- [ ] `curl -i http://localhost:7000/notes` → `401 invalid_token`.
- [ ] Copy the access token from the app home page, then:

      ```bash
      TOKEN='paste-access-token-here'
      curl -i -H "Authorization: Bearer $TOKEN" http://localhost:7000/notes
      TAMPERED="${TOKEN%?}X"
      curl -i -H "Authorization: Bearer $TAMPERED" http://localhost:7000/notes
      ```

      Valid token → `200`; tampered token → `401` (bad signature).
- [ ] Send the **ID token** to the API instead: `401` bad audience (`aud` is
      `leetcode-app`, not `notes-api`).

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Connection refused` on `:8080` | Keycloak is still booting (20–60 s on first start). Wait for the “Listening on” log. |
| `invalid_redirect_uri` | Use `localhost`, port 8000, path `/callback`. The Google realm client must also allow `http://localhost:8080/realms/demo/broker/google/endpoint`. |
| First login shows Keycloak’s **Review Profile** page | It normally skips because the Google user has first/last name, email, and verified email. If you remove any of those claims, Keycloak may ask once. Fill it in and continue. |
| Broker login fails with `cookie_not_found` in curl/httpx | Keycloak marks its auth cookies `Secure`. Browsers allow that on `http://localhost`; minimal HTTP clients do not. Use a browser. |
| Google roles missing in the app | Check the broker IdP mappers `google-admin-to-admin` and `google-viewer-to-viewer`. After changing Google roles, log out of both realms (or recreate the brokered user) and log in again. |
| Logout ends on a Google logout `400` page | The IdP must not have a `logoutUrl` set, otherwise Keycloak tries to propagate logout to the upstream Google realm. This lab intentionally omits it. |
| Realm edits do not appear | `docker compose ... down` then `up` re-imports both realms. |
| App restarted / `state` mismatch | The app’s sessions are in memory and are lost on restart. Log in again. |
| API `401 invalid_token` | Token expired (5 min), Keycloak was recreated (new signing keys), or the issuer/audience changed. Log in again; check the API terminal for the exact reason. |

---

## Security notes (why this is a lab, not production)

- HTTP on localhost, client secrets in environment variables, tokens rendered
  into HTML for learning.
- In-memory sessions; production needs shared/persistent storage.
- The broker trusts the simulated Google realm over plain HTTP. Production
  brokering requires HTTPS, strict issuer/audience/JWKS validation, and secret
  rotation.
- Logout propagation upstream is intentionally disabled. Real systems must
  decide whether “logout of the app” should also end the social/enterprise IdP
  session (and implement back-channel/front-channel logout where needed).
- Role mapping happens at first broker login and on updates; production should
  also consider de-provisioning, group mapping, and token revocation.
