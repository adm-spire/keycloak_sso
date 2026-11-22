# Starting the Broker Lab

Exact commands for the Keycloak-broker + simulated-Google setup. Use **three
terminals** and keep them open.

Project root: `sso-lab/` (the directory containing this file).

- Terminal 1: Keycloak (broker realm `demo` + simulated Google realm `google`)
- Terminal 2: notes API (`api.py`, port 7000)
- Terminal 3: LeetCode-style app (`leetcode_app.py`, port 8000)

> Use `http://localhost:...` everywhere. Do **not** use `127.0.0.1`; the realms,
> redirect URIs, issuers, and cookies are configured for `localhost`.

---

## Prerequisites

- Docker Engine + Docker Compose v2 (`docker compose ...`)
- Python 3.11 or newer

All commands below assume your shell is in the `sso-lab/` directory:

```bash
cd /home/raunaq/Desktop/sso_project/sso-lab
```

PowerShell:

```powershell
cd C:\path\to\sso-lab
```

---

## Terminal 1 — Start Keycloak

### bash / macOS / Linux / WSL

```bash
cd /home/raunaq/Desktop/sso_project/sso-lab
docker compose -f keycloak/docker-compose.yml up
```

### Windows PowerShell

```powershell
cd C:\path\to\sso-lab
docker compose -f keycloak/docker-compose.yml up
```

Wait until the log shows:

```
Listening on: http://0.0.0.0:8080
```

Verify:

- Broker realm: <http://localhost:8080/realms/demo/.well-known/openid-configuration>
- Simulated Google realm: <http://localhost:8080/realms/google/.well-known/openid-configuration>
- Admin console: <http://localhost:8080> — `admin` / `admin`

Leave this terminal running. Press `Ctrl+C` to stop Keycloak.

---

## Terminal 2 — Create the Python environment and start the API

### bash

```bash
cd /home/raunaq/Desktop/sso_project/sso-lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

uvicorn api:app --port 7000 --reload
```

### Windows PowerShell

```powershell
cd C:\path\to\sso-lab
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

uvicorn api:app --port 7000 --reload
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Verify: <http://localhost:7000/public> returns JSON. Leave this terminal running.

---

## Terminal 3 — Start the LeetCode-style app

The virtual environment already exists, so just activate it.

### bash

```bash
cd /home/raunaq/Desktop/sso_project/sso-lab
source .venv/bin/activate

CLIENT_ID=leetcode-app \
CLIENT_SECRET=leetcode-secret \
PORT=8000 \
APP_NAME=leetcode \
IDP_HINT=google \
uvicorn leetcode_app:app --port 8000 --reload
```

### Windows PowerShell

```powershell
cd C:\path\to\sso-lab
.\.venv\Scripts\Activate.ps1

$env:CLIENT_ID="leetcode-app"
$env:CLIENT_SECRET="leetcode-secret"
$env:PORT="8000"
$env:APP_NAME="leetcode"
$env:IDP_HINT="google"
uvicorn leetcode_app:app --port 8000 --reload
```

Verify: <http://localhost:8000> shows the app with a **Sign in with Google**
button.

---

## Open the lab

| What | URL |
| --- | --- |
| LeetCode-style app | <http://localhost:8000> |
| Notes API | <http://localhost:7000/public> |
| Keycloak admin | <http://localhost:8080> (`admin` / `admin`) |

Users are in the **simulated Google realm**:

| User | Password | Google roles | Broker roles after mapping |
| --- | --- | --- | --- |
| `alice` | `alice123` | `admin`, `viewer` | `admin`, `viewer` |
| `bob` | `bob123` | `viewer` | `viewer` |

Click **Sign in with Google** on the app, then use one of the users above on the
Google realm login page. On first login, Keycloak creates the local broker user
and maps the roles automatically.

---

## Optional environment variables

Defaults are shown. Set these before the `uvicorn` command if you need to change
them.

### API

```bash
ISSUER=http://localhost:8080/realms/demo
AUDIENCE=notes-api
```

### App

```bash
ISSUER=http://localhost:8080/realms/demo
IDP_HINT=google
API_BASE_URL=http://localhost:7000
```

`IDP_HINT` is the identity-provider alias in the broker realm. It becomes the
`kc_idp_hint=google` authorization parameter, which skips the broker’s login page
and goes straight to the simulated Google login.

---

## Stop everything

- Keycloak: press `Ctrl+C` in Terminal 1, then optionally remove the container:

  ```bash
  docker compose -f keycloak/docker-compose.yml down
  ```

- API and app: press `Ctrl+C` in Terminals 2 and 3.

### Re-import the realms after editing JSON

The realms are imported only when they do not already exist. The dev-mode
database lives inside the container, so recreate it to pick up changes:

```bash
docker compose -f keycloak/docker-compose.yml down
docker compose -f keycloak/docker-compose.yml up
```

---

## Quick troubleshooting

| Symptom | Fix |
| --- | --- |
| Keycloak connection refused on `:8080` | Wait for `Listening on: http://0.0.0.0:8080`; first boot takes 20–60 s. |
| `invalid_redirect_uri` | Use `localhost`, port 8000, path `/callback`. Also keep the Google client redirect at `http://localhost:8080/realms/demo/broker/google/endpoint`. |
| First login shows a Review Profile page | Normally skipped when the Google user has first/last name, email, and verified email. Fill it in once if it appears. |
| Roles missing after login | Check broker IdP mappers `google-admin-to-admin` / `google-viewer-to-viewer`. Log out of both realms or recreate the brokered user, then log in again. |
| Logout ends on a Google logout error | The IdP must not set `logoutUrl`; this lab intentionally omits it so logging out of the app does not end the Google session. |
| Realm changes do not appear | Run `docker compose ... down` then `up` to re-import. |
| App restarted / `state` mismatch | In-memory sessions were lost. Log in again. |
| PowerShell cannot activate `.venv` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal. |

For the full flow and security explanations, see `docs/broker-walkthrough.md`.
