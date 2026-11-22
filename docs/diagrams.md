# Broker Lab — Diagrams

Mermaid diagrams for the Keycloak-broker + simulated-Google setup. They render on
GitHub/GitLab and in editors with Mermaid support.

---

## 1. Architecture

```mermaid
flowchart LR
    U["User's browser<br/>cookies only"]

    subgraph KC["Keycloak 26 :8080"]
        BROKER["Broker realm demo<br/>client leetcode-app<br/>IdP alias google<br/>local linked users + roles"]
        GOOGLE["Simulated Google realm google<br/>users alice/bob<br/>login page + roles"]
        BROKER -->|"keycloak-oidc brokering"| GOOGLE
    end

    A["LeetCode-style app :8000<br/>leetcode_app.py<br/>server-side session"]
    API["notes API :7000<br/>api.py<br/>JWT validation + scope/role checks"]

    U -->|"1. click Sign in with Google"| A
    A -->|"2. 302 to demo /auth<br/>kc_idp_hint=google<br/>state, nonce, PKCE"| BROKER
    BROKER -->|"3. 302 to google /auth"| U
    U -->|"4. Google login form"| GOOGLE
    GOOGLE -->|"5. redirect code"| BROKER
    BROKER -->|"6. create/link user<br/>map roles"| BROKER
    BROKER -->|"7. 302 to app /callback?code"| A
    A -->|"8. POST /token<br/>code + verifier + secret"| BROKER
    BROKER -->|"9. tokens issued by demo"| A
    A -->|"10. Bearer access token"| API
    API -->|"11. JWKS (demo)"| BROKER
```

The app trusts **only** the broker realm (`demo`). It never sees the Google
realm's tokens. The broker realm is the only IdP the app needs to know about.

---

## 2. Direct IdP vs brokered IdP

```mermaid
flowchart TB
    subgraph DIRECT["Direct integration (no broker)"]
        A1["App"] -->|"trusts"| G1["Google / Entra ID"]
    end

    subgraph BROKERED["Brokered integration (this lab)"]
        A2["App"] -->|"trusts"| K["Keycloak broker"]
        K -->|"trusts / federates"| G2["Google / Entra ID"]
    end
```

Brokering lets one app trust a single IdP (Keycloak) while Keycloak handles many
upstream providers. It also centralizes role mapping, user linking, and policy.

---

## 3. Brokered login sequence

```mermaid
sequenceDiagram
    autonumber
    actor U as User (Browser)
    participant A as LeetCode app (8000)
    participant KB as Keycloak broker demo (8080)
    participant KG as Simulated Google google (8080)
    participant API as notes API (7000)

    U->>A: Click Sign in with Google
    Note over A: Authlib generates state, nonce, code_verifier
    A-->>U: 302 demo /auth?kc_idp_hint=google<br/>&state&nonce&code_challenge=S256
    U->>KB: GET broker authorization endpoint
    Note over KB: kc_idp_hint selects the google IdP<br/>skip the broker's local login page
    KB-->>U: 302 google /auth<br/>(broker client leetcode-broker)
    U->>KG: GET Google authorization endpoint
    KG-->>U: Simulated Google login page
    U->>KG: alice / alice123
    KG-->>U: 302 demo /broker/google/endpoint?code
    U->>KB: GET broker callback
    KB->>KG: POST /token (broker client secret + code)
    KG-->>KB: Google ID/access token
    Note over KB: Create or link local demo user<br/>Map Google roles to demo roles
    KB-->>U: 302 app /callback?code&state
    U->>A: GET /callback?code&state
    Note over A: Validate state (CSRF), remove it (single use)
    A->>KB: POST /token<br/>code + redirect_uri + client_secret + code_verifier
    Note over KB: Validate client, one-time code, exact redirect URI, PKCE
    KB-->>A: ID/access/refresh tokens issued by demo
    Note over A: Validate ID token: signature, iss=demo,<br/>aud=leetcode-app, nonce, exp<br/>Store tokens server-side
    A-->>U: 303 / (cookie has only session id)
    U->>A: GET /
    A-->>U: Logged in as alice@gmail.com, roles admin/viewer
    A->>API: GET /notes Authorization: Bearer access_token
    Note over API: Verify RS256/iss=demo/aud=notes-api<br/>Check scope notes.read
    API-->>A: 200 notes for the token's sub
```

---

## 4. Role mapping from Google to the broker

```mermaid
flowchart LR
    GU["Google user alice<br/>realm_access.roles = admin, viewer"]
    GT["Google access token<br/>issued by realm google"]
    KB["Keycloak broker demo<br/>IdP mappers"]
    LU["Local demo user alice<br/>roles admin, viewer"]
    DT["Demo access token<br/>realm_access.roles = admin, viewer"]

    GU --> GT
    GT -->|"validated access token"| KB
    KB -->|"keycloak-oidc-role-to-role-idp-mapper<br/>external.role=admin -> role=admin"| LU
    KB -->|"keycloak-oidc-role-to-role-idp-mapper<br/>external.role=viewer -> role=viewer"| LU
    LU --> DT
```

The app receives the demo token, so it sees `realm_access.roles` as mapped by
Keycloak. The Google realm remains the source of authentication and role
assignment; the broker owns the local authorization model.

---

## 5. Logout: broker session vs Google session

```mermaid
sequenceDiagram
    autonumber
    actor U as User (Browser)
    participant A as LeetCode app (8000)
    participant KB as Keycloak broker demo (8080)
    participant KG as Simulated Google google (8080)

    U->>A: GET /logout
    Note over A: Clear local session and expire app cookie
    A-->>U: 303 broker end_session_endpoint<br/>?id_token_hint=...&post_logout_redirect_uri=...
    U->>KB: GET broker logout
    Note over KB: Validate id_token_hint + redirect URI<br/>End broker SSO session and cookies
    KB-->>U: 302 app home?state=...
    U->>A: GET / (logged out)

    Note over KG: Google SSO session is NOT ended<br/>(IdP has no logoutUrl configured)
    U->>A: Click Sign in with Google again
    A->>KB: Authorization request (kc_idp_hint=google)
    KB->>KG: Broker authorization request
    Note over KG: Google session cookie still valid
    KG-->>KB: Silent re-authentication (no password)
    KB-->>A: code
    A-->>U: Logged in again (silent)
```

This mirrors the real world: logging out of LeetCode does not log you out of
Google. If you want “log out everywhere”, you must also invoke the upstream
IdP’s logout and handle its redirect URI; that is deliberately out of scope here.

---

## 6. API token validation and 401 vs 403

```mermaid
flowchart TD
    R["Request to an API endpoint"] --> H{"Authorization header<br/>Bearer token present?"}
    H -- No --> E401["401 invalid_token<br/>WWW-Authenticate: Bearer error='invalid_token'"]
    H -- Yes --> S{"Signature valid?<br/>RS256 + demo realm JWKS"}
    S -- No --> E401
    S -- Yes --> I{"iss == demo realm issuer?"}
    I -- No --> E401
    I -- Yes --> A{"aud contains 'notes-api'?"}
    A -- No --> E401
    A -- Yes --> X{"exp / iat valid?<br/>within leeway"}
    X -- No --> E401
    X -- Yes --> C{"Required claims present?<br/>exp, iat, iss, aud, sub"}
    C -- No --> E401
    C -- Yes --> P{"Endpoint authorization"}

    P -->|"/public"| OK["200 OK"]
    P -->|"/notes"| SC{"scope contains notes.read?"}
    P -->|"/admin"| RL{"realm_access.roles contains admin?"}
    SC -- No --> E403["403 insufficient_scope<br/>WWW-Authenticate: Bearer error='insufficient_scope'"]
    RL -- No --> E403
    SC -- Yes --> OK
    RL -- Yes --> OK
```

**401** = authentication failed (missing, expired, bad signature, wrong issuer,
wrong audience). **403** = authentication succeeded but the valid token lacks the
required scope or role.

---

## 7. Where tokens and sessions live

```mermaid
flowchart LR
    subgraph Browser
        C["Cookies:<br/>leetcode_session<br/>demo broker SSO cookies<br/>google SSO cookies"]
    end

    subgraph App["LeetCode app process"]
        S[("SESSIONS dict<br/>session id -> demo tokens")]
    end

    subgraph KC["Keycloak"]
        KB[("demo broker:<br/>linked users, roles,<br/>SSO sessions, signing keys")]
        KG[("google:<br/>source users, roles,<br/>SSO sessions, signing keys")]
    end

    subgraph API["notes API"]
        J["JWKS cache (demo)<br/>no user sessions"]
    end

    C -->|"only opaque session id"| S
    S -->|"demo access token as Bearer"| J
    KB -->|"demo public keys via JWKS"| J
    KB -->|"broker tokens"| S
    KG -->|"Google tokens"| KB
```

- The browser holds only cookies, never app tokens.
- The app stores **demo-issued** tokens server-side.
- The Google realm's tokens stay inside Keycloak's brokering logic.
- The API is stateless: it caches the **demo** realm’s public keys and validates
  tokens locally.
