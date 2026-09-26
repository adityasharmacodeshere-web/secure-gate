# SecureGate

SecureGate is a runnable password-safety demo: the browser hashes a password with Web Crypto before any network request, checks the SHA-1 prefix through a FastAPI proxy to Have I Been Pwned, and rejects breached passwords in signup and reset flows.

> **Demo, not a production certification.** The project intentionally demonstrates a privacy-preserving design. Before production, add a managed database, distributed rate limiting, identity verification, secret management, observability controls, CSRF/session protection, and an independent security review.

## Architecture and privacy contract

```text
Browser -- SHA-1(password), local suffix comparison --> FastAPI -- 5-char prefix + Add-Padding: true --> HIBP
   |                                                        |
   +-- client-derived verifier only --> FastAPI             +-- Argon2id verifier storage
```

* `crypto.subtle.digest("SHA-1")` runs before the breach request. The browser sends only the first five uppercase hexadecimal characters to `/api/password/check`; the suffix stays in the browser and is compared against the padded HIBP response.
* The backend never receives, stores, or logs raw passwords or full password hashes. Signup/reset sends a browser-derived verifier (SHA-256 over a domain-separated password value); the backend Argon2id-hashes that verifier for the demo account.
* The HIBP proxy uses `Add-Padding: true`, strict timeouts, redacted structured logging, and returns only the padded suffix/count pairs needed by the browser.
* No real customer or admin data is included. Metrics are synthetic and explicitly labelled.

## Quick start

### Local development

Requirements: Node 20+, Python 3.11+.

```powershell
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
cd frontend
npm install
npm run dev
```

Run the API separately with `uvicorn app.main:app --reload --port 8000` from `backend`. Vite proxies `/api` to `http://localhost:8000`.

### Docker Compose

```powershell
docker compose up --build
```

The frontend is available at `http://localhost:4173` and the API at `http://localhost:8000`.

## API

* `GET /health` returns service and database availability.
* `POST /api/password/check` accepts `{ "prefix": "ABCDE" }` and returns `{ "suffixes": [{"suffix": "...", "count": 1}], "source": "hibp" }`. The caller compares its locally-held suffix.
* `POST /api/accounts/signup` and `POST /api/accounts/reset` accept `{ "email": "...", "verifier": "..." }`. `verifier` is a client-derived value, never a raw password. Responses are generic to reduce account enumeration.
* `GET /api/admin/metrics` returns synthetic security metrics only and requires `X-Demo-Admin: <ADMIN_TOKEN>`.

## Configuration and deployment

Copy `.env.example` to `.env`. `DATABASE_URL` supports SQLite (`sqlite:///./securegate.db`) and PostgreSQL (`postgresql+psycopg://...`). Set `CORS_ORIGINS` to explicit origins, `ADMIN_TOKEN` to a real secret, and `HIBP_API_URL` only for a trusted compatible endpoint. The development rate limiter is process-local and is not sufficient for multiple replicas; use a gateway or shared store in production.

The Docker image runs as a non-root user and uses a health check. Put TLS termination, a secrets manager, a managed PostgreSQL instance, and a distributed limiter in front of it.

## Threat model and limitations

This design reduces password exposure to the backend and to HIBP, but cannot protect a compromised browser, malicious extensions, an XSS vulnerability, a compromised dependency, or a user who reuses a password elsewhere. SHA-1 is used only because the HIBP range protocol requires it; it is not used as a password storage algorithm. The demo verifier is a transport-safe proof, not a complete authentication protocol. Add WebAuthn/strong identity proofing, session management, email reset tokens, audit controls, and key rotation before production.

## Tests

```powershell
cd backend
pytest -q
cd ..\frontend
npm run build
```

The backend tests cover k-anonymity request construction, padded response parsing, and the no-secret-logging contract.
