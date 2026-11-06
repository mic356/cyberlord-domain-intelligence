# CyberLord Domain Intelligence — A32 Upgrade

A Flask-based cybersecurity intelligence workspace for **authorised defensive assessments**. This package preserves the existing Flask project structure and upgrades authentication, account gating, phone/email intelligence, security headers, reporting guidance and deployment configuration.

## Included capabilities

- Login-first experience: unauthenticated visitors are redirected to `/login`; successful sign-in/registration opens the dashboard; logout clears the session.
- Account creation and secure password hashing (Werkzeug), minimum 12-character passwords, HTTP-only session cookies, seven-day session lifetime and session renewal on authentication.
- Domain posture scan: public DNS, public IP resolution, TLS certificate metadata, HTTP response headers and baseline security-header findings.
- Premium modules: Certificate Transparency subdomain discovery, SPF/DMARC/common-selector DKIM and MX checks, public IP network metadata, NIST NVD CVE lookup, DNS intelligence, passive technology signals, domain comparison and limited common TCP connect checks.
- Phone-number metadata using libphonenumber: validation, numbering region/type and available carrier hints. No live location tracking, subscriber identity lookup, call interception or private records.
- Scan history and per-user JSON report downloads with timestamps, score, findings and recommendations.
- Premium access is enforced by server-side decorators. Bybit Pay checkout is retained and activates Premium only after a signed, timestamp-checked webhook matching a pending order. Paystack remains in place until a final Bybit merchant configuration is verified; do not remove it prematurely.
- Production response security headers and environment-based secrets.

## Local setup

1. Use Python 3.11+.
2. Install dependencies: `pip install -r requirements.txt`.
3. Set a persistent secret: `FLASK_SECRET_KEY` (at least 32 random characters).
4. Run `python app.py` and visit `http://127.0.0.1:5000/login`.

Example secret generation: `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

## Render deployment

The included `render.yaml` retains the persistent disk and database path. Deploy the existing project folder and preserve the current Render service/database. Configure `FLASK_SECRET_KEY` and `COOKIE_SECURE=1`. Keep provider credentials in Render environment variables only. The Render blueprint generates the Flask secret if not already set.

## Payment configuration and verification

- Bybit Pay requires an approved Bybit Pay merchant integration and the server variables listed in `render.yaml`. A regular Bybit account or wallet address is not sufficient for API checkout.
- Premium is not activated by a browser redirect, client-side state, screenshot, or user-submitted transaction reference. Only the signed Bybit callback can activate it.
- Paystack is retained as a fallback because the request explicitly says to remove it only after the final payment configuration has been confirmed. Test the chosen provider end-to-end before disabling the other integration.
- Never commit API keys, private keys, payment secrets, or `.env` files.

## Responsible-use boundaries

Use domain and IP features only for assets you own or have explicit authorisation to assess. The common-port module is a restrained TCP-connect check, not a full Nmap workflow. It requires an explicit authorisation confirmation in the request. No exploit execution, brute force, credential attacks, stealth, or persistence features are included. Kali Linux tooling is not bundled or remotely invoked; integrate only within a controlled lab or authorised environment and maintain written scope/approval.

Email analysis checks public DNS authentication records; it does not log in to mailboxes or claim access to private breach records. DKIM is selector-specific, so an empty `default` selector is inconclusive. Phone analysis reports numbering metadata only and cannot establish scam activity or identify a subscriber.

## Important production work still required

This is an upgraded source package, not a security-audited commercial SaaS. Before public launch, add CSRF protection for cookie-authenticated state-changing routes, distributed rate limiting and login lockout, verified email/password reset, database migrations/backups, monitoring, privacy/retention controls, provider-specific payment reconciliation, and an independent security review. SQLite is intended for a single-instance pilot; use managed PostgreSQL for multi-instance production.

## Test checklist

- [ ] `/` redirects to `/login` when signed out.
- [ ] Registration rejects malformed email and passwords shorter than 12 characters.
- [ ] Login works, authenticated `/` loads, and logout returns to `/login`.
- [ ] API routes reject unauthenticated users; Premium routes reject non-Premium users.
- [ ] Domain scan works for an authorised public test domain.
- [ ] Email-domain MX/SPF/DMARC/DKIM record lookup works.
- [ ] Phone-number validation works for valid international test numbers.
- [ ] JSON report downloads are limited to the owning account.
- [ ] Payment activation occurs only after provider-side verification.
- [ ] Test desktop/mobile layouts and Render deployment with the production environment variables.
