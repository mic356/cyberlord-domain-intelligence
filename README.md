# CyberLord Domain Intelligence — Ultimate Edition

A browser-based, dark-neon cybersecurity intelligence workspace. It is designed for passive reconnaissance and authorised defensive assessments. It does **not** exploit targets, brute-force credentials, or run intrusive port scans.

## Included modules
- Domain security scan: public DNS records, public IP resolution, TLS certificate metadata, HTTP response headers, cookies and basic security-header findings.
- Certificate Transparency subdomain discovery (crt.sh).
- SPF, DMARC and common-selector DKIM TXT checks.
- Public IP geolocation/network metadata (ipwho.is).
- CVE search using the NIST NVD API.
- Two-domain posture comparison.
- Account registration/login, saved scan history and downloadable JSON reports.
- Paystack Premium checkout at **₦5,000**, with server-side transaction verification and webhook confirmation.

## Local setup
1. Install Python 3.11 or newer.
2. Create a virtual environment and install requirements:
   `python -m venv .venv`
   `source .venv/bin/activate` (Windows: `.venv\\Scripts\\activate`)
   `pip install -r requirements.txt`
3. Set a strong `FLASK_SECRET_KEY` environment variable.
4. Run: `python app.py`
5. Open `http://127.0.0.1:5000`.

## Render deployment
1. Push this folder to a private or public GitHub repository (never commit `.env`, keys, or database files).
2. Create a Render Web Service from the repository. The included `render.yaml` defines the service and persistent disk.
3. Set `PAYSTACK_SECRET_KEY` to your **test** secret key first. Set a long random `FLASK_SECRET_KEY` if not using Render's generated value.
4. Deploy and copy the public service URL.
5. In Paystack Dashboard → Settings → API Keys & Webhooks, add webhook URL:
   `https://YOUR-RENDER-DOMAIN/api/paystack/webhook`
6. Test the checkout with Paystack test mode. The app grants Premium only after server-side verification of the saved reference, email, exact amount (500000 kobo) and NGN currency.
7. Only after successful tests and Paystack business approval, switch to live credentials.

## Environment variables
- `FLASK_SECRET_KEY` — strong random session-signing secret; mandatory for production.
- `PAYSTACK_SECRET_KEY` — Paystack test or live secret key. Never expose it in browser JavaScript or GitHub.
- `PAYMENTS_DB` — SQLite path. Use persistent storage in production (Render blueprint uses `/var/data/cyberlord.db`).
- `COOKIE_SECURE=1` — enable secure session cookies behind HTTPS.
- `TON_WALLET_ADDRESS` — optional public receiving address displayed nowhere by default in this edition; configure only if you later add a separately verified TON payment workflow.

## Important payment notes
- The OPay card number shared in chat is deliberately **not** stored or used. Never put card PAN, expiry, CVV or PIN in application source. If a full card number was exposed, freeze/block that card in OPay and request a replacement.
- Paystack collects customer card/bank details on its hosted checkout. Configure the eligible settlement bank/account in Paystack's dashboard; do not assume an OPay card number is a settlement account. Confirm OPay account eligibility with Paystack.
- TON wallet transfers are not automatically verified in this version. A wallet address on its own is not proof of payment. Do not grant Premium based only on a user-entered transaction hash; add a verified TON blockchain/indexer integration before enabling that flow.

## Security and production checklist
- Add email verification, password reset, CSRF protection, per-user and per-IP rate limits, audit logging, admin support tooling and automated backups before public commercial launch.
- Use a managed database for multi-instance production deployments; SQLite is suitable for a small single-instance pilot only.
- Review provider terms and privacy requirements before sending customer IP/domain data to third-party intelligence providers.
- Only scan domains and IPs you own or have explicit permission to assess. Results are indicators, not a full penetration test or compliance certification.
- This starter release is a functional foundation, not a fully audited commercial SaaS. Have a security professional review it before accepting live customer payments.


## Updated release notes

- Login and registration sessions are permanent browser sessions with a seven-day lifetime, refreshed while the user remains active. Signing out clears the session.
- Login and registration buttons show an animated spinner, disable while requests are in progress, and display success/error messages.
- Added premium DNS record intelligence, passive technology fingerprinting, and a limited common TCP port check (only for systems the user owns or is authorised to assess).
- Existing domain scanner includes TLS/certificate and HTTP security-header analysis; existing modules include subdomain discovery, email authentication, IP intelligence, CVE lookup, domain comparison and scan history.
- Added an optional Bybit Pay USDT checkout integration. It requires a **Bybit Pay merchant account/onboarding**, a Bybit Pay API key/secret, merchant ID, a chosen USDT price, and Bybit's official webhook public key. A normal personal Bybit account or wallet address alone does not provide merchant checkout API access. The webhook signature is verified server-side before Premium is activated.
- Paystack remains available as a separate hosted checkout option.

### Required Render environment variables for Bybit Pay

Configure these in Render only after Bybit approves/provisions your merchant integration:

- `BYBIT_PAY_API_KEY` — system-generated HMAC API key for Bybit Pay.
- `BYBIT_PAY_API_SECRET` — matching API secret. Keep it private.
- `BYBIT_MERCHANT_ID` — merchant UID provided by Bybit.
- `BYBIT_PREMIUM_PRICE_USDT` — the USDT price you decide to charge (for example, set a price only after deciding it).
- `BYBIT_PAY_PLATFORM_PUBLIC_KEY` — official Bybit Pay platform public key used to verify payment callbacks.
- `BYBIT_PAY_BASE_URL` — mainnet API base URL; defaults to `https://api2.bybit.com`. Use the testnet URL supplied by Bybit for sandbox testing.
- `BYBIT_MERCHANT_NAME` — optional display name.

Webhook URL to register with Bybit Pay:
`https://cyberlord-domain-intelligence.onrender.com/api/bybit/webhook`

Do not paste API secrets or private keys into source code, GitHub, or ChatGPT. Never use a screenshot, manually supplied transaction ID, or a user-controlled redirect as proof of payment. Only a verified signed Bybit webhook can grant Premium.

### Important deployment note

This ZIP is the updated source code, not an already-deployed update. Upload the changed files to the existing GitHub repository and let Render deploy them. Keep your current Render environment variables and persistent disk. Do not delete the existing service or database.


## Subscription plans (monthly)

- Free: ₦0, no expiry.
- Premium: ₦5,000 / 30 days (configurable with `PREMIUM_PRICE_NGN`).
- Professional: ₦10,000 / 30 days (configurable with `PROFESSIONAL_PRICE_NGN`).

Paystack amounts are set and checked on the server in kobo. A successful transaction is tied to the signed-in account and grants a 30-day entitlement. Repeated verification/webhook delivery does not extend an already processed transaction. Existing entitlement rows are migrated to a 30-day expiry based on their original `updated_at`.

Phone intelligence validates international numbering-plan data and displays available public metadata; it does not prove number ownership. Actual SMS OTP ownership checks require a configured SMS gateway and are not enabled by this release. Individual email intelligence accepts any syntactically valid domain and checks public DNS mail configuration; it does not verify mailbox existence.
