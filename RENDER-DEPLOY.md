# CyberLord A32 — Render deployment

## Important: upload the contents of this ZIP to the repository root

The repository root must contain `app.py`, `requirements.txt`, `render.yaml`, `Procfile`, `runtime.txt`, and the `templates/` and `static/` folders. Do not leave these files inside an extra `cyberlord-ultimate/` folder.

Expected layout:

```text
app.py
requirements.txt
render.yaml
Procfile
runtime.txt
README.md
templates/
  login.html
  index.html
  payment_result.html
static/
  style.css
  app.js
```

## Deploy on your existing Render service

1. Open Render Dashboard and select `cyberlord-domain-intelligence`.
2. In Settings, confirm the connected GitHub repository and the branch being deployed.
3. Set **Root Directory** to blank (repository root), unless you intentionally put all app files in a subfolder.
4. Set **Build Command** to `pip install -r requirements.txt`.
5. Set **Start Command** to `gunicorn app:app --workers 2 --threads 4 --timeout 120`.
6. In Environment, ensure `FLASK_SECRET_KEY` exists and has a strong random value. Never publish it.
7. Deploy the latest commit and open `/login`.

## Important notes

- The `render.yaml` blueprint included here provisions a Starter web service with a persistent disk. Do not use Blueprint Sync on an existing service unless you intend to create/update infrastructure. For an existing service, apply the Build Command and Start Command manually in its Settings.
- Payment integrations remain inactive until the corresponding private merchant credentials are configured in Render Environment. Never put API secrets in GitHub.
- If the page is still blank, check Render Logs and the deployed commit. Confirm that `templates/login.html` is present in the deployed repository under the root `templates/` directory.
