# PhishGuard Cloud

PhishGuard Cloud is a Flask-based phishing URL analysis web application. It combines a rule-based URL risk engine with a locally stored scikit-learn model and provides user accounts, scan history, dashboards, and administrator controls.

> **Safety note:** PhishGuard is a defensive screening aid, not a guarantee that a URL is safe. A `SAFE` result does not prove a site is legitimate. Do not open suspicious links just to test them. The application analyzes URL text and does not visit the submitted website.

## Features

- URL syntax validation and heuristic risk scoring.
- ML classification using ten URL features (URL length, domain length, dots, hyphens, `@`, slashes, digits, HTTPS, IP-host flag, and suspicious-keyword count).
- Combined SAFE / SUSPICIOUS / PHISHING verdict.
- User registration and login with Werkzeug password hashing.
- User dashboard, scan history, and analytics.
- Admin dashboard, user controls, audit logs, threat alerts, and blocked-domain list.
- SQLite persistence.
- CSRF protection for state-changing requests, authentication rate limits, secure session-cookie settings, and basic HTTP security headers.

## Project structure

```text
PhishGuard-Cloud/
├── app.py                    # Local run entry point
├── wsgi.py                   # Gunicorn WSGI entry point
├── Procfile                  # Hosting start command
├── feature.py                # Public feature-extractor wrapper
├── requirements.txt
├── .env.example
├── backend/
│   ├── app.py                # Flask routes, database, auth, scan API
│   └── create_admin.py       # Interactive first-admin setup
├── ml/
│   ├── url_features.py       # Canonical URL feature extraction
│   ├── predict_url.py        # Model inference
│   ├── train_real_model.py   # Dataset training/evaluation
│   ├── download_real_dataset.py
│   └── models/               # Trained .pkl model files
├── database/                 # SQLite database is created at runtime
├── dataset/                  # Large training data is downloaded locally
├── notebooks/                # Model training walkthrough
├── templates/                # Jinja2 HTML pages
├── static/                   # CSS and JavaScript assets
└── tests/                    # Automated checks
```

## Requirements

- Python 3.11 or 3.12 recommended.
- pip.
- Internet connection only if you choose to download the training dataset.

The included model was serialized with scikit-learn 1.9.0. Keep the scikit-learn version in `requirements.txt` aligned with the model file; scikit-learn does not guarantee pickle compatibility across versions. Only load trusted model files.

## Run locally on macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Generate a secret key and put it in `.env` as `SECRET_KEY=...`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Then start the application:

```bash
python app.py
```

Open `http://127.0.0.1:5000`. The SQLite database is created automatically at `database/phishguard.db` unless `PHISHGUARD_DB_PATH` is set.

## Create the first administrator

Admin self-registration is disabled by default. In a second terminal (with the virtual environment active), run:

```bash
python backend/create_admin.py
```

Enter the administrator name, email, and a password of at least 12 characters when prompted. If web-based admin registration is deliberately required, set a long random `ADMIN_REGISTRATION_CODE` in the environment; never use a public/default code.

## Train the ML model

The training CSV is not bundled because it can be large. Download the UCI dataset and train the model:

```bash
python ml/download_real_dataset.py
python ml/train_real_model.py
```

The training script compares a Decision Tree and Logistic Regression using a held-out split, prints accuracy/precision/recall/F1 and a confusion matrix, then saves the model with the best F1 score to `ml/models/phishing_model_real.pkl`. The current bundled model can be used without downloading the dataset.

To run the notebook, install Jupyter separately if needed:

```bash
pip install notebook
jupyter notebook notebooks/PhishGuard_Model_Training.ipynb
```

## Tests

Run the included standard-library test suite:

```bash
python -m unittest discover -s tests -v
```

If Flask and Flask-Limiter are installed from `requirements.txt`, the suite also checks the Flask CSRF guard.

## Deployment (Gunicorn)

The included `Procfile` runs:

```bash
gunicorn --workers 2 --threads 4 --timeout 120 --bind 0.0.0.0:$PORT wsgi:app
```

For a production deployment:

1. Set `SECRET_KEY` to a unique random value.
2. Set `PRODUCTION=1` and `SESSION_COOKIE_SECURE=1` behind HTTPS.
3. Set `PHISHGUARD_DB_PATH` to a persistent disk path provided by your host. SQLite on an ephemeral filesystem can be lost during redeploys.
4. Keep `ADMIN_REGISTRATION_CODE` unset unless you explicitly need admin self-registration.
5. Set `RATELIMIT_STORAGE_URI` to a shared Redis URL when running multiple workers/instances; the default in-memory limiter is suitable only for local/single-instance use.
6. Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM` before relying on password-reset emails. Without SMTP, links are printed only in local development; they are not exposed in production logs.
7. Use a trusted, version-matched model file and protect access to the server and database.

## Security and limitations

- Passwords are stored as Werkzeug password hashes, not plaintext.
- All POST/PUT/PATCH/DELETE requests require a session-bound CSRF token.
- Login and registration endpoints are rate-limited.
- The scanner uses lexical URL features and heuristic rules; it does not check live DNS, TLS certificates, page content, redirects, or commercial threat-intelligence feeds.
- Model probabilities are model scores, not a promise of real-world detection accuracy. Evaluate against a recent, representative dataset before making security decisions.
- The SQLite database contains account and scan-history data. Do not commit it or share it publicly.

## License

Add the license required by your dataset and project distribution before publishing a public release.
