from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from urllib.parse import urlparse
from pathlib import Path
from datetime import timedelta
import sqlite3
import sys
import re
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.predict_url import predict_url


app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static")
)


configured_db_path = os.environ.get("DATABASE_PATH")
DB_PATH = (
    Path(configured_db_path).expanduser()
    if configured_db_path
    else PROJECT_ROOT / "database" / "phishguard.db"
)

if not DB_PATH.is_absolute():
    DB_PATH = PROJECT_ROOT / DB_PATH


def csrf_token():
    token = session.get("_csrf_token")

    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token

    return token


def valid_csrf():
    sent_token = request.form.get("csrf_token")
    saved_token = session.get("_csrf_token")

    return bool(
        sent_token
        and saved_token
        and secrets.compare_digest(
            sent_token,
            saved_token
        )
    )


app.jinja_env.globals["csrf_token"] = csrf_token

production_mode = os.environ.get(
    "PRODUCTION", ""
).strip().lower() in {"1", "true", "yes"}

secret_key = os.environ.get("SECRET_KEY")

if production_mode and not secret_key:
    raise RuntimeError(
        "Set the SECRET_KEY environment variable when PRODUCTION=1."
    )

app.secret_key = secret_key or "phishguard-local-development-key"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=production_mode,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2)
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            rule_status TEXT,
            ml_prediction TEXT,
            ml_probability REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


init_db()


def is_valid_url(url):
    url = str(url).strip()

    if not url or " " in url:
        return False

    if not url.startswith(("http://", "https://")):
        test_url = "https://" + url
    else:
        test_url = url

    try:
        parsed = urlparse(test_url)
        hostname = parsed.hostname

        if not hostname:
            return False

        # Allow normal domains or IPv4 addresses
        is_ip = re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            hostname
        )

        is_domain = (
            "." in hostname
            and not hostname.startswith(".")
            and not hostname.endswith(".")
        )

        return bool(is_ip or is_domain)

    except Exception:
        return False


def analyze_url(url):
    score = 0
    reasons = []

    original_url = url.strip()

    if not original_url.startswith(("http://", "https://")):
        url = "https://" + original_url
    else:
        url = original_url

    parsed_url = urlparse(url)

    domain = parsed_url.netloc.lower()
    full_url = url.lower()

    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    if len(url) > 120:
        score += 10
        reasons.append("URL is extremely long")

    if parsed_url.scheme != "https":
        score += 10
        reasons.append("Website does not use HTTPS")

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 30
        reasons.append("IP address used instead of domain name")

    if "@" in url:
        score += 20
        reasons.append("@ symbol found in URL")

    if domain.count(".") >= 3:
        score += 15
        reasons.append("Multiple subdomains detected")

    if domain.count("-") >= 2:
        score += 10
        reasons.append("Multiple hyphens found in domain")

    if url.count("%") >= 3:
        score += 10
        reasons.append("URL contains excessive encoded characters")

    if url.count("//") > 1:
        score += 10
        reasons.append("Multiple // patterns found in URL")

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly"
    ]

    for shortener in shorteners:
        if domain == shortener or domain.endswith("." + shortener):
            score += 20
            reasons.append("URL shortening service detected")
            break

    suspicious_words = [
        "login",
        "verify",
        "account",
        "secure",
        "update",
        "banking",
        "confirm",
        "password",
        "signin",
        "wallet",
        "payment",
        "recover",
        "security",
        "credential"
    ]

    for word in suspicious_words:
        if word in full_url:
            score += 7
            reasons.append(
                f"Suspicious keyword detected: {word}"
            )

    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 15
            reasons.append(
                "Suspicious top-level domain detected"
            )
            break

    if len(domain) > 35:
        score += 10
        reasons.append(
            "Domain name is unusually long"
        )

    if re.search(r"[a-zA-Z]+\d{4,}", domain):
        score += 10
        reasons.append(
            "Domain contains an unusual number pattern"
        )

    score = min(score, 100)

    if score >= 60:
        status = "PHISHING"

    elif score >= 30:
        status = "SUSPICIOUS"

    else:
        status = "SAFE"

    return {
        "url": url,
        "status": status,
        "risk_score": score,
        "reasons": reasons
    }


def final_verdict(rule_status, ml_prediction, ml_probability):

    if rule_status == "PHISHING":
        return "PHISHING"

    if (
        ml_prediction == "PHISHING"
        and ml_probability >= 80
    ):
        return "PHISHING"

    if rule_status == "SUSPICIOUS":
        return "SUSPICIOUS"

    if (
        ml_prediction == "PHISHING"
        and ml_probability >= 50
    ):
        return "SUSPICIOUS"

    return "SAFE"


def save_scan(result):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans (
            user_id,
            url,
            status,
            risk_score,
            rule_status,
            ml_prediction,
            ml_probability
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session.get("user_id"),
            result["url"],
            result["status"],
            result["risk_score"],
            result["rule_status"],
            result["ml_prediction"],
            result["ml_probability"]
        )
    )

    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if session.get("user_id"):
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))

    error = None

    if request.method == "POST":
        if not valid_csrf():
            return "Invalid CSRF token", 403

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        user = conn.execute(
            """
            SELECT id, name, email, password_hash, role, is_active
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        conn.close()

        if user and user["is_active"] == 0:
            error = "Your account has been blocked by the administrator"

        elif user and check_password_hash(
            user["password_hash"],
            password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["email"] = user["email"]
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("user_dashboard"))

        error = "Invalid email or password"

    return render_template(
        "login.html",
        error=error,
        mode="login"
    )


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def forgot_password():
    message = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        conn = sqlite3.connect(DB_PATH)

        user = conn.execute(
            "SELECT id, email FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        # Always show same message to avoid revealing
        # whether an account exists.
        message = (
            "If an account exists for that email, "
            "a password reset link has been generated."
        )

        if user:
            serializer = URLSafeTimedSerializer(
                app.secret_key
            )

            token = serializer.dumps(
                email,
                salt="password-reset"
            )

            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            print("\n======================================")
            print("PHISHGUARD PASSWORD RESET LINK")
            print(reset_url)
            print("Valid for 15 minutes")
            print("======================================\n")

    return render_template(
        "forgot_password.html",
        message=message
    )


@app.route(
    "/reset-password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):
    serializer = URLSafeTimedSerializer(
        app.secret_key
    )

    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=900
        )

    except SignatureExpired:
        return render_template(
            "reset_password.html",
            error="Reset link has expired.",
            token=None
        )

    except BadSignature:
        return render_template(
            "reset_password.html",
            error="Invalid password reset link.",
            token=None
        )

    error = None

    if request.method == "POST":
        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(password) < 8:
            error = (
                "Password must be at least 8 characters."
            )

        elif password != confirm_password:
            error = "Passwords do not match."

        else:
            conn = sqlite3.connect(DB_PATH)

            conn.execute(
                """
                UPDATE users
                SET password_hash = ?
                WHERE email = ?
                """,
                (
                    generate_password_hash(password),
                    email
                )
            )

            conn.commit()
            conn.close()

            return redirect(
                url_for(
                    "login",
                    reset="success"
                )
            )

    return render_template(
        "reset_password.html",
        error=error,
        token=token
    )


@app.route("/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    if not valid_csrf():
        return "Invalid CSRF token", 403

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not email or not password:
        return render_template(
            "login.html",
            error="All fields are required",
            mode="register"
        )

    if len(password) < 8:
        return render_template(
            "login.html",
            error="Password must be at least 8 characters",
            mode="register"
        )

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    existing = cursor.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing:
        conn.close()

        return render_template(
            "login.html",
            error="Account with this email already exists",
            mode="register"
        )

    cursor.execute(
        """
        INSERT INTO users (
            name,
            email,
            password_hash,
            role
        )
        VALUES (?, ?, ?, 'user')
        """,
        (
            name,
            email,
            generate_password_hash(password)
        )
    )

    conn.commit()
    conn.close()

    return redirect(url_for("login", registered="1"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin")
def admin_dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("home"))

    conn = sqlite3.connect(DB_PATH)

    total_users = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'user'"
    ).fetchone()[0]

    total_scans = conn.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    phishing_scans = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE status = 'PHISHING'"
    ).fetchone()[0]

    users = conn.execute(
        """
        SELECT id, name, email, role, created_at, is_active
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_scans=total_scans,
        phishing_scans=phishing_scans,
        users=users
    )


@app.route("/admin/activity")
def admin_activity():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(url_for("admin_login"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    users = conn.execute("""
        SELECT
            u.id,
            u.name,
            u.email,
            u.is_active,
            u.created_at,

            COUNT(s.id) AS total_scans,

            SUM(
                CASE
                    WHEN s.status = 'SAFE'
                    THEN 1
                    ELSE 0
                END
            ) AS safe_scans,

            SUM(
                CASE
                    WHEN s.status = 'SUSPICIOUS'
                    THEN 1
                    ELSE 0
                END
            ) AS suspicious_scans,

            SUM(
                CASE
                    WHEN s.status = 'PHISHING'
                    THEN 1
                    ELSE 0
                END
            ) AS phishing_scans,

            MAX(s.scanned_at) AS last_scan

        FROM users u

        LEFT JOIN scans s
            ON s.user_id = u.id

        WHERE u.role = 'user'

        GROUP BY
            u.id,
            u.name,
            u.email,
            u.is_active,
            u.created_at

        ORDER BY
            total_scans DESC,
            u.created_at DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin_activity.html",
        users=users
    )


@app.route("/admin/user/<int:user_id>")
def admin_user_detail(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(url_for("admin_login"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT
            id,
            name,
            email,
            role,
            is_active,
            created_at
        FROM users
        WHERE id = ?
          AND role = 'user'
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return "User not found", 404

    stats = conn.execute("""
        SELECT
            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN status = 'SAFE'
                    THEN 1
                    ELSE 0
                END
            ) AS safe,

            SUM(
                CASE
                    WHEN status = 'SUSPICIOUS'
                    THEN 1
                    ELSE 0
                END
            ) AS suspicious,

            SUM(
                CASE
                    WHEN status = 'PHISHING'
                    THEN 1
                    ELSE 0
                END
            ) AS phishing

        FROM scans
        WHERE user_id = ?
    """, (user_id,)).fetchone()

    scans = conn.execute("""
        SELECT
            id,
            url,
            status,
            risk_score,
            rule_status,
            ml_prediction,
            ml_probability,
            scanned_at
        FROM scans
        WHERE user_id = ?
        ORDER BY scanned_at DESC
        LIMIT 100
    """, (user_id,)).fetchall()

    conn.close()

    return render_template(
        "admin_user_detail.html",
        user=user,
        stats=stats,
        scans=scans
    )


@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
def toggle_user(user_id):
    if not session.get("user_id") or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT role, is_active FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if user and user[0] != "admin":
        new_status = 0 if user[1] == 1 else 1

        cursor.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (new_status, user_id)
        )

        conn.commit()

    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    if not session.get("user_id") or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    user = cursor.execute(
        "SELECT role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if user and user[0] != "admin":
        cursor.execute(
            "DELETE FROM users WHERE id = ?",
            (user_id,)
        )

        conn.commit()

    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/dashboard")
def user_dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    user_id = session.get("user_id")

    conn = sqlite3.connect(DB_PATH)

    total_scans = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id = ?",
        (user_id,)
    ).fetchone()[0]

    safe_scans = conn.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ? AND status = 'SAFE'
        """,
        (user_id,)
    ).fetchone()[0]

    suspicious_scans = conn.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ? AND status = 'SUSPICIOUS'
        """,
        (user_id,)
    ).fetchone()[0]

    phishing_scans = conn.execute(
        """
        SELECT COUNT(*)
        FROM scans
        WHERE user_id = ? AND status = 'PHISHING'
        """,
        (user_id,)
    ).fetchone()[0]

    recent_scans = conn.execute(
        """
        SELECT
            url,
            status,
            risk_score,
            ml_prediction,
            ml_probability,
            scanned_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 8
        """,
        (user_id,)
    ).fetchall()

    conn.close()

    return render_template(
        "user_dashboard.html",
        user_name=session.get("name"),
        user_email=session.get("email"),
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        phishing_scans=phishing_scans,
        recent_scans=recent_scans
    )


@app.route("/analytics")
def user_analytics():

    if not session.get("user_id"):
        return redirect(url_for("user_login"))

    if session.get("role") != "user":
        return redirect(url_for("admin_dashboard"))

    return render_template(
        "user_analytics.html",
        user_name=session.get("name")
    )


@app.route("/profile")
def profile():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute(
        """
        SELECT id, name, email, role, created_at
        FROM users
        WHERE id = ?
        """,
        (session.get("user_id"),)
    ).fetchone()

    conn.close()

    return render_template(
        "profile.html",
        user=user,
        success=request.args.get("success"),
        error=None
    )


@app.route("/change-password", methods=["POST"])
def change_password():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    current_password = request.form.get(
        "current_password",
        ""
    )

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute(
        """
        SELECT id, name, email, role,
               created_at, password_hash
        FROM users
        WHERE id = ?
        """,
        (session.get("user_id"),)
    ).fetchone()

    if not user:
        conn.close()
        session.clear()
        return redirect(url_for("login"))

    error = None

    if not check_password_hash(
        user["password_hash"],
        current_password
    ):
        error = "Current password is incorrect"

    elif len(new_password) < 8:
        error = "New password must be at least 8 characters"

    elif new_password != confirm_password:
        error = "New passwords do not match"

    elif check_password_hash(
        user["password_hash"],
        new_password
    ):
        error = "New password must be different from current password"

    if error:
        conn.close()

        return render_template(
            "profile.html",
            user=user,
            error=error,
            success=None
        )

    conn.execute(
        """
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        """,
        (
            generate_password_hash(new_password),
            session.get("user_id")
        )
    )

    conn.commit()
    conn.close()

    return redirect(
        url_for(
            "profile",
            success="Password changed successfully"
        )
    )


@app.route("/history/clear", methods=["POST"])
def clear_user_history():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if not valid_csrf():
        return "Invalid CSRF token", 403

    conn = sqlite3.connect(DB_PATH)

    conn.execute(
        "DELETE FROM scans WHERE user_id = ?",
        (session.get("user_id"),)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("user_dashboard"))


@app.route("/admin/history/clear", methods=["POST"])
def clear_all_history():
    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(url_for("login"))

    if not valid_csrf():
        return "Invalid CSRF token", 403

    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))



@app.route("/user/login", methods=["GET", "POST"])
def user_login():

    if session.get("user_id"):
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))

    error = None

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        user = conn.execute(
            """
            SELECT
                id,
                name,
                email,
                password_hash,
                role,
                is_active
            FROM users
            WHERE email = ?
              AND role = 'user'
            """,
            (email,)
        ).fetchone()

        conn.close()

        if not user:
            error = "Invalid user email or password"

        elif user["is_active"] == 0:
            error = "Your user account has been blocked"

        elif not check_password_hash(
            user["password_hash"],
            password
        ):
            error = "Invalid user email or password"

        else:
            session.clear()

            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["email"] = user["email"]
            session["role"] = "user"

            return redirect(
                url_for("user_dashboard")
            )

    return render_template(
        "user_auth.html",
        error=error,
        mode="login"
    )


@app.route("/user/register", methods=["POST"])
def user_register():

    name = request.form.get(
        "name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )

    if not name or not email or not password:
        return render_template(
            "user_auth.html",
            error="All fields are required",
            mode="register"
        )

    if len(password) < 8:
        return render_template(
            "user_auth.html",
            error="Password must be at least 8 characters",
            mode="register"
        )

    conn = sqlite3.connect(DB_PATH)

    existing = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing:
        conn.close()

        return render_template(
            "user_auth.html",
            error="Account already exists with this email",
            mode="register"
        )

    conn.execute(
        """
        INSERT INTO users (
            name,
            email,
            password_hash,
            role,
            is_active
        )
        VALUES (?, ?, ?, 'user', 1)
        """,
        (
            name,
            email,
            generate_password_hash(password)
        )
    )

    conn.commit()
    conn.close()

    return redirect(
        url_for(
            "user_login",
            registered="1"
        )
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if session.get("user_id"):
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("user_dashboard"))

    error = None

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        admin = conn.execute(
            """
            SELECT
                id,
                name,
                email,
                password_hash,
                role,
                is_active
            FROM users
            WHERE email = ?
              AND role = 'admin'
            """,
            (email,)
        ).fetchone()

        conn.close()

        if not admin:
            error = "Invalid admin email or password"

        elif admin["is_active"] == 0:
            error = "Admin account is disabled"

        elif not check_password_hash(
            admin["password_hash"],
            password
        ):
            error = "Invalid admin email or password"

        else:
            session.clear()

            session["user_id"] = admin["id"]
            session["name"] = admin["name"]
            session["email"] = admin["email"]
            session["role"] = "admin"

            return redirect(
                url_for("admin_dashboard")
            )

    return render_template(
        "admin_auth.html",
        error=error,
        mode="login"
    )


@app.route("/admin/register", methods=["POST"])
def admin_register():

    name = request.form.get(
        "name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )

    access_code = request.form.get(
        "access_code",
        ""
    )

    required_code = os.environ.get(
        "ADMIN_REGISTRATION_CODE",
        "PHISHGUARD-ADMIN-2026"
    )

    if access_code != required_code:
        return render_template(
            "admin_auth.html",
            error="Invalid Admin Access Code",
            mode="register"
        )

    if not name or not email or not password:
        return render_template(
            "admin_auth.html",
            error="All fields are required",
            mode="register"
        )

    if len(password) < 8:
        return render_template(
            "admin_auth.html",
            error="Password must be at least 8 characters",
            mode="register"
        )

    conn = sqlite3.connect(DB_PATH)

    existing = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing:
        conn.close()

        return render_template(
            "admin_auth.html",
            error="Account already exists with this email",
            mode="register"
        )

    conn.execute(
        """
        INSERT INTO users (
            name,
            email,
            password_hash,
            role,
            is_active
        )
        VALUES (?, ?, ?, 'admin', 1)
        """,
        (
            name,
            email,
            generate_password_hash(password)
        )
    )

    conn.commit()
    conn.close()

    return redirect(
        url_for(
            "admin_login",
            registered="1"
        )
    )


@app.before_request
def protect_portals():
    path = request.path

    # Public pages
    public_paths = {
        "/",
        "/user/login",
        "/user/register",
        "/admin/login",
        "/admin/register",
        "/forgot-password"
    }

    if (
        path in public_paths
        or path.startswith("/reset-password/")
        or path.startswith("/static/")
    ):
        return None

    user_id = session.get("user_id")
    role = session.get("role")

    # Admin area
    if path.startswith("/admin"):
        if not user_id:
            return redirect(url_for("admin_login"))

        if role != "admin":
            return redirect(url_for("user_dashboard"))

    # User-only pages
    user_pages = (
        "/dashboard",
        "/scanner",
        "/analytics",
        "/profile",
        "/change-password",
        "/history/clear"
    )

    if path in user_pages:
        if not user_id:
            return redirect(url_for("user_login"))

        if role != "user":
            return redirect(url_for("admin_dashboard"))

    # API requires login
    if path.startswith("/api/"):
        if not user_id:
            return jsonify({
                "error": "Authentication required"
            }), 401

    return None



def normalize_domain(value):
    value = (value or "").strip().lower()

    if not value:
        return ""

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlparse(value)
        domain = (parsed.hostname or "").lower()

        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except Exception:
        return ""


def ensure_blocked_domains_table():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def get_blocked_domain(url):
    domain = normalize_domain(url)

    if not domain:
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT id, domain, reason
        FROM blocked_domains
    """).fetchall()

    conn.close()

    for row in rows:
        blocked = row["domain"]

        if (
            domain == blocked
            or domain.endswith("." + blocked)
        ):
            return row

    return None


ensure_blocked_domains_table()


@app.before_request
def enforce_domain_blocklist():

    if request.path != "/api/scan":
        return None

    if request.method != "POST":
        return None

    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return None

    blocked = get_blocked_domain(url)

    if not blocked:
        return None

    normalized_url = url

    if "://" not in normalized_url:
        normalized_url = "https://" + normalized_url

    result = {
        "url": normalized_url,
        "status": "PHISHING",
        "risk_score": 100,
        "rule_status": "PHISHING",
        "ml_prediction": "BLOCKLIST",
        "ml_probability": 100.0,
        "reasons": [
            "Domain is blocked by the administrator",
            blocked["reason"] or "Known unsafe domain"
        ]
    }

    try:
        save_scan(result)
    except Exception as error:
        print("Blocked-domain save error:", error)

    return jsonify(result), 200



def ensure_security_tables():

    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            source TEXT,
            resolved INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            role TEXT,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def write_audit_log(
    action,
    details="",
    user_id=None,
    role=None
):

    try:

        conn = sqlite3.connect(DB_PATH)

        conn.execute("""
            INSERT INTO audit_logs (
                user_id,
                role,
                action,
                details
            )
            VALUES (?, ?, ?, ?)
        """, (
            user_id or session.get("user_id"),
            role or session.get("role"),
            action,
            details
        ))

        conn.commit()
        conn.close()

    except Exception as error:

        print(
            "Audit log error:",
            error
        )


ensure_security_tables()


@app.after_request
def security_activity_monitor(response):

    try:

        # =========================
        # PHISHING ALERT
        # =========================

        if (
            request.path == "/api/scan"
            and request.method == "POST"
            and response.status_code == 200
        ):

            data = response.get_json(
                silent=True
            )

            if (
                data
                and data.get("status") == "PHISHING"
            ):

                conn = sqlite3.connect(DB_PATH)

                conn.execute("""
                    INSERT INTO threat_alerts (
                        user_id,
                        url,
                        verdict,
                        risk_score,
                        source
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    session.get("user_id"),
                    data.get("url", ""),
                    data.get("status", "PHISHING"),
                    data.get("risk_score", 0),
                    data.get(
                        "ml_prediction",
                        "Hybrid Detection"
                    )
                ))

                conn.commit()
                conn.close()


        # =========================
        # ADMIN AUDIT LOGS
        # =========================

        if (
            request.method == "POST"
            and response.status_code
                in (200, 201, 302)
        ):

            path = request.path


            if path == "/admin/blocked-domains/add":

                write_audit_log(
                    "BLOCK_DOMAIN",
                    request.form.get(
                        "domain",
                        ""
                    )
                )


            elif (
                path.startswith(
                    "/admin/blocked-domains/"
                )
                and path.endswith(
                    "/delete"
                )
            ):

                write_audit_log(
                    "UNBLOCK_DOMAIN",
                    path
                )


            elif (
                path.startswith(
                    "/admin/user/"
                )
                and path.endswith(
                    "/toggle"
                )
            ):

                write_audit_log(
                    "CHANGE_USER_STATUS",
                    path
                )


            elif (
                path.startswith(
                    "/admin/user/"
                )
                and path.endswith(
                    "/delete"
                )
            ):

                write_audit_log(
                    "DELETE_USER",
                    path
                )


            elif (
                path ==
                "/admin/history/clear"
            ):

                write_audit_log(
                    "CLEAR_ALL_SCAN_HISTORY",
                    "Administrator cleared scan history"
                )


            elif (
                path ==
                "/history/clear"
            ):

                write_audit_log(
                    "CLEAR_USER_HISTORY",
                    "User cleared personal scan history"
                )


            elif (
                path ==
                "/change-password"
            ):

                write_audit_log(
                    "CHANGE_PASSWORD",
                    "Account password changed"
                )


    except Exception as error:

        print(
            "Security activity monitor error:",
            error
        )


    return response


@app.context_processor
def inject_admin_dashboard_data():

    data = {
        "total_scans": 0,
        "safe_scans": 0,
        "suspicious_scans": 0,
        "phishing_scans": 0,
        "recent_scans": []
    }

    if session.get("role") != "admin":
        return data

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        stats = conn.execute("""
            SELECT
                COUNT(*) AS total_scans,

                SUM(
                    CASE
                        WHEN status = 'SAFE'
                        THEN 1
                        ELSE 0
                    END
                ) AS safe_scans,

                SUM(
                    CASE
                        WHEN status = 'SUSPICIOUS'
                        THEN 1
                        ELSE 0
                    END
                ) AS suspicious_scans,

                SUM(
                    CASE
                        WHEN status = 'PHISHING'
                        THEN 1
                        ELSE 0
                    END
                ) AS phishing_scans

            FROM scans
        """).fetchone()

        recent_scans = conn.execute("""
            SELECT
                id,
                url,
                status,
                risk_score,
                rule_status,
                ml_prediction,
                ml_probability,
                scanned_at

            FROM scans

            ORDER BY scanned_at DESC

            LIMIT 10
        """).fetchall()

        conn.close()

        data["total_scans"] = (
            stats["total_scans"] or 0
        )

        data["safe_scans"] = (
            stats["safe_scans"] or 0
        )

        data["suspicious_scans"] = (
            stats["suspicious_scans"] or 0
        )

        data["phishing_scans"] = (
            stats["phishing_scans"] or 0
        )

        data["recent_scans"] = recent_scans

    except Exception as error:
        print(
            "Admin dashboard stats error:",
            error
        )

    return data


@app.route("/")
def home():

    if session.get("user_id"):

        if session.get("role") == "admin":
            return redirect(
                url_for("admin_dashboard")
            )

        return redirect(
            url_for("user_dashboard")
        )

    return render_template(
        "role_select.html"
    )

@app.route("/scanner")
def scanner():

    if not session.get("user_id"):
        return redirect(
            url_for("home")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    return render_template(
        "index.html",
        user_name=session.get("name")
    )


@app.route("/api/scan", methods=["POST"])
def scan_url():

    if not session.get("user_id"):
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify(
            {"error": "URL is required"}
        ), 400

    if not is_valid_url(data["url"]):
        return jsonify(
            {"error": "Please enter a valid website URL"}
        ), 400

    result = analyze_url(data["url"])

    rule_status = result["status"]

    ml_result = predict_url(
        result["url"]
    )

    result["rule_status"] = rule_status
    result["ml_prediction"] = ml_result["prediction"]
    result["ml_probability"] = ml_result["phishing_probability"]

    result["status"] = final_verdict(
        rule_status,
        result["ml_prediction"],
        result["ml_probability"]
    )

    save_scan(result)

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def scan_history():

    if not session.get("user_id"):
        return jsonify({"error": "Authentication required"}), 401

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if session.get("role") == "admin":
        rows = cursor.execute(
            """
            SELECT
                id,
                url,
                status,
                risk_score,
                scanned_at,
                rule_status,
                ml_prediction,
                ml_probability
            FROM scans
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()

    else:
        rows = cursor.execute(
            """
            SELECT
                id,
                url,
                status,
                risk_score,
                scanned_at,
                rule_status,
                ml_prediction,
                ml_probability
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 20
            """,
            (session.get("user_id"),)
        ).fetchall()

    conn.close()

    history = []

    for row in rows:
        history.append({
            "id": row[0],
            "url": row[1],
            "status": row[2],
            "risk_score": row[3],
            "scanned_at": row[4],
            "rule_status": row[5],
            "ml_prediction": row[6],
            "ml_probability": row[7]
        })

    return jsonify(history)


@app.route("/api/stats", methods=["GET"])
def scan_stats():

    if not session.get("user_id"):
        return jsonify({"error": "Authentication required"}), 401

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if session.get("role") == "admin":
        where = ""
        params = ()
    else:
        where = " WHERE user_id = ?"
        params = (session.get("user_id"),)

    total = cursor.execute(
        "SELECT COUNT(*) FROM scans" + where,
        params
    ).fetchone()[0]

    safe = cursor.execute(
        "SELECT COUNT(*) FROM scans" +
        where +
        (" AND status = 'SAFE'" if where else " WHERE status = 'SAFE'"),
        params
    ).fetchone()[0]

    suspicious = cursor.execute(
        "SELECT COUNT(*) FROM scans" +
        where +
        (" AND status = 'SUSPICIOUS'" if where else " WHERE status = 'SUSPICIOUS'"),
        params
    ).fetchone()[0]

    phishing = cursor.execute(
        "SELECT COUNT(*) FROM scans" +
        where +
        (" AND status = 'PHISHING'" if where else " WHERE status = 'PHISHING'"),
        params
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "phishing": phishing
    })




@app.route("/admin/scanner")
def admin_scanner_page():
    if not session.get("user_id") or session.get("role") != "admin":
        return redirect(url_for("admin_login"))

    return redirect(url_for("admin_dashboard") + "#scanner")


@app.route("/admin/history")
def admin_scan_history_page():
    if not session.get("user_id") or session.get("role") != "admin":
        return redirect(url_for("admin_login"))

    return render_template("admin_history.html")


@app.route("/admin/cloud-status")
def admin_cloud_status_page():
    if not session.get("user_id") or session.get("role") != "admin":
        return redirect(url_for("admin_login"))

    return render_template("cloud_status.html")


@app.route("/api/cloud-status")
def cloud_status_api():
    if not session.get("user_id") or session.get("role") != "admin":
        return jsonify({"error": "Admin authentication required"}), 401

    database_ok = False
    database_message = "Unavailable"
    scan_count = 0

    try:
        conn = sqlite3.connect(DB_PATH)

        row = conn.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()

        scan_count = row[0] if row else 0

        conn.close()

        database_ok = True
        database_message = "Connected"

    except Exception as error:
        database_message = str(error)

    model_path = (
        PROJECT_ROOT
        / "ml"
        / "models"
        / "phishing_model_real.pkl"
    )

    model_ok = model_path.exists()

    return jsonify({
        "application": {
            "status": "ONLINE",
            "service": "PhishGuard Cloud",
            "framework": "Flask"
        },
        "database": {
            "status": "ONLINE" if database_ok else "OFFLINE",
            "message": database_message,
            "total_scans": scan_count
        },
        "ml_engine": {
            "status": "ONLINE" if model_ok else "OFFLINE",
            "model": "Decision Tree - PhiUSIIL",
            "model_file_found": model_ok
        },
        "rule_engine": {
            "status": "ONLINE"
        }
    })



@app.route("/admin/blocked-domains")
def admin_blocked_domains():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(url_for("admin_login"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    domains = conn.execute("""
        SELECT
            id,
            domain,
            reason,
            created_at
        FROM blocked_domains
        ORDER BY created_at DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin_blocked_domains.html",
        domains=domains,
        error=request.args.get("error"),
        success=request.args.get("success")
    )


@app.route(
    "/admin/blocked-domains/add",
    methods=["POST"]
)
def admin_add_blocked_domain():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(url_for("admin_login"))

    if not valid_csrf():
        return "Invalid CSRF token", 403

    raw_domain = request.form.get(
        "domain",
        ""
    )

    reason = request.form.get(
        "reason",
        ""
    ).strip()

    domain = normalize_domain(raw_domain)

    if (
        not domain
        or "." not in domain
        or " " in domain
    ):
        return redirect(
            url_for(
                "admin_blocked_domains",
                error="Enter a valid domain"
            )
        )

    conn = sqlite3.connect(DB_PATH)

    try:

        conn.execute("""
            INSERT INTO blocked_domains (
                domain,
                reason,
                added_by
            )
            VALUES (?, ?, ?)
        """, (
            domain,
            reason,
            session.get("user_id")
        ))

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return redirect(
            url_for(
                "admin_blocked_domains",
                error="Domain is already blocked"
            )
        )

    conn.close()

    return redirect(
        url_for(
            "admin_blocked_domains",
            success="Domain blocked successfully"
        )
    )


@app.route(
    "/admin/blocked-domains/<int:domain_id>/delete",
    methods=["POST"]
)
def admin_delete_blocked_domain(domain_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(url_for("admin_login"))

    if not valid_csrf():
        return "Invalid CSRF token", 403

    conn = sqlite3.connect(DB_PATH)

    conn.execute(
        "DELETE FROM blocked_domains WHERE id = ?",
        (domain_id,)
    )

    conn.commit()
    conn.close()

    return redirect(
        url_for(
            "admin_blocked_domains",
            success="Domain removed from blocklist"
        )
    )




@app.route("/admin/alerts")
def admin_alerts():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(
            url_for("admin_login")
        )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    alerts = conn.execute("""
        SELECT
            a.id,
            a.user_id,
            a.url,
            a.verdict,
            a.risk_score,
            a.source,
            a.resolved,
            a.created_at,
            u.name AS user_name,
            u.email AS user_email

        FROM threat_alerts a

        LEFT JOIN users u
            ON u.id = a.user_id

        ORDER BY
            a.resolved ASC,
            a.created_at DESC
    """).fetchall()

    open_alerts = conn.execute("""
        SELECT COUNT(*)
        FROM threat_alerts
        WHERE resolved = 0
    """).fetchone()[0]

    conn.close()

    return render_template(
        "admin_alerts.html",
        alerts=alerts,
        open_alerts=open_alerts
    )


@app.route(
    "/admin/alerts/<int:alert_id>/resolve",
    methods=["POST"]
)
def resolve_admin_alert(alert_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(
            url_for("admin_login")
        )

    if not valid_csrf():
        return "Invalid CSRF token", 403

    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        UPDATE threat_alerts
        SET resolved = 1
        WHERE id = ?
    """, (alert_id,))

    conn.commit()
    conn.close()

    write_audit_log(
        "RESOLVE_THREAT_ALERT",
        f"Alert ID: {alert_id}"
    )

    return redirect(
        url_for("admin_alerts")
    )


@app.route("/admin/audit-logs")
def admin_audit_logs():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(
            url_for("admin_login")
        )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    logs = conn.execute("""
        SELECT
            a.id,
            a.user_id,
            a.role,
            a.action,
            a.details,
            a.created_at,
            u.name AS user_name,
            u.email AS user_email

        FROM audit_logs a

        LEFT JOIN users u
            ON u.id = a.user_id

        ORDER BY
            a.created_at DESC

        LIMIT 500
    """).fetchall()

    conn.close()

    return render_template(
        "admin_audit_logs.html",
        logs=logs
    )




@app.route("/admin/analytics")
def admin_analytics():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return redirect(url_for("admin_login"))

    from datetime import datetime, timedelta
    from collections import defaultdict

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row


    # =========================
    # USER STATS
    # =========================

    user_stats = conn.execute("""
        SELECT
            COUNT(*) AS total_users,

            SUM(
                CASE
                    WHEN is_active = 1
                    THEN 1 ELSE 0
                END
            ) AS active_users,

            SUM(
                CASE
                    WHEN is_active = 0
                    THEN 1 ELSE 0
                END
            ) AS blocked_users

        FROM users
        WHERE role = 'user'
    """).fetchone()


    # =========================
    # SCAN STATS
    # =========================

    scan_stats = conn.execute("""
        SELECT
            COUNT(*) AS total_scans,

            SUM(
                CASE
                    WHEN status = 'SAFE'
                    THEN 1 ELSE 0
                END
            ) AS safe_scans,

            SUM(
                CASE
                    WHEN status = 'SUSPICIOUS'
                    THEN 1 ELSE 0
                END
            ) AS suspicious_scans,

            SUM(
                CASE
                    WHEN status = 'PHISHING'
                    THEN 1 ELSE 0
                END
            ) AS phishing_scans

        FROM scans
    """).fetchone()


    # =========================
    # OPEN ALERTS
    # =========================

    try:

        open_alerts = conn.execute("""
            SELECT COUNT(*)
            FROM threat_alerts
            WHERE resolved = 0
        """).fetchone()[0]

    except sqlite3.OperationalError:

        open_alerts = 0


    # =========================
    # MOST ACTIVE USERS
    # =========================

    active_users = conn.execute("""
        SELECT
            u.id,
            u.name,
            u.email,
            COUNT(s.id) AS scan_count

        FROM users u

        LEFT JOIN scans s
            ON s.user_id = u.id

        WHERE u.role = 'user'

        GROUP BY
            u.id,
            u.name,
            u.email

        ORDER BY
            scan_count DESC

        LIMIT 5
    """).fetchall()


    # =========================
    # LAST 7 DAYS
    # =========================

    today = datetime.now().date()

    dates = [
        today - timedelta(days=i)
        for i in range(6, -1, -1)
    ]

    daily_rows = conn.execute("""
        SELECT
            DATE(scanned_at) AS scan_date,
            COUNT(*) AS scan_count

        FROM scans

        WHERE scanned_at >= datetime('now', '-6 days')

        GROUP BY DATE(scanned_at)
    """).fetchall()


    daily_map = {
        row["scan_date"]: row["scan_count"]
        for row in daily_rows
    }


    chart_labels = [
        date.strftime("%d %b")
        for date in dates
    ]


    chart_values = [
        daily_map.get(
            date.isoformat(),
            0
        )
        for date in dates
    ]


    # =========================
    # TOP RISKY DOMAINS
    # =========================

    scan_rows = conn.execute("""
        SELECT
            url,
            status,
            risk_score

        FROM scans

        ORDER BY scanned_at DESC

        LIMIT 2000
    """).fetchall()

    conn.close()


    domain_stats = defaultdict(
        lambda: {
            "scans": 0,
            "threats": 0,
            "risk_total": 0,
            "max_risk": 0
        }
    )


    for scan in scan_rows:

        domain = normalize_domain(
            scan["url"]
        )

        if not domain:
            continue


        data = domain_stats[domain]

        data["scans"] += 1

        risk = int(
            scan["risk_score"] or 0
        )

        data["risk_total"] += risk

        data["max_risk"] = max(
            data["max_risk"],
            risk
        )


        if scan["status"] in (
            "SUSPICIOUS",
            "PHISHING"
        ):
            data["threats"] += 1


    risky_domains = []


    for domain, data in domain_stats.items():

        average_risk = (
            data["risk_total"]
            / data["scans"]
            if data["scans"]
            else 0
        )


        risky_domains.append({
            "domain": domain,
            "scans": data["scans"],
            "threats": data["threats"],
            "max_risk": data["max_risk"],
            "average_risk": round(
                average_risk,
                1
            )
        })


    risky_domains.sort(
        key=lambda item: (
            item["threats"],
            item["max_risk"],
            item["average_risk"]
        ),
        reverse=True
    )


    risky_domains = risky_domains[:8]


    return render_template(
        "admin_analytics.html",

        total_users=(
            user_stats["total_users"] or 0
        ),

        active_user_count=(
            user_stats["active_users"] or 0
        ),

        blocked_user_count=(
            user_stats["blocked_users"] or 0
        ),

        total_scans=(
            scan_stats["total_scans"] or 0
        ),

        safe_scans=(
            scan_stats["safe_scans"] or 0
        ),

        suspicious_scans=(
            scan_stats["suspicious_scans"] or 0
        ),

        phishing_scans=(
            scan_stats["phishing_scans"] or 0
        ),

        open_alerts=open_alerts,

        active_users=active_users,

        risky_domains=risky_domains,

        chart_labels=chart_labels,
        chart_values=chart_values
    )




@app.route("/profile/update", methods=["POST"])
def update_user_profile():

    if (
        not session.get("user_id")
        or session.get("role") != "user"
    ):
        return redirect("/user/login")

    # Use the project's CSRF protection when available.
    if "valid_csrf" in globals():

        if not valid_csrf():

            return redirect(
                "/profile?error=Security+validation+failed"
            )


    name = (
        request.form.get("name", "")
        .strip()
    )

    email = (
        request.form.get("email", "")
        .strip()
        .lower()
    )


    if (
        len(name) < 2
        or len(name) > 60
    ):

        return redirect(
            "/profile?error=Enter+a+valid+name"
        )


    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):

        return redirect(
            "/profile?error=Enter+a+valid+email"
        )


    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row


    existing = conn.execute("""
        SELECT id
        FROM users
        WHERE LOWER(email) = LOWER(?)
          AND id != ?
    """, (
        email,
        session.get("user_id")
    )).fetchone()


    if existing:

        conn.close()

        return redirect(
            "/profile?error=Email+is+already+in+use"
        )


    conn.execute("""
        UPDATE users
        SET name = ?,
            email = ?
        WHERE id = ?
    """, (
        name,
        email,
        session.get("user_id")
    ))


    conn.commit()
    conn.close()


    session["name"] = name
    session["email"] = email


    return redirect(
        "/profile?success=Profile+updated+successfully"
    )




@app.route("/profile/change-password", methods=["GET", "POST"])
def profile_change_password():

    if (
        not session.get("user_id")
        or session.get("role") != "user"
    ):
        return redirect("/user/login")

    error = None
    success = None

    if request.method == "POST":

        # CSRF validation if project helper exists
        if "valid_csrf" in globals():
            if not valid_csrf():
                return render_template(
                    "change_password.html",
                    error="Security validation failed. Refresh the page and try again.",
                    success=None
                ), 403

        current_password = request.form.get(
            "current_password", ""
        )

        new_password = request.form.get(
            "new_password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not current_password:
            error = "Enter your current password."

        elif len(new_password) < 8:
            error = "New password must contain at least 8 characters."

        elif new_password != confirm_password:
            error = "New password and confirm password do not match."

        elif current_password == new_password:
            error = "New password must be different from your current password."

        else:

            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row

            user = conn.execute("""
                SELECT id, password_hash
                FROM users
                WHERE id = ?
            """, (
                session.get("user_id"),
            )).fetchone()

            if not user:

                conn.close()

                error = "User account was not found."

            elif not check_password_hash(
                user["password_hash"],
                current_password
            ):

                conn.close()

                error = "Current password is incorrect."

            else:

                new_hash = generate_password_hash(
                    new_password
                )

                conn.execute("""
                    UPDATE users
                    SET password_hash = ?
                    WHERE id = ?
                """, (
                    new_hash,
                    session.get("user_id")
                ))

                conn.commit()
                conn.close()

                if "write_audit_log" in globals():
                    try:
                        write_audit_log(
                            "CHANGE_PASSWORD",
                            "User changed account password"
                        )
                    except Exception as audit_error:
                        print(
                            "Password audit error:",
                            audit_error
                        )

                success = "Password changed successfully."

    return render_template(
        "change_password.html",
        error=error,
        success=success
    )




# ==========================================================
# ADMIN USER MANAGEMENT
# ==========================================================

@app.route("/admin/users")
def admin_users_management():

    if not session.get("user_id") or session.get("role") != "admin":
        return redirect("/admin/login")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    columns = [
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    ]

    has_is_active = "is_active" in columns

    if has_is_active:
        users = conn.execute("""
            SELECT
                id,
                name,
                email,
                role,
                is_active,
                created_at
            FROM users
            ORDER BY created_at DESC
        """).fetchall()
    else:
        users = conn.execute("""
            SELECT
                id,
                name,
                email,
                role,
                created_at
            FROM users
            ORDER BY created_at DESC
        """).fetchall()

    conn.close()

    return render_template(
        "admin_users.html",
        users=users,
        has_is_active=has_is_active
    )


@app.route(
    "/admin/users/<int:user_id>/delete",
    methods=["POST"]
)
def admin_delete_user_account(user_id):

    if not session.get("user_id") or session.get("role") != "admin":
        return redirect("/admin/login")

    # CSRF protection if enabled in the project
    if "valid_csrf" in globals():
        if not valid_csrf():
            return "Security validation failed.", 403

    # Admin cannot delete their own account
    if user_id == session.get("user_id"):
        return redirect("/admin/users?error=self")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT id, name, email, role
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return redirect("/admin/users?error=notfound")

    # Protect admin accounts
    if user["role"] == "admin":
        conn.close()
        return redirect("/admin/users?error=admin")

    try:

        # Remove related records before deleting user.
        tables = [
            row["name"]
            for row in conn.execute("""
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
            """).fetchall()
        ]

        for table in tables:

            if table == "users":
                continue

            columns = [
                row["name"]
                for row in conn.execute(
                    f'PRAGMA table_info("{table}")'
                ).fetchall()
            ]

            if "user_id" in columns:
                conn.execute(
                    f'DELETE FROM "{table}" WHERE user_id = ?',
                    (user_id,)
                )

        conn.execute(
            "DELETE FROM users WHERE id = ?",
            (user_id,)
        )

        conn.commit()
        conn.close()

        if "write_audit_log" in globals():
            try:
                write_audit_log(
                    "DELETE_USER",
                    f'Deleted user: {user["email"]}'
                )
            except Exception as audit_error:
                print("Audit log warning:", audit_error)

        return redirect("/admin/users?deleted=1")

    except Exception as error:

        conn.rollback()
        conn.close()

        print("Delete user error:", error)

        return redirect("/admin/users?error=database")





# === ADMIN USER MANAGEMENT V2 ===

def ensure_admin_user_status_column():
    conn = sqlite3.connect(DB_PATH)

    columns = [
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "is_active" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1
        """)
        conn.commit()

    conn.close()


def admin_api_csrf_valid():

    # Project me CSRF system nahi hai to API normal chalegi.
    if "csrf_token" not in globals():
        return True

    import hmac

    saved = session.get("_csrf_token")

    sent = (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
    )

    return bool(
        saved
        and sent
        and hmac.compare_digest(
            str(saved),
            str(sent)
        )
    )


@app.route("/admin/api/users-v2")
def admin_users_api_v2():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({
            "error": "Admin authentication required"
        }), 401

    ensure_admin_user_status_column()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT
            id,
            name,
            email,
            role,
            is_active,
            created_at
        FROM users
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    token = None

    if "csrf_token" in globals():
        try:
            token = csrf_token()
        except Exception:
            token = None

    return jsonify({
        "users": [
            {
                "id": row["id"],
                "name": row["name"],
                "email": row["email"],
                "role": row["role"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"]
            }
            for row in rows
        ],
        "csrf_token": token
    })


@app.route(
    "/admin/api/users-v2/<int:user_id>/toggle",
    methods=["POST"]
)
def admin_toggle_user_v2(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if not admin_api_csrf_valid():
        return jsonify({
            "error": "Security validation failed"
        }), 403

    ensure_admin_user_status_column()

    if user_id == session.get("user_id"):
        return jsonify({
            "error": "You cannot block your own account"
        }), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT id, name, email, role, is_active
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({
            "error": "User not found"
        }), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({
            "error": "Admin accounts are protected"
        }), 400

    new_status = 0 if user["is_active"] else 1

    conn.execute("""
        UPDATE users
        SET is_active = ?
        WHERE id = ?
    """, (
        new_status,
        user_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "is_active": bool(new_status),
        "message":
            "User unblocked successfully"
            if new_status
            else "User blocked successfully"
    })


@app.route(
    "/admin/api/users-v2/<int:user_id>/delete",
    methods=["POST"]
)
def admin_delete_user_v2(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if not admin_api_csrf_valid():
        return jsonify({
            "error": "Security validation failed"
        }), 403

    if user_id == session.get("user_id"):
        return jsonify({
            "error": "You cannot delete your own account"
        }), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT id, name, email, role
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({
            "error": "User not found"
        }), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({
            "error": "Admin accounts cannot be deleted"
        }), 400

    try:

        tables = [
            row["name"]
            for row in conn.execute("""
                SELECT name
                FROM sqlite_master
                WHERE type='table'
            """).fetchall()
        ]

        # Related records clean karo
        for table in tables:

            if table == "users":
                continue

            columns = [
                row["name"]
                for row in conn.execute(
                    f'PRAGMA table_info("{table}")'
                ).fetchall()
            ]

            if "user_id" in columns:
                conn.execute(
                    f'DELETE FROM "{table}" WHERE user_id = ?',
                    (user_id,)
                )

        conn.execute(
            "DELETE FROM users WHERE id = ?",
            (user_id,)
        )

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": "User deleted successfully"
        })

    except Exception as error:

        conn.rollback()
        conn.close()

        print("Delete user error:", error)

        return jsonify({
            "error": "Unable to delete user"
        }), 500


@app.before_request
def enforce_blocked_user_v2():

    user_id = session.get("user_id")

    if (
        not user_id
        or session.get("role") != "user"
    ):
        return None

    try:

        ensure_admin_user_status_column()

        conn = sqlite3.connect(DB_PATH)

        row = conn.execute("""
            SELECT is_active
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        conn.close()

        if row and not row[0]:

            session.clear()

            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Your account has been blocked by administrator"
                }), 403

            return redirect(
                "/user/login?blocked=1"
            )

    except Exception as error:
        print(
            "Blocked user check warning:",
            error
        )

    return None





# ==========================================================
# EXPLICIT ADMIN BLOCK / UNBLOCK
# ==========================================================

@app.route(
    "/admin/api/users-v3/<int:user_id>/block",
    methods=["POST"]
)
def admin_block_user_v3(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if user_id == session.get("user_id"):
        return jsonify({
            "error": "You cannot block your own admin account"
        }), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    columns = [
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "is_active" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1
        """)
        conn.commit()

    user = conn.execute("""
        SELECT id, role
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({
            "error": "User not found"
        }), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({
            "error": "Admin accounts are protected"
        }), 400

    conn.execute("""
        UPDATE users
        SET is_active = 0
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "User blocked successfully",
        "is_active": False
    })


@app.route(
    "/admin/api/users-v3/<int:user_id>/unblock",
    methods=["POST"]
)
def admin_unblock_user_v3(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT id, role
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({
            "error": "User not found"
        }), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({
            "error": "Admin accounts are protected"
        }), 400

    conn.execute("""
        UPDATE users
        SET is_active = 1
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "User unblocked successfully",
        "is_active": True
    })





# === FINAL ADMIN USER CONTROL ===

@app.route("/admin/api/user-control")
def admin_user_control_list():

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT
            id,
            name,
            email,
            role,
            is_active,
            created_at
        FROM users
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    token = None

    if "csrf_token" in globals():
        try:
            token = csrf_token()
        except Exception:
            pass

    return jsonify({
        "users": [
            {
                "id": row["id"],
                "name": row["name"],
                "email": row["email"],
                "role": row["role"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"]
            }
            for row in rows
        ],
        "csrf_token": token
    })


def admin_control_csrf_ok():

    if "valid_csrf" not in globals():
        return True

    import secrets

    saved = session.get("_csrf_token")

    sent = (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
    )

    if not saved or not sent:
        return False

    return secrets.compare_digest(
        str(saved),
        str(sent)
    )


@app.route(
    "/admin/api/user-control/<int:user_id>/block",
    methods=["POST"]
)
def admin_final_block_user(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if not admin_control_csrf_ok():
        return jsonify({"error": "Security validation failed"}), 403

    if user_id == session.get("user_id"):
        return jsonify({
            "error": "You cannot block your own admin account"
        }), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT id, role
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({
            "error": "Admin accounts are protected"
        }), 400

    conn.execute("""
        UPDATE users
        SET is_active = 0
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "User blocked successfully"
    })


@app.route(
    "/admin/api/user-control/<int:user_id>/unblock",
    methods=["POST"]
)
def admin_final_unblock_user(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if not admin_control_csrf_ok():
        return jsonify({"error": "Security validation failed"}), 403

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT id, role
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({
            "error": "Admin accounts are protected"
        }), 400

    conn.execute("""
        UPDATE users
        SET is_active = 1
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "User unblocked successfully"
    })


@app.route(
    "/admin/api/user-control/<int:user_id>/delete",
    methods=["POST"]
)
def admin_final_delete_user(user_id):

    if (
        not session.get("user_id")
        or session.get("role") != "admin"
    ):
        return jsonify({"error": "Unauthorized"}), 401

    if not admin_control_csrf_ok():
        return jsonify({"error": "Security validation failed"}), 403

    if user_id == session.get("user_id"):
        return jsonify({
            "error": "You cannot delete your own account"
        }), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    user = conn.execute("""
        SELECT id, role
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    if user["role"] == "admin":
        conn.close()
        return jsonify({
            "error": "Admin accounts are protected"
        }), 400

    try:

        tables = [
            row["name"]
            for row in conn.execute("""
                SELECT name
                FROM sqlite_master
                WHERE type='table'
            """)
        ]

        for table in tables:

            if table in ("users", "sqlite_sequence"):
                continue

            cols = [
                row["name"]
                for row in conn.execute(
                    f'PRAGMA table_info("{table}")'
                )
            ]

            if "user_id" in cols:
                conn.execute(
                    f'DELETE FROM "{table}" WHERE user_id = ?',
                    (user_id,)
                )

        conn.execute(
            "DELETE FROM users WHERE id = ?",
            (user_id,)
        )

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": "User deleted successfully"
        })

    except Exception as error:

        conn.rollback()
        conn.close()

        print("User delete error:", error)

        return jsonify({
            "error": "Unable to delete user"
        }), 500


@app.before_request
def final_blocked_user_guard():

    user_id = session.get("user_id")

    if (
        not user_id
        or session.get("role") != "user"
    ):
        return None

    try:

        conn = sqlite3.connect(DB_PATH)

        row = conn.execute("""
            SELECT is_active
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        conn.close()

        if row and row[0] == 0:

            session.clear()

            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Account blocked by administrator"
                }), 403

            return redirect("/user/login?blocked=1")

    except Exception as error:
        print("Blocked-user guard:", error)

    return None


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        debug=os.environ.get(
            "FLASK_DEBUG", ""
        ).strip().lower() in {"1", "true", "yes"},
        port=int(os.environ.get("PORT", "5000"))
    )
