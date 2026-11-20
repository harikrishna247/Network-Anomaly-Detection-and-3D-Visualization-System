import os
import re
import sqlite3
from pathlib import Path

from flask import request, redirect, url_for, render_template_string
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import netpulse_db

login_manager = LoginManager()

# Uses the same database location as netpulse_db when it exposes DB_PATH.
DB_PATH = Path(getattr(netpulse_db, "DB_PATH", "netpulse.db"))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

LOGIN_PAGE = """
<!doctype html>
<html>
<head>
    <title>{{ title }} - Network Monitor</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        body { margin:0; background:#F6F7F9; font-family:Arial,sans-serif; color:#111827; }
        .box { width:360px; max-width:calc(100% - 40px); margin:80px auto; background:white;
               border:1px solid #E5E7EB; border-radius:8px; padding:28px; box-sizing:border-box; }
        h2 { margin:0 0 20px; font-size:20px; }
        label { display:block; margin:12px 0 5px; font-size:13px; color:#4B5563; }
        input { width:100%; box-sizing:border-box; padding:10px; border:1px solid #D1D5DB;
                border-radius:6px; font-size:14px; }
        button { width:100%; margin-top:18px; padding:10px; border:0; border-radius:6px;
                 background:#2563EB; color:white; cursor:pointer; font-size:14px; }
        .error { color:#DC2626; font-size:13px; margin-bottom:12px; }
        .link { margin-top:16px; text-align:center; font-size:13px; color:#6B7280; }
        a { color:#2563EB; text-decoration:none; }
    </style>
</head>
<body>
<div class="box">
    <h2>{{ title }}</h2>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="post">
        <label>{{ 'Username' if signup else 'Username or email' }}</label>
        <input name="username" required autocomplete="username">
        {% if signup %}
        <label>Email (for threat alerts)</label>
        <input name="email" type="email" required autocomplete="email">
        {% endif %}
        <label>Password</label>
        <input name="password" type="password" required autocomplete="current-password">
        {% if signup %}
        <label>Confirm password</label>
        <input name="confirm_password" type="password" required autocomplete="new-password">
        {% endif %}
        <button type="submit">{{ button }}</button>
    </form>
    <div class="link">
        {% if signup %}
            Already have an account? <a href="/login">Log in</a>
        {% else %}
            No account? <a href="/signup">Create one</a>
        {% endif %}
    </div>
</div>
</body>
</html>
"""


class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = str(user_id)
        self.username = username


def _connect():
    return sqlite3.connect(str(DB_PATH), timeout=10)


def _ensure_users_table():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Let the supplied netpulse_db initialize/migrate its own tables first
    # (this also adds the users.email column if it is missing).
    netpulse_db.init_db()
    conn = _connect()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created TEXT,
                email TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()


@login_manager.user_loader
def load_user(user_id):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()
    return User(row[0], row[1]) if row else None


def init_auth(server):
    server.config["SECRET_KEY"] = os.environ.get(
        "NETPULSE_SECRET_KEY", "change-this-development-secret"
    )
    login_manager.init_app(server)
    login_manager.login_view = "login"
    _ensure_users_table()

    @server.route("/signup", methods=["GET", "POST"])
    def signup():
        if current_user.is_authenticated:
            return redirect("/")

        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if not username or not password or not email:
                error = "Username, email and password are required."
            elif len(username) < 3:
                error = "Username must be at least 3 characters."
            elif not EMAIL_RE.match(email):
                error = "Enter a valid email address."
            elif password != confirm:
                error = "Passwords do not match."
            elif len(password) < 6:
                error = "Password must be at least 6 characters."
            else:
                conn = _connect()
                try:
                    exists = conn.execute(
                        "SELECT 1 FROM users WHERE username = ? OR email = ?",
                        (username, email),
                    ).fetchone()
                    if exists:
                        error = "That username or email is already in use."
                    else:
                        cur = conn.execute(
                            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                            (username, generate_password_hash(password, method="pbkdf2:sha256"), email),
                        )
                        conn.commit()
                        login_user(User(cur.lastrowid, username))
                        return redirect("/")
                finally:
                    conn.close()

        return render_template_string(
            LOGIN_PAGE, title="Create account", button="Sign up", signup=True, error=error
        )

    @server.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect("/")

        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            conn = _connect()
            try:
                row = conn.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?",
                    (username, username.lower()),
                ).fetchone()
            finally:
                conn.close()

            if row and check_password_hash(row[2], password):
                login_user(User(row[0], row[1]))
                return redirect("/")
            error = "Invalid username/email or password."

        return render_template_string(
            LOGIN_PAGE, title="Log in", button="Log in", signup=False, error=error
        )

    @server.route("/logout")
    def logout():
        logout_user()
        return redirect("/login")

    @server.before_request
    def require_login():
        allowed = {"login", "signup", "logout", "static"}
        if request.endpoint in allowed or request.path.startswith("/assets/"):
            return None
        if current_user.is_authenticated:
            return None
        return redirect(url_for("login"))
import re
import sqlite3
from pathlib import Path

from flask import request, redirect, url_for, render_template_string
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import netpulse_db

login_manager = LoginManager()

# Uses the same database location as netpulse_db when it exposes DB_PATH.
DB_PATH = Path(getattr(netpulse_db, "DB_PATH", "netpulse.db"))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

LOGIN_PAGE = """
<!doctype html>
<html>
<head>
    <title>{{ title }} - Network Monitor</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        body { margin:0; background:#F6F7F9; font-family:Arial,sans-serif; color:#111827; }
        .box { width:360px; max-width:calc(100% - 40px); margin:80px auto; background:white;
               border:1px solid #E5E7EB; border-radius:8px; padding:28px; box-sizing:border-box; }
        h2 { margin:0 0 20px; font-size:20px; }
        label { display:block; margin:12px 0 5px; font-size:13px; color:#4B5563; }
        input { width:100%; box-sizing:border-box; padding:10px; border:1px solid #D1D5DB;
                border-radius:6px; font-size:14px; }
        button { width:100%; margin-top:18px; padding:10px; border:0; border-radius:6px;
                 background:#2563EB; color:white; cursor:pointer; font-size:14px; }
        .error { color:#DC2626; font-size:13px; margin-bottom:12px; }
        .link { margin-top:16px; text-align:center; font-size:13px; color:#6B7280; }
        a { color:#2563EB; text-decoration:none; }
    </style>
</head>
<body>
<div class="box">
    <h2>{{ title }}</h2>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="post">
        <label>{{ 'Username' if signup else 'Username or email' }}</label>
        <input name="username" required autocomplete="username">
        {% if signup %}
        <label>Email (for threat alerts)</label>
        <input name="email" type="email" required autocomplete="email">
        {% endif %}
        <label>Password</label>
        <input name="password" type="password" required autocomplete="current-password">
        {% if signup %}
        <label>Confirm password</label>
        <input name="confirm_password" type="password" required autocomplete="new-password">
        {% endif %}
        <button type="submit">{{ button }}</button>
    </form>
    <div class="link">
        {% if signup %}
            Already have an account? <a href="/login">Log in</a>
        {% else %}
            No account? <a href="/signup">Create one</a>
        {% endif %}
    </div>
</div>
</body>
</html>
"""


class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = str(user_id)
        self.username = username


def _connect():
    return sqlite3.connect(str(DB_PATH), timeout=10)


def _ensure_users_table():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Let the supplied netpulse_db initialize/migrate its own tables first
    # (this also adds the users.email column if it is missing).
    netpulse_db.init_db()
    conn = _connect()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created TEXT,
                email TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()


@login_manager.user_loader
def load_user(user_id):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()
    return User(row[0], row[1]) if row else None


def init_auth(server):
    server.config["SECRET_KEY"] = os.environ.get(
        "NETPULSE_SECRET_KEY", "change-this-development-secret"
    )
    login_manager.init_app(server)
    login_manager.login_view = "login"
    _ensure_users_table()

    @server.route("/signup", methods=["GET", "POST"])
    def signup():
        if current_user.is_authenticated:
            return redirect("/")

        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if not username or not password or not email:
                error = "Username, email and password are required."
            elif len(username) < 3:
                error = "Username must be at least 3 characters."
            elif not EMAIL_RE.match(email):
                error = "Enter a valid email address."
            elif password != confirm:
                error = "Passwords do not match."
            elif len(password) < 6:
                error = "Password must be at least 6 characters."
            else:
                conn = _connect()
                try:
                    exists = conn.execute(
                        "SELECT 1 FROM users WHERE username = ? OR email = ?",
                        (username, email),
                    ).fetchone()
                    if exists:
                        error = "That username or email is already in use."
                    else:
                        cur = conn.execute(
                            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                            (username, generate_password_hash(password, method="pbkdf2:sha256"), email),
                        )
                        conn.commit()
                        login_user(User(cur.lastrowid, username))
                        return redirect("/")
                finally:
                    conn.close()

        return render_template_string(
            LOGIN_PAGE, title="Create account", button="Sign up", signup=True, error=error
        )

    @server.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect("/")

        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            conn = _connect()
            try:
                row = conn.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ? OR email = ?",
                    (username, username.lower()),
                ).fetchone()
            finally:
                conn.close()

            if row and check_password_hash(row[2], password):
                login_user(User(row[0], row[1]))
                return redirect("/")
            error = "Invalid username/email or password."

        return render_template_string(
            LOGIN_PAGE, title="Log in", button="Log in", signup=False, error=error
        )

    @server.route("/logout")
    def logout():
        logout_user()
        return redirect("/login")

    @server.before_request
    def require_login():
        allowed = {"login", "signup", "logout", "static"}
        if request.endpoint in allowed or request.path.startswith("/assets/"):
            return None
        if current_user.is_authenticated:
            return None
        return redirect(url_for("login"))