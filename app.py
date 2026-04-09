import os
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf import CSRFProtect
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta
import requests


load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.getenv("SECRET_KEY")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800

SIEM_API_URL = os.getenv("SIEM_API_URL", "http://127.0.0.1:5050/ingest")
SIEM_INGEST_API_KEY = os.getenv("SIEM_INGEST_API_KEY", "")

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

csrf = CSRFProtect(app)

if not os.path.exists("logs"):
    os.mkdir("logs")

file_handler = RotatingFileHandler("logs/bank_app.log", maxBytes=100000, backupCount=3)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(levelname)s: %(message)s"
))

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info("Bank of a Vibe Code startup")


def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )


def send_siem_event(event_type, severity, source_ip, message, app_name="bank_app", environment="prod"):
    payload = {
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "message": message,
        "app_name": app_name,
        "environment": environment,
    }

    headers = {"Content-Type": "application/json"}
    if SIEM_INGEST_API_KEY:
        headers["X-API-Key"] = SIEM_INGEST_API_KEY

    try:
        requests.post(SIEM_API_URL, json=payload, headers=headers, timeout=5)
    except Exception as e:
        app.logger.error("Failed to send SIEM event: %s", e)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        query = """
        SELECT id, username, password, failed_login_attempts, lockout_until
        FROM users
        WHERE username = %s
        """
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        # Check if account is locked
        if user and user["lockout_until"] is not None:
            if datetime.utcnow() < user["lockout_until"]:
                cursor.close()
                db.close()
                app.logger.warning(f"Locked account login attempt for username: {username} from IP: {request.remote_addr}")
                send_siem_event(
                    event_type="failed_login",
                    severity="low",
                    source_ip=request.remote_addr,
                    message=f"Locked account login attempt for username: {username}"
                )
                return render_template("login.html", error="Account temporarily locked. Please try again later.")

        # Successful login
        if user and check_password_hash(user["password"], password):
            reset_query = """
            UPDATE users
            SET failed_login_attempts = 0, lockout_until = NULL
            WHERE username = %s
            """
            cursor.execute(reset_query, (username,))
            db.commit()

            session.clear()
            session.permanent = True
            session["username"] = user["username"]

            app.logger.info(f"User logged in: {username} from IP: {request.remote_addr}")

            cursor.close()
            db.close()
            return redirect(url_for("dashboard"))

        # Failed login
        if user:
            new_attempts = user["failed_login_attempts"] + 1

            if new_attempts >= 5:
                lockout_time = datetime.utcnow() + timedelta(minutes=15)
                fail_query = """
                UPDATE users
                SET failed_login_attempts = %s, lockout_until = %s
                WHERE username = %s
                """
                cursor.execute(fail_query, (new_attempts, lockout_time, username))
                db.commit()

                app.logger.warning(f"Account locked for username: {username} from IP: {request.remote_addr}")
                send_siem_event(
                    event_type="failed_login",
                    severity="high",
                    source_ip=request.remote_addr,
                    message=f"Account locked after repeated failed logins for username: {username}"
                )

                cursor.close()
                db.close()
                return render_template("login.html", error="Account locked for 15 minutes due to too many failed attempts.")
            else:
                fail_query = """
                UPDATE users
                SET failed_login_attempts = %s
                WHERE username = %s
                """
                cursor.execute(fail_query, (new_attempts, username))
                db.commit()

        app.logger.warning(f"Failed login attempt for username: {username} from IP: {request.remote_addr}")
        send_siem_event(
            event_type="failed_login",
            severity="low",
            source_ip=request.remote_addr,
            message=f"Failed login attempt for username: {username}"
        )

        cursor.close()
        db.close()
        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    db = get_db_connection()

    user_cursor = db.cursor(dictionary=True)
    user_query = """
    SELECT username, checking_balance, savings_balance
    FROM users
    WHERE username = %s
    """
    user_cursor.execute(user_query, (username,))
    user = user_cursor.fetchone()

    transaction_cursor = db.cursor(dictionary=True)
    transaction_query = """
    SELECT action, account_type, amount, created_at
    FROM transactions
    WHERE username = %s
    ORDER BY created_at DESC
    """
    transaction_cursor.execute(transaction_query, (username,))
    transactions = transaction_cursor.fetchall()

    user_cursor.close()
    transaction_cursor.close()
    db.close()

    return render_template(
        "dashboard.html",
        user=user,
        transactions=transactions
    )


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))


@app.route("/deposit", methods=["POST"])
@limiter.limit("10 per minute")
def deposit():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    account = request.form["account"]
    try:
        amount = Decimal(request.form["amount"])
    except InvalidOperation:
        return redirect(url_for("dashboard"))

    if amount <= 0 or amount > Decimal("10000.00"):
        return redirect(url_for("dashboard"))

    db = get_db_connection()
    cursor = db.cursor()

    if account == "checking":
        query = "UPDATE users SET checking_balance = checking_balance + %s WHERE username = %s"
    else:
        query = "UPDATE users SET savings_balance = savings_balance + %s WHERE username = %s"

    cursor.execute(query, (amount, username))

    transaction_query = """
    INSERT INTO transactions (username, action, account_type, amount)
    VALUES (%s, %s, %s, %s)
    """
    cursor.execute(transaction_query, (username, "deposit", account, amount))

    db.commit()

    app.logger.info(f"Deposit: user={username} amount={amount} account={account}")

    cursor.close()
    db.close()

    return redirect(url_for("dashboard"))


@app.route("/withdraw", methods=["POST"])
@limiter.limit("10 per minute")
def withdraw():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    account = request.form["account"]

    try:
        amount = Decimal(request.form["amount"])
    except InvalidOperation:
        return redirect(url_for("dashboard"))

    if amount <= 0 or amount > Decimal("10000.00"):
        return redirect(url_for("dashboard"))

    db = get_db_connection()
    cursor = db.cursor()

    if account == "checking":
        query = """
        UPDATE users
        SET checking_balance = checking_balance - %s
        WHERE username = %s AND checking_balance >= %s
        """
    elif account == "savings":
        query = """
        UPDATE users
        SET savings_balance = savings_balance - %s
        WHERE username = %s AND savings_balance >= %s
        """
    else:
        cursor.close()
        db.close()
        return redirect(url_for("dashboard"))

    cursor.execute(query, (amount, username, amount))

    if cursor.rowcount == 0:
        db.rollback()
        cursor.close()
        db.close()
        return redirect(url_for("dashboard"))

    transaction_query = """
    INSERT INTO transactions (username, action, account_type, amount)
    VALUES (%s, %s, %s, %s)
    """
    cursor.execute(transaction_query, (username, "withdraw", account, amount))

    db.commit()
    cursor.close()
    db.close()

    app.logger.info(f"Withdraw: user={username} amount={amount} account={account}")

    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        full_name = request.form["full_name"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(full_name) > 100:
            return render_template("register.html", error="Full name is too long.")

        if len(username) > 50:
            return render_template("register.html", error="Username is too long.")

        if len(password) > 128:
            return render_template("register.html", error="Password is too long.")

        try:
            checking_balance = Decimal(request.form["checking_balance"])
            savings_balance = Decimal(request.form["savings_balance"])
        except InvalidOperation:
            return render_template("register.html", error="Invalid balance input.")

        if not full_name or not username or not password:
            return render_template("register.html", error="All required fields must be filled out.")

        if len(password) < 8:
            return render_template("register.html", error="Password must be at least 8 characters")

        if checking_balance < 0 or savings_balance < 0:
            return render_template("register.html", error="Starting balances cannot be negative.")

        hashed_password = generate_password_hash(password)

        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            db.close()
            return render_template("register.html", error="That username is already taken. Please choose another.")

        query = """
        INSERT INTO users (full_name, username, password, checking_balance, savings_balance)
        VALUES (%s, %s, %s, %s, %s)
        """
        values = (full_name, username, hashed_password, checking_balance, savings_balance)

        cursor.execute(query, values)
        db.commit()

        app.logger.info(f"New user registered: {username} from IP: {request.remote_addr}")

        cursor.close()
        db.close()

        return render_template("register_success.html", name=full_name)

    return render_template("register.html")


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    return response


@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("login.html", error="Too many login attempts. Please wait a minute and try again."), 429


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
