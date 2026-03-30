import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db_connection()
        cursor = db.cursor()

        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        cursor.close()
        db.close()

        if user and check_password_hash(user[3], password):
            session["username"] = user[2]
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    db = get_db_connection()
    cursor = db.cursor()

    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    transaction_cursor = db.cursor(dictionary=True)
    transaction_query = """
    SELECT action, account_type, amount, created_at
    FROM transactions
    WHERE username = %s
    ORDER BY created_at DESC
    """
    transaction_cursor.execute(transaction_query, (username,))
    transactions = transaction_cursor.fetchall()

    cursor.close()
    transaction_cursor.close()
    db.close()

    return render_template(
        "dashboard.html",
        name=user[1],
        username=user[2],
        checking=user[4],
        savings=user[5],
        transactions=transactions
    )

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))

@app.route("/deposit", methods=["POST"])
def deposit():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    account = request.form["account"]
    amount = float(request.form["amount"])

    if amount <= 0:
        return "Amount must be greater than zero."


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

    cursor.close()
    db.close()

    return redirect(url_for("dashboard"))

@app.route("/withdraw", methods=["POST"])
def withdraw():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    account = request.form["account"]
    amount = float(request.form["amount"])

    if amount <= 0:
        return "Amount must be greater than zero."


    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        "SELECT checking_balance, savings_balance FROM users WHERE username = %s",
        (username,)
    )
    user = cursor.fetchone()

    if account == "checking":
        current_balance = float(user["checking_balance"])
        if amount > current_balance:
            cursor.close()
            db.close()
            return "Insufficient checking balance."
        query = "UPDATE users SET checking_balance = checking_balance - %s WHERE username = %s"
    else:
        current_balance = float(user["savings_balance"])
        if amount > current_balance:
            cursor.close()
            db.close()
            return "Insufficient savings balance."
        query = "UPDATE users SET savings_balance = savings_balance - %s WHERE username = %s"

    cursor.execute(query, (amount, username))

    transaction_query = """
    INSERT INTO transactions (username, action, account_type, amount)
    VALUES (%s, %s, %s, %s)
    """
    cursor.execute(transaction_query, (username, "withdraw", account, amount))

    db.commit()

    cursor.close()
    db.close()

    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form["full_name"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        checking_balance = float(request.form["checking_balance"])
        savings_balance = float(request.form["savings_balance"])

        # Required fields check
        if not full_name or not username or not password:
            return render_template("register.html", error="All required fields must be filled out.")

        # Password strength check
        if len(password) < 8:
            return render_template("register.html", error="Password must be at least 8 characters long.")

        if checking_balance < 0 or savings_balance < 0:
            return render_template("register.html", error="Starting balances cannot be negative.")


        hashed_password = generate_password_hash(password)

        db = get_db_connection()
        cursor = db.cursor()

        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            db.close()
            return render_template("register.html", error="That username is already taken. Please choose another one.")

        query = """
        INSERT INTO users (full_name, username, password, checking_balance, savings_balance)
        VALUES (%s, %s, %s, %s, %s)
        """
        values = (full_name, username, hashed_password, checking_balance, savings_balance)

        cursor.execute(query, values)
        db.commit()

        cursor.close()
        db.close()

        return render_template("register_success.html", name=full_name)

    return render_template("register.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
