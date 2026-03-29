from flask import Flask, render_template, request, redirect, url_for
import mysql.connector

app = Flask(__name__)

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="jadenapp",
        password="Password123!",
        database="bank"
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

        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        values = (username, password)

        cursor.execute(query, values)
        user = cursor.fetchone()

        cursor.close()
        db.close()

        if user:
            return redirect(url_for("dashboard", username=user[2]))
        else:
            return "Invalid username or password."

    return render_template("login.html")

@app.route("/dashboard/<username>")
def dashboard(username):
    db = get_db_connection()
    cursor = db.cursor()

    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    cursor.close()
    db.close()

    return render_template(
        "dashboard.html",
        name=user[1],
        username=user[2],
        checking=user[4],
        savings=user[5]
    )

@app.route("/deposit", methods=["POST"])
def deposit():
    username = request.form["username"]
    account = request.form["account"]
    amount = float(request.form["amount"])

    db = get_db_connection()
    cursor = db.cursor()

    if account == "checking":
        query = "UPDATE users SET checking_balance = checking_balance + %s WHERE username = %s"
    else:
        query = "UPDATE users SET savings_balance = savings_balance + %s WHERE username = %s"

    values = (amount, username)

    cursor.execute(query, values)
    db.commit()

    cursor.close()
    db.close()

    return redirect(url_for("dashboard", username=username))

@app.route("/withdraw", methods=["POST"])
def withdraw():
    username = request.form["username"]
    account = request.form["account"]
    amount = float(request.form["amount"])

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
            return "Withdrawal failed: insufficient checking balance."
        query = "UPDATE users SET checking_balance = checking_balance - %s WHERE username = %s"
    else:
        current_balance = float(user["savings_balance"])
        if amount > current_balance:
            cursor.close()
            db.close()
            return "Withdrawal failed: insufficient savings balance."
        query = "UPDATE users SET savings_balance = savings_balance - %s WHERE username = %s"

    cursor.execute(query, (amount, username))
    db.commit()

    cursor.close()
    db.close()

    return redirect(url_for("dashboard", username=username))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form["full_name"]
        username = request.form["username"]
        password = request.form["password"]
        checking_balance = request.form["checking_balance"]
        savings_balance = request.form["savings_balance"]

        db = get_db_connection()
        cursor = db.cursor()

        query = """
        INSERT INTO users (full_name, username, password, checking_balance, savings_balance)
        VALUES (%s, %s, %s, %s, %s)
        """
        values = (full_name, username, password, checking_balance, savings_balance)

        cursor.execute(query, values)
        db.commit()

        cursor.close()
        db.close()

        return f"Account created successfully for {full_name}!"

    return render_template("register.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
