from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
import sqlite3
import time
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
import os
load_dotenv()
app = Flask(__name__)
csrf = CSRFProtect(app)

app.secret_key = os.getenv("SECRET_KEY")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

bcrypt = Bcrypt(app)
login_attempts = {}
MAX_ATTEMPTS = 5
LOCK_TIME = 60

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


# Create database
with get_db() as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)


@app.route("/")
def home():
    if "username" not in session:
        return redirect("/login")

    return render_template(
        "home.html",
        username=session["username"]
    )


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            return "Username must contain at least 3 characters."

        if len(password) < 8:
            return "Password must contain at least 8 characters."

        if not any(char.isupper() for char in password):
            return "Password must contain at least one uppercase letter."

        if not any(char.isdigit() for char in password):
            return "Password must contain at least one number."

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")
        try:
            with get_db() as conn:

                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_password)
                )

                conn.commit()

            return redirect("/login")

        except sqlite3.IntegrityError:
            return "Username already exists."

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        current_time = time.time()

        # Check previous failed attempts
        if username in login_attempts:

            attempts, last_attempt = login_attempts[username]

            if attempts >= MAX_ATTEMPTS:

                if current_time - last_attempt < LOCK_TIME:
                    return render_template(
    "login.html",
    error="Too many failed attempts. Please try again later."
)

                else:
                    login_attempts[username] = (0, current_time)

        with get_db() as conn:

            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and bcrypt.check_password_hash(
            user["password"],
            password
        ):

            login_attempts.pop(username, None)

            session.clear()
            session["username"] = user["username"]

            return redirect("/")

        # Record failed attempt
        attempts, _ = login_attempts.get(username, (0, current_time))

        login_attempts[username] = (
            attempts + 1,
            current_time
        )

        return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)