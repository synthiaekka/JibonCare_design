from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random, os, smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# --- CONFIG ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# --- DB Setup ---
client = MongoClient(os.getenv("MONGO_URI"))
db = client["haatExpress"]
users = db["users"]

# --- Email Utility ---
def send_email(to_email, subject, body):
    sender_email = os.getenv("SMTP_EMAIL")
    sender_password = os.getenv("SMTP_PASSWORD")
    msg = MIMEText(body, "plain")
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        print(f"[EMAIL] Sent to {to_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

# --- ROUTES ---

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/grocery')
def grocery():
    return render_template("grocery.html")

@app.route('/medicine')
def medicine():
    return render_template("medicine.html")

@app.route('/restaurant')
def restaurant():
    return render_template("restaurant.html")

# =================== REGISTER ===================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        password = request.form["password"]

        if users.find_one({"email": email}):
            flash("Email already registered!", "danger")
            return redirect(url_for("register"))

        # Save temp user and send OTP
        otp = str(random.randint(100000, 999999))
        session["temp_user"] = {
            "name": name,
            "email": email,
            "phone": phone,
            "password": generate_password_hash(password),
            "otp": otp
        }

        send_email(email, "Your OTP - HaatExpress", f"Your OTP is {otp}")
        flash("OTP sent to your email. Please verify!", "info")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")

# =================== OTP VERIFICATION ===================
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "temp_user" not in session:
        return redirect(url_for("register"))

    if request.method == "POST":
        entered_otp = request.form["otp"]
        if entered_otp == session["temp_user"]["otp"]:
            # Save user to DB
            users.insert_one({
                "full_name": session["temp_user"]["name"],
                "email": session["temp_user"]["email"],
                "phone": session["temp_user"]["phone"],
                "password": session["temp_user"]["password"],
                "created_at": datetime.now()
            })
            session.pop("temp_user", None)
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid OTP. Try again!", "danger")

    return render_template("otp_verify.html")

# =================== LOGIN ===================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = users.find_one({"email": email})
        if user and check_password_hash(user["password"], password):
            session["user_email"] = user["email"]
            session["user_name"] = user["full_name"]
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid email or password!", "danger")

    return render_template("login.html")

# =================== FORGOT PASSWORD ===================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = users.find_one({"email": email})

        if not user:
            flash("Email not registered!", "danger")
            return redirect(url_for("forgot_password"))

        otp = str(random.randint(100000, 999999))
        session["reset_email"] = email
        session["reset_otp"] = otp
        send_email(email, "Password Reset OTP - HaatExpress", f"Your OTP is {otp}")
        flash("OTP sent to your email!", "info")
        return redirect(url_for("reset_password_otp"))

    return render_template("forgot_password.html")

# =================== RESET PASSWORD (OTP) ===================
@app.route("/reset-password-otp", methods=["GET", "POST"])
def reset_password_otp():
    if request.method == "POST":
        entered_otp = request.form["otp"]
        if entered_otp == session.get("reset_otp"):
            return redirect(url_for("set_new_password"))
        else:
            flash("Invalid OTP!", "danger")

    return render_template("reset_password_otp.html")

@app.route("/set-new-password", methods=["GET", "POST"])
def set_new_password():
    if request.method == "POST":
        password = request.form["password"]
        users.update_one(
            {"email": session["reset_email"]},
            {"$set": {"password": generate_password_hash(password)}}
        )
        session.pop("reset_email", None)
        session.pop("reset_otp", None)
        flash("Password updated! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("set_new_password.html")

# =================== LOGOUT ===================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))




# =================== RUN APP ===================
if __name__ == "__main__":
    app.run(debug=True)
