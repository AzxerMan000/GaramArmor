import os
import json
import secrets
import requests
from functools import wraps
from flask import Flask, redirect, request, session, render_template, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeme")

WHITELIST_FILE = "whitelist.json"
PROTECTED_SCRIPT = """-- Protected Lua Script
print("Welcome to GaramArmor!")
game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = 100
"""

def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("is_admin"):
            return f(*args, **kwargs)
        if request.method == "POST":
            if request.form.get("admin_pass") == ADMIN_PASS:
                session["is_admin"] = True
                return f(*args, **kwargs)
        return redirect(url_for("admin_login"))
    return wrapper

@app.route("/")
def home():
    user = session.get("user")
    return render_template("index.html", user=user)

@app.route("/login")
def login():
    scope = "identify"
    return redirect(f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={scope}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "scope": "identify"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post("https://discord.com/api/oauth2/token", data=data, headers=headers)
    if r.status_code != 200:
        return f"Error fetching token: {r.text}", 400

    access_token = r.json().get("access_token")
    user_resp = requests.get("https://discord.com/api/users/@me", headers={"Authorization": f"Bearer {access_token}"})
    if user_resp.status_code != 200:
        return "Failed to fetch user info", 400

    user = user_resp.json()
    session["user"] = user
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/script")
def script():
    user = session.get("user")
    if not user:
        return redirect("/login")

    whitelist = load_json(WHITELIST_FILE, {"users": []}).get("users", [])
    if str(user.get("id")) not in whitelist:
        return render_template("access_denied.html", user=user)

    return render_template("script.html", script=PROTECTED_SCRIPT, user=user)

@app.route("/admin", methods=["GET", "POST"])
@require_admin
def admin():
    whitelist = load_json(WHITELIST_FILE, {"users": []}).get("users", [])

    if request.method == "POST":
        discord_id = request.form.get("discord_id")
        if discord_id and discord_id not in whitelist:
            whitelist.append(discord_id)
            save_json(WHITELIST_FILE, {"users": whitelist})

    return render_template("admin.html", whitelist=whitelist)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        if request.form.get("admin_pass") == ADMIN_PASS:
            session["is_admin"] = True
            return redirect("/admin")
        error = "Incorrect password"
    return render_template("admin_login.html", error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
    