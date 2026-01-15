import os
import sqlite3
from flask import Blueprint, render_template, redirect, url_for, request, session, flash, g

idor_bp = Blueprint(
    "idor",
    __name__,
    template_folder="templates",
    static_folder="static"
)

# Path vers la base de ce challenge
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "ctf.db")
SECRET_KEY = os.environ.get("FLASK_SECRET", "idor_secret_for_local_dev")

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        g._database = db
    return db

@idor_bp.teardown_app_request
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

@idor_bp.route("/")
def index():
    if 'user_id' not in session:
        return render_template("index.html")
    return render_template("home.html", username=session.get("username"))

@idor_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Nom d'utilisateur et mot de passe requis.", "danger")
            return redirect(url_for("idor.register"))

        password_hash = generate_password_hash(password)
        try:
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, profile_data, created_at) VALUES (?, ?, 'user', ?, datetime('now'))",
                (username, password_hash, f"Profil de {username}")
            )
            conn.commit()
            new_id = cur.lastrowid
            cur.close()

            session["user_id"] = new_id
            session["username"] = username
            session["role"] = "user"
            flash("Compte créé et connecté.", "success")
            return redirect(f"/challenge/idor/user?id={new_id}")
        except sqlite3.IntegrityError:
            flash("Nom d'utilisateur déjà pris.", "danger")
            return redirect(url_for("idor.register"))
    return render_template("register.html")

@idor_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Connecté.", "success")
            return redirect(f"/challenge/idor/user?id={user['id']}")
        flash("Identifiants incorrects.", "danger")
        return redirect(url_for("idor.login"))
    return render_template("login.html")

@idor_bp.route("/logout")
def logout():
    session.clear()
    flash("Déconnecté.", "info")
    return redirect(url_for("idor.index"))

@idor_bp.route("/user")
def user_profile():
    if "user_id" not in session:
        return redirect(url_for("idor.login"))

    raw_id = request.args.get("id")
    if raw_id is None or raw_id == "":
        target_id = session["user_id"]
    else:
        try:
            target_id = int(raw_id)
        except ValueError:
            flash("id invalide.", "danger")
            return redirect(url_for("idor.index"))

    user = query_db(
        "SELECT id, username, role, profile_data FROM users WHERE id = ?",
        (target_id,),
        one=True
    )
    if not user:
        flash("Utilisateur non trouvé.", "warning")
        return redirect(url_for("idor.index"))
    return render_template("user.html", user=user)

@idor_bp.route("/submit-flag", methods=["POST"])
def submit_flag():
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "Non connecté"}), 403
    flag = request.form.get("flag", "").strip()
    if flag == "ER{succ3ss_JP0!}":
        return jsonify({"status": "success", "message": "Réussi ! 🎉"})
    else:
        return jsonify({"status": "fail", "message": "Incorrect."})
