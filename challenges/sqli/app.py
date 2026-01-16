import os
import sqlite3
from flask import Blueprint, request, g, render_template, redirect, url_for, session

sqli_bp = Blueprint(
    "sqli",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/sqli-static"
)

# Configuration
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "challenge.db")
SECRET_KEY = os.environ.get("FLASK_SECRET", "dev_secret_for_local_only")
VULNERABLE = os.environ.get("VULNERABLE", "1").lower() in ("1", "true", "yes")

# Connexion à la base SQLite
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g._database = conn
    return g._database

@sqli_bp.teardown_app_request
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# Page d'accueil du challenge SQL
@sqli_bp.route("/")
def index():
    mode = "VULNÉRABLE" if VULNERABLE else "SÉCURISÉE"
    return render_template("sqli/index.html", mode=mode)

# Indique le mode (utile pour scripts de test)
@sqli_bp.route("/mode")
def mode():
    return ("vulnerable" if VULNERABLE else "safe"), 200, {
        "Content-Type": "text/plain; charset=utf-8"
    }

# Login
@sqli_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("sqli/login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    cursor = db.cursor()

    if VULNERABLE:
        # ---------- VERSION VULNÉRABLE ----------
        sql = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
            username,
            password
        )
        try:
            cursor.execute(sql)
            row = cursor.fetchone()
        except Exception as e:
            return render_template(
                "sqli/result.html",
                status="error",
                message=f"Erreur SQL (mode vulnérable) : {e}"
            )
    else:
        # ---------- VERSION SÉCURISÉE ----------
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        row = cursor.fetchone()

    if row:
        session["user"] = row["username"]
        return render_template(
            "sqli/result.html",
            status="ok",
            message=(
                "Authentification réussie. "
                f"Vous êtes connecté en tant que <strong>{row['username']}</strong>."
            )
        )
    else:
        return render_template(
            "sqli/result.html",
            status="fail",
            message="Échec de la connexion. Nom d'utilisateur ou mot de passe incorrect."
        )

# Flag
@sqli_bp.route("/flag")
def flag():
    user = session.get("user")
    if not user:
        return render_template(
            "sqli/flag.html",
            ok=False,
            message="Accès refusé : vous devez être connecté."
        )
    if user != "admin":
        return render_template(
            "sqli/flag.html",
            ok=False,
            message="Accès refusé : compte non autorisé pour voir le flag."
        )

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT flag FROM flags LIMIT 1")
    row = cur.fetchone()

    if row:
        return render_template("sqli/flag.html", ok=True, flag=row["flag"])
    else:
        return render_template(
            "sqli/flag.html",
            ok=False,
            message="Aucun flag trouvé."
        )

# Logout
@sqli_bp.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("sqli.index"))
