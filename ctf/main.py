from flask import Flask, render_template
from challenges.idor.app import idor_bp
from challenges.sql.app import sqli_bp

app = Flask(__name__)
app.secret_key = "ctf_master_secret"

app.register_blueprint(idor_bp, url_prefix="/challenge/idor")
app.register_blueprint(sqli_bp, url_prefix="/challenge/sql")

@app.route("/")
def index():
    return render_template("ctf_index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
