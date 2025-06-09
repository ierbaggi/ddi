from flask import Flask, render_template, request, redirect, send_file, session, url_for
import os, datetime, sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from fpdf import FPDF
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cambiame")  # Pon un SECRET_KEY en prod
UPLOAD_FOLDER = "uploads"
DB_PATH = "history.db"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# --- Inicializar BD ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        pwd_hash TEXT,
                        is_admin INTEGER
                    )""")
        c.execute("""CREATE TABLE IF NOT EXISTS analysis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT,
                        company TEXT,
                        filename TEXT,
                        keyword TEXT,
                        timestamp TEXT
                    )""")
        conn.commit()
init_db()

# --- Login requerido ---
from functools import wraps
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

# --- Rutas de autenticación ---
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form["username"]
        p=request.form["password"]
        with sqlite3.connect(DB_PATH) as conn:
            c=conn.cursor()
            c.execute("SELECT pwd_hash FROM users WHERE username=?", (u,))
            row=c.fetchone()
        if row and check_password_hash(row[0], p):
            session["user"]=u
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Credenciales inválidas")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- Cambio de contraseña ---
@app.route("/change-password", methods=["GET","POST"])
@login_required
def change_password():
    if request.method=="POST":
        old=request.form["old_password"]
        new=request.form["new_password"]
        with sqlite3.connect(DB_PATH) as conn:
            c=conn.cursor()
            c.execute("SELECT pwd_hash FROM users WHERE username=?", (session["user"],))
            row=c.fetchone()
            if row and check_password_hash(row[0], old):
                new_hash=generate_password_hash(new)
                c.execute("UPDATE users SET pwd_hash=? WHERE username=?", (new_hash, session["user"]))
                conn.commit()
                return render_template("change-password.html", msg="Contraseña cambiada")
        return render_template("change-password.html", error="Contraseña actual incorrecta")
    return render_template("change-password.html")

# --- Backoffice (solo admin) ---
@app.route("/admin/users", methods=["GET","POST"])
@login_required
def manage_users():
    with sqlite3.connect(DB_PATH) as conn:
        c=conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE username=?", (session["user"],))
        is_admin = c.fetchone()[0]
    if not is_admin:
        return "Acceso denegado", 403

    if request.method=="POST":
        if "add" in request.form:
            u=request.form["new_user"]
            p=request.form["new_pass"]
            h=generate_password_hash(p)
            ia=1 if request.form.get("is_admin") else 0
            with sqlite3.connect(DB_PATH) as conn:
                conn.cursor().execute("INSERT INTO users (username,pwd_hash,is_admin) VALUES(?,?,?)",(u,h,ia))
                conn.commit()
        elif "del" in request.form:
            with sqlite3.connect(DB_PATH) as conn:
                conn.cursor().execute("DELETE FROM users WHERE username=?", (request.form["del_user"],))
                conn.commit()
    with sqlite3.connect(DB_PATH) as conn:
        users=conn.cursor().execute("SELECT username,is_admin FROM users").fetchall()
    return render_template("manage-users.html", users=users)

# --- Página principal y análisis ---
KEYWORDS=["beneficial owner","tax id","source of funds","public office","pep"]
@app.route("/", methods=["GET"])
@login_required
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    files=request.files.getlist("files")
    company=request.form["company_name"]
    ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings=[]
    for f in files:
        fn=secure_filename(f.filename)
        pth=os.path.join(UPLOAD_FOLDER,fn)
        f.save(pth)
        text=open(pth, "r", errors="ignore").read().lower()
        for kw in KEYWORDS:
            if kw in text:
                findings.append((fn,kw))
                with sqlite3.connect(DB_PATH) as conn:
                    conn.cursor().execute(
                        "INSERT INTO analysis (user,company,filename,keyword,timestamp) VALUES(?,?,?,?,?)",
                        (session["user"], company, fn, kw, ts)
                    )
                    conn.commit()
    return render_template("results.html", company=company, findings=findings, timestamp=ts)

# --- Descarga de informe PDF ---
@app.route("/download/<company>/<timestamp>")
@login_required
def download(company, timestamp):
    fname=f"report_{company}_{timestamp.replace(':','-').replace(' ','_')}.pdf"
    fp=os.path.join(REPORT_FOLDER,fname)
    pdf=FPDF(); pdf.add_page(); pdf.set_font("Arial",size=12)
    pdf.cell(200,10,txt=f"Report - {company}",ln=1)
    pdf.cell(200,10,txt=f"Date: {timestamp}",ln=2); pdf.ln(10)
    pdf.cell(200,10,txt="Detected:",ln=3)
    rows=sqlite3.connect(DB_PATH).cursor().execute(
        "SELECT filename,keyword FROM analysis WHERE company=? AND timestamp=?",
        (company,timestamp)
    ).fetchall()
    if rows:
        for r in rows: pdf.cell(200,10,txt=f"{r[0]} → {r[1]}",ln=1)
    else:
        pdf.cell(200,10,txt="None found",ln=1)
    pdf.output(fp)
    return send_file(fp, as_attachment=True)

# --- Historial y auditoría ---
@app.route("/history")
@login_required
def history():
    rec=sqlite3.connect(DB_PATH).cursor().execute(
        "SELECT user,company,filename,keyword,timestamp FROM analysis ORDER BY timestamp DESC"
    ).fetchall()
    return render_template("history.html", records=rec)

if __name__=="__main__":
    app.run()
