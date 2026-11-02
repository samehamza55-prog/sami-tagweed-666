
import os, sqlite3, hashlib, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(APP_DIR, "data", "tajweed.sqlite"))
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-before-deploying-" + secrets.token_hex(12))

SEED = [
    ("إبراهيم عبد الماجد", "Ibrahim-26", 9.5),
    ("آدم حمزة", "Adam-26", 7.5),
    ("أحمد عادل", "Ahmad-26", 9.5),
    ("يحيى وجدي", "Yahya-26", 6.0),
    ("عبد الرحمن علاء", "Abdul-26", 5.0),
    ("تيم", "Taym-26", 5.0),
]
ADMIN_DEFAULT = os.environ.get("ADMIN_PASSWORD", "Tajweed-26")
ADMIN_HASH = generate_password_hash(ADMIN_DEFAULT)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn is not None: conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS tests (
      id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
      title TEXT NOT NULL, score REAL NOT NULL, max_score REAL NOT NULL,
      test_date TEXT DEFAULT '', note TEXT DEFAULT '',
      FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
    );
    """)
    count = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0]
    if count == 0:
        for i, (name, password, score) in enumerate(SEED, start=1):
            username = f"student{i}"
            conn.execute("INSERT INTO students(name,username,password_hash) VALUES(?,?,?)",
                         (name, username, generate_password_hash(password)))
            sid = conn.execute("SELECT id FROM students WHERE username=?", (username,)).fetchone()[0]
            conn.execute("INSERT INTO tests(student_id,title,score,max_score,test_date,note) VALUES(?,?,?,?,?,?)",
                         (sid, "الاختبار الأول", score, 10, "2026-11-02", "النتيجة الافتتاحية"))
    conn.commit(); conn.close()

init_db()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin": return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def student_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "student": return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        kind = request.form.get("kind")
        password = request.form.get("password", "")
        if kind == "admin" and check_password_hash(ADMIN_HASH, password):
            session.clear(); session["role"] = "admin"
            return redirect(url_for("dashboard"))
        if kind == "student":
            username = request.form.get("username", "").strip()
            row = db().execute("SELECT * FROM students WHERE username=? AND active=1", (username,)).fetchone()
            if row and check_password_hash(row["password_hash"], password):
                session.clear(); session["role"] = "student"; session["student_id"] = row["id"]
                return redirect(url_for("my_results"))
        flash("بيانات الدخول غير صحيحة. حاول مرة أخرى.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
@admin_required
def dashboard():
    students = db().execute("""SELECT s.*, COUNT(t.id) test_count,
      COALESCE(SUM(t.score),0) total_score, COALESCE(SUM(t.max_score),0) total_max
      FROM students s LEFT JOIN tests t ON t.student_id=s.id
      GROUP BY s.id ORDER BY s.id""").fetchall()
    tests = db().execute("""SELECT t.*,s.name FROM tests t JOIN students s ON s.id=t.student_id
      ORDER BY t.id DESC LIMIT 30""").fetchall()
    return render_template("admin.html", students=students, tests=tests)

@app.route("/admin/student/add", methods=["POST"])
@admin_required
def add_student():
    name=request.form.get("name","").strip()
    username=request.form.get("username","").strip()
    password=request.form.get("password","").strip()
    if not name or not username or len(password)<4:
        flash("أدخل الاسم واسم الدخول وكلمة مرور من 4 أحرف على الأقل.")
    else:
        try:
            db().execute("INSERT INTO students(name,username,password_hash) VALUES(?,?,?)",
                         (name,username,generate_password_hash(password)))
            db().commit(); flash("تمت إضافة الطالب.")
        except sqlite3.IntegrityError: flash("اسم الدخول مستخدم مسبقاً.")
    return redirect(url_for("dashboard"))

@app.route("/admin/student/<int:sid>/edit", methods=["POST"])
@admin_required
def edit_student(sid):
    name=request.form.get("name","").strip()
    password=request.form.get("password","").strip()
    active=1 if request.form.get("active")=="1" else 0
    if name:
        db().execute("UPDATE students SET name=?,active=? WHERE id=?", (name,active,sid))
    if password:
        db().execute("UPDATE students SET password_hash=? WHERE id=?", (generate_password_hash(password),sid))
    db().commit(); flash("تم تحديث بيانات الطالب.")
    return redirect(url_for("dashboard"))

@app.route("/admin/test/add", methods=["POST"])
@admin_required
def add_test():
    try:
        sid=int(request.form["student_id"]); score=float(request.form["score"]); maximum=float(request.form["max_score"])
        title=request.form["title"].strip()
        if maximum <= 0 or score < 0 or score > maximum or not title: raise ValueError()
        db().execute("INSERT INTO tests(student_id,title,score,max_score,test_date,note) VALUES(?,?,?,?,?,?)",
          (sid,title,score,maximum,request.form.get("test_date",""),request.form.get("note","").strip()))
        db().commit(); flash("تم حفظ نتيجة الاختبار.")
    except Exception: flash("تحقق من بيانات الاختبار والعلامة.")
    return redirect(url_for("dashboard"))

@app.route("/admin/test/<int:tid>/edit", methods=["POST"])
@admin_required
def edit_test(tid):
    try:
        score=float(request.form["score"]); maximum=float(request.form["max_score"])
        if maximum<=0 or score<0 or score>maximum: raise ValueError()
        db().execute("UPDATE tests SET title=?,score=?,max_score=?,test_date=?,note=? WHERE id=?",
          (request.form["title"].strip(),score,maximum,request.form.get("test_date",""),request.form.get("note",""),tid))
        db().commit(); flash("تم تعديل العلامة.")
    except Exception: flash("علامة غير صالحة.")
    return redirect(url_for("dashboard"))

@app.route("/admin/test/<int:tid>/delete", methods=["POST"])
@admin_required
def delete_test(tid):
    db().execute("DELETE FROM tests WHERE id=?", (tid,)); db().commit()
    flash("تم حذف الاختبار."); return redirect(url_for("dashboard"))

@app.route("/results")
@student_required
def my_results():
    sid=session["student_id"]
    student=db().execute("SELECT * FROM students WHERE id=?", (sid,)).fetchone()
    tests=db().execute("SELECT * FROM tests WHERE student_id=? ORDER BY id", (sid,)).fetchall()
    total=sum(x["score"] for x in tests); maximum=sum(x["max_score"] for x in tests)
    return render_template("results.html", student=student, tests=tests, total=total, maximum=maximum)

@app.errorhandler(404)
def not_found(e): return render_template("login.html"), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
