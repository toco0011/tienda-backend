"""Backend de la tienda — Flask + SQLite + API REST."""
import os, re, secrets, sqlite3, time
from functools import wraps
from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

# ================== CONFIGURACIÓN (variables de entorno) ==================
BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "tienda.db"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()   # correo del administrador
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")              # contraseña inicial (mín. 10 caracteres)
ADMIN_FORCE_RESET = os.environ.get("ADMIN_FORCE_RESET") == "1"     # 1 = restablece la clave desde ADMIN_PASSWORD
# Orígenes permitidos, separados por coma. Admite comodín: https://mitienda.netlify.app,https://*.netlify.app
ALLOWED = os.environ.get("ALLOWED_ORIGINS", "*")
MIN_PASS = 10
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$")
TOKEN_HORAS = 12
PUBLIC_KEYS = ("name", "sub", "title", "lead", "tag", "hero", "heroVideo", "theme")
MAXLEN = {"name": 60, "sub": 120, "title": 120, "lead": 400, "tag": 80}

app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024  # 12 MB por petición
def cors_origins():
    if ALLOWED.strip() == "*": return "*"
    out = []
    for o in (x.strip().rstrip("/") for x in ALLOWED.split(",")):  # sin "/" final: el navegador no la envía
        if not o: continue
        out.append(re.compile("^" + re.escape(o).replace(r"\*", "[a-z0-9-]+") + "$", re.I) if "*" in o else o)
    return out

CORS(app, supports_credentials=False, resources={r"/api/*": {
    "origins": cors_origins(), "methods": ["GET", "POST", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"], "max_age": 86400}})

# ================== BASE DE DATOS ==================
SCHEMA = """
CREATE TABLE IF NOT EXISTS config(clave TEXT PRIMARY KEY, valor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS productos(
  id TEXT PRIMARY KEY, nombre TEXT NOT NULL, precio REAL NOT NULL DEFAULT 0,
  descripcion TEXT NOT NULL DEFAULT '', imagen TEXT NOT NULL, video TEXT NOT NULL DEFAULT '',
  medidas TEXT NOT NULL, orden INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS temas(
  id TEXT PRIMARY KEY, nombre TEXT NOT NULL, bg TEXT NOT NULL, fg TEXT NOT NULL, ac TEXT NOT NULL, cd TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admins(
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);
"""
VID = "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4"
CH = "S,90,66,43\nM,96,69,45\nL,102,72,47\nXL,108,74,49"  # talla,pecho,largo,hombro (cm)
SEED_CONFIG = {"name": "APEX LAB", "sub": "Rendimiento sin límites", "title": "Remeras de|compresión",
               "lead": "Diseñadas para moverse contigo. Máximo rendimiento, ajuste perfecto y estilo imparable.",
               "tag": "Entrena|con actitud", "hero": "hero.jpg", "heroVideo": "", "theme": "normal", "version": "1"}
SEED_TEMAS = [("normal", "Normal", "#0a0a0a", "#f5f5f5", "#e5e5e5", "#141414"),
              ("halloween", "Halloween", "#0b0705", "#fff4e6", "#ff7a00", "#1a0f08"),
              ("navidad", "Navidad", "#07120b", "#ffffff", "#e11d2e", "#0f2417")]
SEED_PROD = [("p1", "Aero Compression Tee — Black", 34990, "Compresión media, tejido 4-way stretch y secado rápido.", "https://picsum.photos/seed/tee1/900/1100"),
             ("p2", "Apex Fit Tee — Slate", 32990, "Corte athletic fit que marca el físico sin restringir.", "https://picsum.photos/seed/tee2/900/1100"),
             ("p3", "Titan Long Sleeve — Onyx", 39990, "Manga larga con costuras planas anti-roce.", "https://picsum.photos/seed/tee3/900/1100")]

def init_db():
    folder = os.path.dirname(DB_PATH)
    if folder: os.makedirs(folder, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    for k, v in SEED_CONFIG.items():
        con.execute("INSERT OR IGNORE INTO config VALUES(?,?)", (k, v))
    con.execute("INSERT OR IGNORE INTO config VALUES('_secret',?)", (secrets.token_hex(32),))
    if not con.execute("SELECT 1 FROM config WHERE clave='seeded'").fetchone():  # datos de ejemplo, solo la 1ª vez
        con.executemany("INSERT OR IGNORE INTO temas VALUES(?,?,?,?,?,?)", SEED_TEMAS)
        for i, (pid, n, pr, d, img) in enumerate(SEED_PROD):
            con.execute("INSERT OR IGNORE INTO productos VALUES(?,?,?,?,?,?,?,?)", (pid, n, pr, d, img, VID, CH, i))
        con.execute("INSERT INTO config VALUES('seeded','1')")
    if ADMIN_EMAIL and ADMIN_PASSWORD and EMAIL_RE.match(ADMIN_EMAIL):  # crea el administrador desde las variables
        fila = con.execute("SELECT id FROM admins ORDER BY id LIMIT 1").fetchone()  # un solo administrador
        if not fila:  # primera vez (o base reiniciada): se crea desde las variables
            con.execute("INSERT INTO admins(email,password_hash) VALUES(?,?)", (ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD)))
        elif ADMIN_FORCE_RESET:  # recuperación: fuerza correo y clave de las variables
            con.execute("UPDATE admins SET email=?, password_hash=? WHERE id=?", (ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD), fila[0]))
        if len(ADMIN_PASSWORD) < MIN_PASS: print(f"⚠ ADMIN_PASSWORD tiene menos de {MIN_PASS} caracteres: cámbiala.")
    elif not con.execute("SELECT 1 FROM admins").fetchone():
        print("⚠ No hay administrador: define ADMIN_EMAIL (válido) y ADMIN_PASSWORD para poder iniciar sesión.")
    con.commit(); con.close()

init_db()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def _close(_):
    con = g.pop("db", None)
    if con is not None: con.close()

def cfg():
    return {r["clave"]: r["valor"] for r in db().execute("SELECT clave, valor FROM config")}

def setcfg(k, v):
    db().execute("INSERT INTO config VALUES(?,?) ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor", (k, v))

def bump():  # sube la versión: el frontend detecta así que hubo cambios
    db().execute("UPDATE config SET valor=CAST(valor AS INTEGER)+1 WHERE clave='version'")

def err(msg, code=400):
    return jsonify({"error": msg}), code

# ================== VALIDACIÓN ==================
URL_RE = re.compile(r"^(https?://|data:(image|video)/|[\w./-]+$)", re.I)  # bloquea javascript:
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

def clean_url(v, required=False):
    v = str(v or "").strip()
    if not v:
        if required: raise ValueError("Falta la imagen")
        return ""
    if not URL_RE.match(v): raise ValueError("URL no válida (usa http(s):// o sube un archivo)")
    return v

def clean_chart(v):
    rows = []
    for line in str(v or "").strip().splitlines():
        p = [x.strip() for x in line.split(",")]
        try:
            assert len(p) == 4 and p[0] and len(p[0]) <= 8
            [float(x) for x in p[1:]]
        except (AssertionError, ValueError):
            raise ValueError(f"Fila de medidas inválida «{line[:30]}». Formato: talla,pecho,largo,hombro")
        rows.append(",".join(p))
    if not rows: raise ValueError("Agrega al menos una talla")
    if len(rows) > 12: raise ValueError("Máximo 12 tallas")
    return "\n".join(rows)

# ================== AUTENTICACIÓN ==================
FAILS = {}  # intentos fallidos recientes (en memoria), por IP y por correo
DUMMY = generate_password_hash("no-existe")  # se compara igual si el correo no existe (no revela cuentas)

def serializer():
    return URLSafeTimedSerializer(os.environ.get("SECRET_KEY") or cfg()["_secret"], salt="admin")

def new_token(adm):  # el token lleva el id y una huella de la clave: al cambiarla, las sesiones viejas caducan
    return serializer().dumps({"id": adm["id"], "p": adm["password_hash"][-10:]})

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        t = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        try: data = serializer().loads(t, max_age=TOKEN_HORAS * 3600)
        except BadSignature: return err("Sesión inválida o expirada", 401)
        adm = db().execute("SELECT * FROM admins WHERE id=?", (data.get("id"),)).fetchone()
        if not adm or adm["password_hash"][-10:] != data.get("p"): return err("Sesión inválida o expirada", 401)
        g.admin = adm
        return f(*a, **k)
    return wrapper

def bloqueado(claves):
    now, bloq = time.time(), False
    if len(FAILS) > 5000: FAILS.clear()
    for k, mx in claves:
        FAILS[k] = [t for t in FAILS.get(k, []) if now - t < 300]
        bloq = bloq or len(FAILS[k]) >= mx
    return bloq

@app.post("/api/admin/login")
def login():
    d = request.get_json(silent=True) or {}
    email, pw = str(d.get("email", "")).strip().lower()[:254], str(d.get("password", ""))[:200]
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    claves = [("ip:" + ip, 8), ("mail:" + email, 15)]
    if bloqueado(claves): return err("Demasiados intentos. Espera 5 minutos.", 429)
    adm = db().execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone() if EMAIL_RE.match(email) else None
    ok = check_password_hash(adm["password_hash"] if adm else DUMMY, pw) and adm is not None
    if not ok:
        for k, _ in claves: FAILS[k].append(time.time())
        return err("Correo o contraseña incorrectos", 401)
    for k, _ in claves: FAILS.pop(k, None)
    return jsonify({"token": new_token(adm), "email": adm["email"], "expira_horas": TOKEN_HORAS})

# ================== API PÚBLICA ==================
@app.get("/api/tienda")
def tienda():
    c = cfg()
    prods = [{"id": r["id"], "name": r["nombre"], "price": int(r["precio"]) if r["precio"] == int(r["precio"]) else r["precio"],
              "desc": r["descripcion"], "img": r["imagen"], "video": r["video"], "chart": r["medidas"]}
             for r in db().execute("SELECT * FROM productos ORDER BY orden, rowid")]
    temas = {r["id"]: {"n": r["nombre"], "bg": r["bg"], "fg": r["fg"], "ac": r["ac"], "cd": r["cd"]}
             for r in db().execute("SELECT * FROM temas ORDER BY rowid")}
    resp = jsonify({"config": {k: c.get(k, "") for k in PUBLIC_KEYS}, "themes": temas,
                    "products": prods, "version": int(c.get("version", "1"))})
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ================== API ADMIN ==================
@app.post("/api/admin/productos")
@admin_required
def guardar_producto():
    d = request.get_json(silent=True) or {}
    try:
        nombre = str(d.get("name", "")).strip()[:120]
        if not nombre: raise ValueError("Falta el nombre")
        try: precio = float(d.get("price") or 0)
        except (TypeError, ValueError): raise ValueError("Precio inválido")
        if not 0 <= precio <= 1e9: raise ValueError("Precio inválido")
        desc = str(d.get("desc", "")).strip()[:1000]
        img, video, medidas = clean_url(d.get("img"), True), clean_url(d.get("video")), clean_chart(d.get("chart"))
    except ValueError as e:
        return err(str(e))
    con, pid = db(), str(d.get("id") or "").strip()
    if pid and con.execute("SELECT 1 FROM productos WHERE id=?", (pid,)).fetchone():
        con.execute("UPDATE productos SET nombre=?,precio=?,descripcion=?,imagen=?,video=?,medidas=? WHERE id=?",
                    (nombre, precio, desc, img, video, medidas, pid))
    else:
        pid = "p" + secrets.token_hex(4)
        orden = con.execute("SELECT COALESCE(MAX(orden),-1)+1 FROM productos").fetchone()[0]
        con.execute("INSERT INTO productos VALUES(?,?,?,?,?,?,?,?)", (pid, nombre, precio, desc, img, video, medidas, orden))
    bump(); con.commit()
    return jsonify({"ok": True, "id": pid})

@app.delete("/api/admin/productos/<pid>")
@admin_required
def borrar_producto(pid):
    if db().execute("DELETE FROM productos WHERE id=?", (pid,)).rowcount == 0: return err("Producto no encontrado", 404)
    bump(); db().commit()
    return jsonify({"ok": True})

@app.post("/api/admin/config")
@admin_required
def cambiar_config():
    d, con, token = request.get_json(silent=True) or {}, db(), None
    try:
        if (d.get("password") or d.get("email")) and not check_password_hash(g.admin["password_hash"], str(d.get("current_password", ""))):
            raise ValueError("Escribe tu contraseña actual para cambiar el correo o la contraseña")
        for k in PUBLIC_KEYS:
            if k not in d: continue
            v = str(d[k] or "").strip()
            if k in ("hero", "heroVideo"): v = clean_url(v)
            elif k == "theme":
                if not con.execute("SELECT 1 FROM temas WHERE id=?", (v,)).fetchone(): raise ValueError("Temática inexistente")
            else: v = v[:MAXLEN[k]]
            setcfg(k, v)
        if d.get("password"):
            pw = str(d["password"])
            if len(pw) < MIN_PASS or pw.lower() == g.admin["email"]:
                raise ValueError(f"La contraseña debe tener al menos {MIN_PASS} caracteres y no ser tu correo")
            con.execute("UPDATE admins SET password_hash=? WHERE id=?", (generate_password_hash(pw), g.admin["id"]))
            token = True
        if d.get("email"):
            em = str(d["email"]).strip().lower()
            if not EMAIL_RE.match(em): raise ValueError("Correo no válido")
            if con.execute("SELECT 1 FROM admins WHERE email=? AND id<>?", (em, g.admin["id"])).fetchone():
                raise ValueError("Ese correo ya está en uso")
            con.execute("UPDATE admins SET email=? WHERE id=?", (em, g.admin["id"]))
    except ValueError as e:
        con.rollback()
        return err(str(e))
    bump(); con.commit()
    out = {"ok": True}
    if token: out["token"] = new_token(con.execute("SELECT * FROM admins WHERE id=?", (g.admin["id"],)).fetchone())  # sesión nueva
    return jsonify(out)

@app.post("/api/admin/temas")
@admin_required
def crear_tema():
    d = request.get_json(silent=True) or {}
    nombre = str(d.get("n", "")).strip()[:40]
    cols = [str(d.get(k, "")) for k in ("bg", "fg", "ac", "cd")]
    if not nombre or not all(HEX_RE.match(c) for c in cols): return err("Nombre o colores inválidos")
    tid = "t" + secrets.token_hex(4)
    db().execute("INSERT INTO temas VALUES(?,?,?,?,?,?)", (tid, nombre, *cols))
    bump(); db().commit()
    return jsonify({"ok": True, "id": tid})

@app.delete("/api/admin/temas/<tid>")
@admin_required
def borrar_tema(tid):
    con = db()
    if cfg().get("theme") == tid: return err("Es la temática activa: cambia de temática antes de eliminarla")
    if con.execute("SELECT COUNT(*) FROM temas").fetchone()[0] <= 1: return err("Debe quedar al menos una temática")
    if con.execute("DELETE FROM temas WHERE id=?", (tid,)).rowcount == 0: return err("Temática no encontrada", 404)
    bump(); con.commit()
    return jsonify({"ok": True})

# ================== ERRORES Y FRONTEND ==================
@app.errorhandler(413)
def _413(_): return err("Archivo demasiado grande (máx. 12 MB). Usa una URL para fotos/videos pesados.", 413)

@app.errorhandler(404)
def _404(_): return err("No encontrado", 404) if request.path.startswith("/api/") else ("No encontrado", 404)

@app.get("/")
def index():
    if os.path.exists(os.path.join(BASE, "static", "index.html")): return send_from_directory("static", "index.html")
    return jsonify({"ok": True, "servicio": "API tienda", "catalogo": "/api/tienda"})

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("DEBUG") == "1")
