import os
import time
import sqlite3
import datetime
from typing import Optional, List

import bcrypt
import jwt
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ===== CONFIG =====
JWT_SECRET = os.environ.get("JWT_SECRET", "change-this-secret-before-deploying")
JWT_ALGO = "HS256"
TOKEN_EXPIRY_SECONDS = 60 * 60 * 24 * 30  # 30 days
DISCIPLINE_LABELS = {
    "synbio": "Synthetic Biology & Biodesign", "aisafety": "AI Safety & Alignment",
    "quantum": "Quantum Computing", "climate": "Climate Engineering",
    "neurotech": "Neurotechnology (BCI)", "nano": "Nanotechnology",
    "space": "Space Resource Utilization", "fusion": "Fusion Energy",
    "genomics": "Genomics & Personalized Medicine",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "futucation.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = FastAPI(title="Futucation API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ===== DATABASE =====
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # WAL mode lets reads and writes happen concurrently instead of queueing —
    # the single change that lets SQLite comfortably handle much heavier traffic.
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            current_tier TEXT DEFAULT 'explorer',
            xp_points INTEGER DEFAULT 0,
            disciplines_started INTEGER DEFAULT 1,
            credentials_earned INTEGER DEFAULT 0,
            birth_year INTEGER,
            guardian_email TEXT,
            parental_consent_needed INTEGER DEFAULT 0,
            reduced_motion INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s','now'))
        )
    """)
    # backward-compatible migration in case an older db file is still around
    existing_cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
    for col, ddl in [
        ("birth_year", "ALTER TABLE users ADD COLUMN birth_year INTEGER"),
        ("guardian_email", "ALTER TABLE users ADD COLUMN guardian_email TEXT"),
        ("parental_consent_needed", "ALTER TABLE users ADD COLUMN parental_consent_needed INTEGER DEFAULT 0"),
        ("reduced_motion", "ALTER TABLE users ADD COLUMN reduced_motion INTEGER DEFAULT 0"),
    ]:
        if col not in existing_cols:
            conn.execute(ddl)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS completions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            discipline TEXT NOT NULL,
            layer_index INTEGER NOT NULL,
            completed_at INTEGER DEFAULT (strftime('%s','now')),
            UNIQUE(user_id, discipline, layer_index)
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ===== SCHEMAS =====
class RegisterIn(BaseModel):
    full_name: str
    email: str
    password: str
    birth_year: Optional[int] = None
    guardian_email: Optional[str] = None


class LoginIn(BaseModel):
    email: str
    password: str


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    reduced_motion: Optional[bool] = None


class ConsentApprove(BaseModel):
    guardian_email: str


class CompleteLayer(BaseModel):
    discipline: str
    layer_index: int


# ===== AUTH HELPERS =====
def make_token(user_id: int, email: str) -> str:
    payload = {"sub": str(user_id), "email": email, "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (payload["sub"],)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ===== PAGES =====
@app.get("/")
def serve_login():
    return FileResponse(os.path.join(STATIC_DIR, "login.html"))


@app.get("/app")
def serve_dashboard():
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.html"))


@app.get("/health")
def health():
    return {"status": "ok", "service": "futucation-api"}


# ===== AUTH ROUTES =====
@app.post("/auth/register")
def register(data: RegisterIn):
    email = data.email.lower().strip()
    full_name = data.full_name.strip()
    if not full_name or not email or len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Name, email and a password of 6+ characters are required.")
    if not data.birth_year:
        raise HTTPException(status_code=400, detail="Birth year is required.")

    current_year = datetime.date.today().year
    age = current_year - data.birth_year
    is_minor = age < 13
    guardian_email = (data.guardian_email or "").lower().strip()

    if is_minor and not guardian_email:
        raise HTTPException(status_code=400, detail="A parent/guardian email is required for learners under 13.")

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    pw_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    cur = conn.execute(
        "INSERT INTO users (full_name, email, password_hash, birth_year, guardian_email, parental_consent_needed) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (full_name, email, pw_hash, data.birth_year, guardian_email or None, 1 if is_minor else 0),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    token = make_token(user_id, email)
    return {
        "token": token,
        "user": {"id": user_id, "full_name": full_name, "email": email},
        "parental_consent_needed": is_minor,
    }


@app.post("/auth/login")
def login(data: LoginIn):
    email = data.email.lower().strip()
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Wrong email or password.")

    token = make_token(user["id"], user["email"])
    return {"token": token, "user": {"id": user["id"], "full_name": user["full_name"], "email": user["email"]}}


@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    conn = get_db()
    discipline_count = conn.execute(
        "SELECT COUNT(DISTINCT discipline) c FROM completions WHERE user_id = ?", (user["id"],)
    ).fetchone()["c"]
    credential_count = conn.execute(
        "SELECT discipline, COUNT(*) c FROM completions WHERE user_id = ? GROUP BY discipline HAVING c = 5",
        (user["id"],),
    ).fetchall()
    conn.close()
    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "current_tier": user["current_tier"],
        "xp_points": user["xp_points"],
        "disciplines_started": discipline_count,
        "credentials_earned": len(credential_count),
        "parental_consent_needed": bool(user["parental_consent_needed"]),
        "reduced_motion": bool(user["reduced_motion"]),
    }


@app.put("/auth/me")
def update_me(data: ProfileUpdate, user=Depends(get_current_user)):
    conn = get_db()
    if data.full_name:
        conn.execute("UPDATE users SET full_name = ? WHERE id = ?", (data.full_name.strip(), user["id"]))
    if data.reduced_motion is not None:
        conn.execute("UPDATE users SET reduced_motion = ? WHERE id = ?", (1 if data.reduced_motion else 0, user["id"]))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/consent/approve")
def approve_consent(data: ConsentApprove, user=Depends(get_current_user)):
    """
    Lightweight parental-consent gate: a parent/guardian confirms by entering
    the exact guardian email that was provided at signup. This is NOT full
    legal-grade COPPA verification (that would need a verified-consent method
    like a signed form or ID check) — it's an honest, functional first gate
    that blocks full access until a guardian actively confirms.
    """
    if not user["guardian_email"]:
        raise HTTPException(status_code=400, detail="No guardian email is on file for this account.")
    if data.guardian_email.lower().strip() != user["guardian_email"].lower().strip():
        raise HTTPException(status_code=400, detail="That email doesn't match the guardian email on file.")

    conn = get_db()
    conn.execute("UPDATE users SET parental_consent_needed = 0 WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()
    return {"status": "approved"}


@app.post("/progress/complete")
def complete_layer(data: CompleteLayer, user=Depends(get_current_user)):
    if data.discipline not in DISCIPLINE_LABELS:
        raise HTTPException(status_code=400, detail="Unknown discipline.")
    if data.layer_index < 0 or data.layer_index > 4:
        raise HTTPException(status_code=400, detail="layer_index must be between 0 and 4.")

    conn = get_db()
    already = conn.execute(
        "SELECT id FROM completions WHERE user_id=? AND discipline=? AND layer_index=?",
        (user["id"], data.discipline, data.layer_index),
    ).fetchone()
    if not already:
        conn.execute(
            "INSERT INTO completions (user_id, discipline, layer_index) VALUES (?, ?, ?)",
            (user["id"], data.discipline, data.layer_index),
        )
        conn.execute("UPDATE users SET xp_points = xp_points + 10 WHERE id = ?", (user["id"],))
        conn.commit()

    rows = conn.execute(
        "SELECT discipline, layer_index FROM completions WHERE user_id = ?", (user["id"],)
    ).fetchall()
    xp = conn.execute("SELECT xp_points FROM users WHERE id = ?", (user["id"],)).fetchone()["xp_points"]
    conn.close()

    by_discipline = {}
    for r in rows:
        by_discipline.setdefault(r["discipline"], []).append(r["layer_index"])

    return {
        "status": "ok",
        "newly_completed": not bool(already),
        "xp_points": xp,
        "discipline_progress": {k: sorted(v) for k, v in by_discipline.items()},
    }


@app.get("/progress/me")
def get_progress(user=Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT discipline, layer_index FROM completions WHERE user_id = ?", (user["id"],)
    ).fetchall()
    conn.close()
    by_discipline = {}
    for r in rows:
        by_discipline.setdefault(r["discipline"], []).append(r["layer_index"])
    return {"discipline_progress": {k: sorted(v) for k, v in by_discipline.items()}}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
