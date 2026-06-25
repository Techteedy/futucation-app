import os
import time
import sqlite3
from typing import Optional

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
            created_at INTEGER DEFAULT (strftime('%s','now'))
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


class LoginIn(BaseModel):
    email: str
    password: str


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None


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

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    pw_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    cur = conn.execute(
        "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
        (full_name, email, pw_hash),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    token = make_token(user_id, email)
    return {"token": token, "user": {"id": user_id, "full_name": full_name, "email": email}}


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
    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "current_tier": user["current_tier"],
        "xp_points": user["xp_points"],
        "disciplines_started": user["disciplines_started"],
        "credentials_earned": user["credentials_earned"],
    }


@app.put("/auth/me")
def update_me(data: ProfileUpdate, user=Depends(get_current_user)):
    if data.full_name:
        conn = get_db()
        conn.execute("UPDATE users SET full_name = ? WHERE id = ?", (data.full_name.strip(), user["id"]))
        conn.commit()
        conn.close()
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
