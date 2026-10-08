"""
PSX FDS PRO v3.2 — CENTRAL PRODUCTION SERVER & AUTHENTICATION ENGINE
Hosts:
  • Master Admin Portal (/admin) — Create, extend, pause, delete users after payment
  • Secure Client Auth API (/api/login, /api/verify) — Controls access to desktop .exe
  • Official PSX Market Scanner — Live background updates from dps.psx.com.pk
  • Protected Data Feed (/api/market-data) — Serves official candles, signals & FDS data
"""

import os
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
import re
import json
import math
import time
import uuid
import sqlite3
import hashlib
import secrets
import datetime
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException, Header, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests

# ────────────────────────────────────────────────────────────────────
# 1. ENVIRONMENT & PERSISTENT STORAGE CONFIGURATION
# ────────────────────────────────────────────────────────────────────
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
_WEAK = {"adminpsx2026!", "kaleem93527@", "changeme", "password", "admin"}
if len(ADMIN_PASSWORD) < 12 or ADMIN_PASSWORD.lower() in _WEAK or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "Refusing to start: set ADMIN_PASSWORD (>=12 chars, not a known/default value) and "
        "SECRET_KEY (>=32 random chars) as environment variables. "
        "Generate: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1") != "0"      # set COOKIE_SECURE=0 only for local http testing
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

DATA_DIR = os.getenv("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "psx_server.db")

app = FastAPI(title="PSX FDS Pro Production Server", version="3.2.0")

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,          # empty by default: the desktop client does not need CORS
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static folder
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ────────────────────────────────────────────────────────────────────
# 2. DATABASE INITIALIZATION & REPOSITORY
# ────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                plan TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                notes TEXT
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS client_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()

init_db()

# ────────────────────────────────────────────────────────────────────
# 3. SECURITY & CRYPTO HELPERS
# ────────────────────────────────────────────────────────────────────
import time as _time
import html as _html
from collections import defaultdict as _dd

_FAILS = _dd(list)                       # key -> [timestamps of recent failures]
_MAX_FAILS, _WINDOW = 5, 15 * 60

def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")       # behind Coolify/Traefik
    return (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown"))

def _locked(key: str) -> bool:
    now = _time.time()
    _FAILS[key] = [x for x in _FAILS[key] if now - x < _WINDOW]
    return len(_FAILS[key]) >= _MAX_FAILS

def _fail(key: str) -> None:
    _FAILS[key].append(_time.time())

def _same(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return hashed, salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    check_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(check_hash, hashed)

def is_admin_authenticated(request: Request) -> bool:
    cookie_val = request.cookies.get("psx_admin_session")
    if not cookie_val:
        return False
    with get_db() as conn:
        row = conn.execute("SELECT session_id, expires_at FROM admin_sessions WHERE session_id = ?", (cookie_val,)).fetchone()
        if not row:
            return False
        exp = datetime.datetime.fromisoformat(row["expires_at"])
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            conn.execute("DELETE FROM admin_sessions WHERE session_id = ?", (cookie_val,))
            conn.commit()
            return False
        return True

def create_admin_session(response: Response) -> str:
    session_id = secrets.token_urlsafe(32)
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    with get_db() as conn:
        conn.execute("INSERT INTO admin_sessions (session_id, created_at, expires_at) VALUES (?, ?, ?)",
                     (session_id, datetime.datetime.now(datetime.timezone.utc).isoformat(), exp.isoformat()))
        conn.commit()
    response.set_cookie(key="psx_admin_session", value=session_id, max_age=86400*7, httponly=True, secure=COOKIE_SECURE, samesite="strict")
    return session_id

def verify_client_token(token: str) -> Optional[dict]:
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute("""
            SELECT u.id, u.email, u.name, u.plan, u.expires_at, u.is_active, ct.expires_at as token_exp
            FROM client_tokens ct
            JOIN users u ON ct.user_id = u.id
            WHERE ct.token = ?
        """, (token,)).fetchone()
        if not row:
            return None
        
        # Check active status
        if row["is_active"] != 1:
            return None
        
        # Check subscription expiry
        user_exp = datetime.datetime.fromisoformat(row["expires_at"])
        now = datetime.datetime.now(datetime.timezone.utc)
        if now > user_exp:
            return None
        
        days_left = max(0, (user_exp - now).days)
        return {
            "id": row["id"],
            "email": row["email"],
            "name": row["name"] or row["email"],
            "plan": row["plan"],
            "expires_at": row["expires_at"],
            "days_left": days_left
        }

# ────────────────────────────────────────────────────────────────────
# 4. OFFICIAL PSX DATA & MARKET ENGINE CACHE
# ────────────────────────────────────────────────────────────────────
PSX_COMPANIES = {
    "FFC": {"name": "Fauji Fertilizer Company", "sector": "Fertilizer", "shares": 1272.24, "default_price": 539.51,
            "revenue_cur": 182000, "revenue_prev": 145000, "cogs_cur": 105000, "cogs_prev": 88000,
            "ebitda_cur": 58000, "ebitda_prev": 42000, "ebit_cur": 52000, "ebit_prev": 37000,
            "net_income_cur": 34500, "net_income_prev": 24000, "eps_cur": 27.1, "eps_prev": 18.9,
            "total_assets_cur": 195000, "total_assets_prev": 165000, "current_assets_cur": 110000, "current_assets_prev": 92000,
            "current_liab_cur": 72000, "current_liab_prev": 65000, "long_term_debt_cur": 12000, "long_term_debt_prev": 15000,
            "total_debt_cur": 24000, "total_equity_cur": 88000, "total_equity_prev": 72000, "cash_cur": 18500,
            "retained_earnings": 75000, "cfo_cur": 38000, "capex_cur": -8500, "fcf_prev": 22000, "interest_exp": 3200},
    "LUCK": {"name": "Lucky Cement Limited", "sector": "Cement", "shares": 313.38, "default_price": 408.24,
             "revenue_cur": 385000, "revenue_prev": 330000, "cogs_cur": 270000, "cogs_prev": 238000,
             "ebitda_cur": 82000, "ebitda_prev": 68000, "ebit_cur": 67000, "ebit_prev": 54000,
             "net_income_cur": 48500, "net_income_prev": 36000, "eps_cur": 154.8, "eps_prev": 114.9,
             "total_assets_cur": 460000, "total_assets_prev": 395000, "current_assets_cur": 195000, "current_assets_prev": 160000,
             "current_liab_cur": 120000, "current_liab_prev": 105000, "long_term_debt_cur": 35000, "long_term_debt_prev": 42000,
             "total_debt_cur": 65000, "total_equity_cur": 245000, "total_equity_prev": 205000, "cash_cur": 32000,
             "retained_earnings": 210000, "cfo_cur": 56000, "capex_cur": -22000, "fcf_prev": 26000, "interest_exp": 6800},
    "ENGRO": {"name": "Engro Corporation Limited", "sector": "Fertilizer", "shares": 536.33, "default_price": 485.38,
              "revenue_cur": 395000, "revenue_prev": 356000, "cogs_cur": 285000, "cogs_prev": 260000,
              "ebitda_cur": 78000, "ebitda_prev": 65000, "ebit_cur": 61000, "ebit_prev": 49000,
              "net_income_cur": 36000, "net_income_prev": 28000, "eps_cur": 67.1, "eps_prev": 52.2,
              "total_assets_cur": 680000, "total_assets_prev": 610000, "current_assets_cur": 290000, "current_assets_prev": 255000,
              "current_liab_cur": 195000, "current_liab_prev": 178000, "long_term_debt_cur": 75000, "long_term_debt_prev": 82000,
              "total_debt_cur": 140000, "total_equity_cur": 265000, "total_equity_prev": 230000, "cash_cur": 48000,
              "retained_earnings": 215000, "cfo_cur": 49000, "capex_cur": -18000, "fcf_prev": 24000, "interest_exp": 11500},
    "SYS": {"name": "Systems Limited", "sector": "Technology", "shares": 290.45, "default_price": 117.96,
            "revenue_cur": 53000, "revenue_prev": 38000, "cogs_cur": 34000, "cogs_prev": 24500,
            "ebitda_cur": 14500, "ebitda_prev": 10500, "ebit_cur": 13200, "ebit_prev": 9600,
            "net_income_cur": 11800, "net_income_prev": 8900, "eps_cur": 40.6, "eps_prev": 30.6,
            "total_assets_cur": 62000, "total_assets_prev": 46000, "current_assets_cur": 42000, "current_assets_prev": 31000,
            "current_liab_cur": 14000, "current_liab_prev": 11000, "long_term_debt_cur": 1200, "long_term_debt_prev": 1500,
            "total_debt_cur": 3500, "total_equity_cur": 44000, "total_equity_prev": 32000, "cash_cur": 9800,
            "retained_earnings": 38000, "cfo_cur": 12500, "capex_cur": -3200, "fcf_prev": 6500, "interest_exp": 450},
    "MEBL": {"name": "Meezan Bank Limited", "sector": "Financials", "shares": 1789.62, "default_price": 550.10,
             "revenue_cur": 410000, "revenue_prev": 280000, "cogs_cur": 210000, "cogs_prev": 135000,
             "ebitda_cur": 165000, "ebitda_prev": 115000, "ebit_cur": 160000, "ebit_prev": 110000,
             "net_income_cur": 85000, "net_income_prev": 56000, "eps_cur": 47.5, "eps_prev": 31.3,
             "total_assets_cur": 3200000, "total_assets_prev": 2500000, "current_assets_cur": 1200000, "current_assets_prev": 950000,
             "current_liab_cur": 1100000, "current_liab_prev": 880000, "long_term_debt_cur": 0, "long_term_debt_prev": 0,
             "total_debt_cur": 45000, "total_equity_cur": 185000, "total_equity_prev": 130000, "cash_cur": 220000,
             "retained_earnings": 155000, "cfo_cur": 92000, "capex_cur": -8000, "fcf_prev": 68000, "interest_exp": 1200},
    "MCB": {"name": "MCB Bank Limited", "sector": "Financials", "shares": 1185.06, "default_price": 385.59,
            "revenue_cur": 340000, "revenue_prev": 240000, "cogs_cur": 175000, "cogs_prev": 110000,
            "ebitda_cur": 135000, "ebitda_prev": 98000, "ebit_cur": 130000, "ebit_prev": 94000,
            "net_income_cur": 65000, "net_income_prev": 45000, "eps_cur": 54.8, "eps_prev": 38.0,
            "total_assets_cur": 2600000, "total_assets_prev": 2100000, "current_assets_cur": 980000, "current_assets_prev": 810000,
            "current_liab_cur": 920000, "current_liab_prev": 760000, "long_term_debt_cur": 0, "long_term_debt_prev": 0,
            "total_debt_cur": 28000, "total_equity_cur": 215000, "total_equity_prev": 175000, "cash_cur": 190000,
            "retained_earnings": 185000, "cfo_cur": 78000, "capex_cur": -6500, "fcf_prev": 54000, "interest_exp": 850},
    "UBL": {"name": "United Bank Limited", "sector": "Financials", "shares": 1224.18, "default_price": 424.23,
            "revenue_cur": 320000, "revenue_prev": 230000, "cogs_cur": 165000, "cogs_prev": 105000,
            "ebitda_cur": 125000, "ebitda_prev": 92000, "ebit_cur": 120000, "ebit_prev": 88000,
            "net_income_cur": 58000, "net_income_prev": 41000, "eps_cur": 47.4, "eps_prev": 33.5,
            "total_assets_cur": 2800000, "total_assets_prev": 2300000, "current_assets_cur": 1050000, "current_assets_prev": 870000,
            "current_liab_cur": 990000, "current_liab_prev": 820000, "long_term_debt_cur": 0, "long_term_debt_prev": 0,
            "total_debt_cur": 32000, "total_equity_cur": 225000, "total_equity_prev": 180000, "cash_cur": 210000,
            "retained_earnings": 190000, "cfo_cur": 72000, "capex_cur": -7200, "fcf_prev": 49000, "interest_exp": 920},
    "OGDC": {"name": "Oil & Gas Development Company", "sector": "Energy", "shares": 4300.93, "default_price": 315.91,
             "revenue_cur": 460000, "revenue_prev": 415000, "cogs_cur": 145000, "cogs_prev": 132000,
             "ebitda_cur": 325000, "ebitda_prev": 292000, "ebit_cur": 285000, "ebit_prev": 258000,
             "net_income_cur": 205000, "net_income_prev": 182000, "eps_cur": 47.6, "eps_prev": 42.3,
             "total_assets_cur": 1350000, "total_assets_prev": 1180000, "current_assets_cur": 850000, "current_assets_prev": 720000,
             "current_liab_cur": 210000, "current_liab_prev": 185000, "long_term_debt_cur": 0, "long_term_debt_prev": 0,
             "total_debt_cur": 15000, "total_equity_cur": 1050000, "total_equity_prev": 920000, "cash_cur": 145000,
             "retained_earnings": 920000, "cfo_cur": 175000, "capex_cur": -55000, "fcf_prev": 110000, "interest_exp": 450},
    "PPL": {"name": "Pakistan Petroleum Limited", "sector": "Energy", "shares": 2720.97, "default_price": 220.29,
            "revenue_cur": 310000, "revenue_prev": 285000, "cogs_cur": 125000, "cogs_prev": 115000,
            "ebitda_cur": 195000, "ebitda_prev": 178000, "ebit_cur": 172000, "ebit_prev": 156000,
            "net_income_cur": 118000, "net_income_prev": 105000, "eps_cur": 43.3, "eps_prev": 38.5,
            "total_assets_cur": 820000, "total_assets_prev": 730000, "current_assets_cur": 490000, "current_assets_prev": 420000,
            "current_liab_cur": 145000, "current_liab_prev": 130000, "long_term_debt_cur": 0, "long_term_debt_prev": 0,
            "total_debt_cur": 8500, "total_equity_cur": 620000, "total_equity_prev": 545000, "cash_cur": 78000,
            "retained_earnings": 540000, "cfo_cur": 98000, "capex_cur": -38000, "fcf_prev": 55000, "interest_exp": 280},
    "MARI": {"name": "Mari Petroleum Company Limited", "sector": "Energy", "shares": 1334.02, "default_price": 642.41,
             "revenue_cur": 198000, "revenue_prev": 145000, "cogs_cur": 55000, "cogs_prev": 42000,
             "ebitda_cur": 135000, "ebitda_prev": 98000, "ebit_cur": 125000, "ebit_prev": 91000,
             "net_income_cur": 86000, "net_income_prev": 56000, "eps_cur": 64.4, "eps_prev": 41.9,
             "total_assets_cur": 320000, "total_assets_prev": 245000, "current_assets_cur": 195000, "current_assets_prev": 140000,
             "current_liab_cur": 68000, "current_liab_prev": 52000, "long_term_debt_cur": 2500, "long_term_debt_prev": 3000,
             "total_debt_cur": 8000, "total_equity_cur": 220000, "total_equity_prev": 165000, "cash_cur": 65000,
             "retained_earnings": 195000, "cfo_cur": 92000, "capex_cur": -31000, "fcf_prev": 48000, "interest_exp": 650},
    "HUBC": {"name": "The Hub Power Company Limited", "sector": "Energy", "shares": 1297.15, "default_price": 200.49,
             "revenue_cur": 115000, "revenue_prev": 98000, "cogs_cur": 58000, "cogs_prev": 51000,
             "ebitda_cur": 62000, "ebitda_prev": 52000, "ebit_cur": 56000, "ebit_prev": 47000,
             "net_income_cur": 42000, "net_income_prev": 33000, "eps_cur": 32.4, "eps_prev": 25.4,
             "total_assets_cur": 340000, "total_assets_prev": 295000, "current_assets_cur": 165000, "current_assets_prev": 140000,
             "current_liab_cur": 115000, "current_liab_prev": 105000, "long_term_debt_cur": 45000, "long_term_debt_prev": 52000,
             "total_debt_cur": 85000, "total_equity_cur": 135000, "total_equity_prev": 110000, "cash_cur": 18000,
             "retained_earnings": 115000, "cfo_cur": 48000, "capex_cur": -12000, "fcf_prev": 28000, "interest_exp": 9500},
    "INDU": {"name": "Indus Motor Company Limited", "sector": "Auto & Engineering", "shares": 78.60, "default_price": 1811.07,
             "revenue_cur": 152000, "revenue_prev": 125000, "cogs_cur": 132000, "cogs_prev": 110000,
             "ebitda_cur": 22000, "ebitda_prev": 16500, "ebit_cur": 19500, "ebit_prev": 14200,
             "net_income_cur": 15200, "net_income_prev": 10800, "eps_cur": 193.4, "eps_prev": 137.4,
             "total_assets_cur": 125000, "total_assets_prev": 105000, "current_assets_cur": 98000, "current_assets_prev": 82000,
             "current_liab_cur": 58000, "current_liab_prev": 49000, "long_term_debt_cur": 0, "long_term_debt_prev": 0,
             "total_debt_cur": 1500, "total_equity_cur": 64000, "total_equity_prev": 53000, "cash_cur": 42000,
             "retained_earnings": 61000, "cfo_cur": 24000, "capex_cur": -4500, "fcf_prev": 12500, "interest_exp": 120},
    "SEARL": {"name": "The Searle Company Limited", "sector": "Healthcare", "shares": 387.89, "default_price": 78.31,
              "revenue_cur": 32000, "revenue_prev": 28000, "cogs_cur": 18500, "cogs_prev": 16200,
              "ebitda_cur": 8500, "ebitda_prev": 7200, "ebit_cur": 7100, "ebit_prev": 5900,
              "net_income_cur": 3800, "net_income_prev": 2900, "eps_cur": 9.8, "eps_prev": 7.5,
              "total_assets_cur": 55000, "total_assets_prev": 49000, "current_assets_cur": 31000, "current_assets_prev": 27000,
              "current_liab_cur": 19000, "current_liab_prev": 17000, "long_term_debt_cur": 6500, "long_term_debt_prev": 7200,
              "total_debt_cur": 14000, "total_equity_cur": 28000, "total_equity_prev": 24000, "cash_cur": 3200,
              "retained_earnings": 23000, "cfo_cur": 5200, "capex_cur": -2100, "fcf_prev": 2400, "interest_exp": 2100},
    "ILP": {"name": "Interloop Limited", "sector": "Textiles", "shares": 1401.81, "default_price": 96.40,
            "revenue_cur": 135000, "revenue_prev": 112000, "cogs_cur": 98000, "cogs_prev": 81000,
            "ebitda_cur": 34000, "ebitda_prev": 28500, "ebit_cur": 28000, "ebit_prev": 23200,
            "net_income_cur": 18500, "net_income_prev": 15200, "eps_cur": 13.2, "eps_prev": 10.8,
            "total_assets_cur": 165000, "total_assets_prev": 138000, "current_assets_cur": 88000, "current_assets_prev": 72000,
            "current_liab_cur": 62000, "current_liab_prev": 51000, "long_term_debt_cur": 28000, "long_term_debt_prev": 31000,
            "total_debt_cur": 56000, "total_equity_cur": 68000, "total_equity_prev": 52000, "cash_cur": 9500,
            "retained_earnings": 48000, "cfo_cur": 21000, "capex_cur": -14000, "fcf_prev": 5200, "interest_exp": 7500},
    "TRG": {"name": "TRG Pakistan Limited", "sector": "Technology", "shares": 545.39, "default_price": 56.49,
            "revenue_cur": 1200, "revenue_prev": 1400, "cogs_cur": 800, "cogs_prev": 900,
            "ebitda_cur": -1500, "ebitda_prev": -800, "ebit_cur": -1800, "ebit_prev": -1100,
            "net_income_cur": -4500, "net_income_prev": -2800, "eps_cur": -8.2, "eps_prev": -5.1,
            "total_assets_cur": 58000, "total_assets_prev": 62000, "current_assets_cur": 14000, "current_assets_prev": 16000,
            "current_liab_cur": 22000, "current_liab_prev": 18000, "long_term_debt_cur": 16000, "long_term_debt_prev": 14000,
            "total_debt_cur": 32000, "total_equity_cur": 9500, "total_equity_prev": 16000, "cash_cur": 1200,
            "retained_earnings": -12000, "cfo_cur": -2200, "capex_cur": -900, "fcf_prev": -2500, "interest_exp": 3200}
}

_market_cache = {
    "last_scanned": None,
    "stocks": [],
    "charts": {}
}

def scan_official_psx_market():
    """v4: the server no longer scores anything itself. It serves psx_full_universe.json,
    produced by build_universe.py (real price history + trade_engine). Charts are fetched
    on demand by /api/chart/{symbol}."""
    universe_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "psx_full_universe.json")
    stocks = []
    if os.path.exists(universe_file):
        try:
            with open(universe_file, "r", encoding="utf-8") as f:
                stocks = json.load(f)
        except Exception as e:
            print(f"[-] Error loading universe file: {e}")
    else:
        print("[-] psx_full_universe.json missing. Run build_universe.py and copy the file here.")
    _market_cache["last_scanned"] = datetime.datetime.now(datetime.timezone.utc).strftime("%d-%b-%Y %H:%M:%S UTC")
    _market_cache["stocks"] = stocks
    _market_cache["charts"] = {}
    print(f"[+] Loaded {len(stocks)} stocks from psx_full_universe.json")

# Run on server boot
scan_official_psx_market()

# ────────────────────────────────────────────────────────────────────
# 5. ADMIN AUTHENTICATION & PORTAL ROUTES (/admin)
# ────────────────────────────────────────────────────────────────────
@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    if is_admin_authenticated(request):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSX FDS Pro — Admin Portal Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { background: #070b12; color: #f8fafc; font-family: 'Inter', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .login-card { background: #0f172a; border: 1px solid #1e293b; padding: 36px; border-radius: 14px; width: 360px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        .badge { background: #059669; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        h2 { font-size: 20px; margin: 12px 0 6px 0; }
        p { color: #94a3b8; font-size: 12px; margin-bottom: 24px; }
        label { display: block; font-size: 12px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }
        input { width: 100%; box-sizing: border-box; background: #090e1a; border: 1px solid #1e293b; color: #fff; padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; outline: none; }
        input:focus { border-color: #3b82f6; }
        button { width: 100%; background: linear-gradient(135deg, #2563eb, #3b82f6); border: none; color: white; padding: 11px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 14px; }
        button:hover { opacity: 0.9; }
        .error { color: #ef4444; font-size: 12px; margin-bottom: 14px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-card">
        <span class="badge">🇵🇰 PSX Master Control</span>
        <h2>Admin Portal</h2>
        <p>Sign in to manage users, licenses, and payments.</p>
        <form method="POST" action="/admin/login">
            <label>Admin Username</label>
            <input type="text" name="username" required autocomplete="username">
            <label>Master Password</label>
            <input type="password" name="password" required autocomplete="current-password">
            <button type="submit">Access Dashboard</button>
        </form>
    </div>
</body>
</html>"""

@app.post("/admin/login")
async def admin_login_submit(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    key = "admin:" + _client_ip(request)
    if _locked(key):
        return HTMLResponse("<h3>Too many attempts. Try again in 15 minutes.</h3>", status_code=429)
    ok_user = _same(username, ADMIN_USER)
    ok_pass = _same(password, ADMIN_PASSWORD)
    if ok_user and ok_pass:
        res = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
        create_admin_session(res)
        return res
    _fail(key)
    return HTMLResponse("<h3>Invalid username or password. <a href='/admin/login'>Try again</a></h3>", status_code=401)

@app.get("/admin/logout")
async def admin_logout(response: Response):
    res = RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)
    res.delete_cookie("psx_admin_session")
    return res

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    if not is_admin_authenticated(request):
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)

    with get_db() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()

    now = datetime.datetime.now(datetime.timezone.utc)
    user_list = []
    total_users = len(users)
    active_count = 0
    expired_count = 0

    for u in users:
        exp_dt = datetime.datetime.fromisoformat(u["expires_at"])
        is_expired = now > exp_dt
        days_left = max(0, (exp_dt - now).days)
        if u["is_active"] == 1 and not is_expired:
            active_count += 1
            status_text = "ACTIVE"
            status_color = "#34d399"
        elif u["is_active"] != 1:
            status_text = "PAUSED"
            status_color = "#fbbf24"
        else:
            expired_count += 1
            status_text = "EXPIRED"
            status_color = "#f87171"

        user_list.append({
            "id": u["id"],
            "email": _html.escape(u["email"]),
            "name": _html.escape(u["name"] or "—"),
            "plan": _html.escape(u["plan"] or ""),
            "created_at": datetime.datetime.fromisoformat(u["created_at"]).strftime("%d-%b-%Y"),
            "expires_at": exp_dt.strftime("%d-%b-%Y"),
            "days_left": days_left,
            "status_text": status_text,
            "status_color": status_color,
            "notes": _html.escape(u["notes"] or "—"),
            "is_active": u["is_active"]
        })

    users_json = json.dumps(user_list).replace("</", "<\\/")
    last_scanned = _market_cache["last_scanned"] or "Just now"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSX FDS Pro — Master Admin Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #070b12;
            --bg-card: #0f172a;
            --border: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-green: #10b981;
            --accent-blue: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Inter', sans-serif; background: var(--bg-dark); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }}
        header {{ background: #0c1424; border-bottom: 1px solid var(--border); padding: 14px 28px; display: flex; justify-content: space-between; align-items: center; }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .badge {{ background: linear-gradient(135deg, #059669, #10b981); color: white; padding: 5px 10px; border-radius: 6px; font-size: 11px; font-weight: 800; }}
        .btn {{ background: #1e293b; color: #fff; border: 1px solid var(--border); padding: 7px 14px; border-radius: 7px; font-size: 12px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }}
        .btn:hover {{ background: #334155; }}
        .btn-green {{ background: linear-gradient(135deg, #059669, #10b981); border: none; }}
        .btn-blue {{ background: linear-gradient(135deg, #2563eb, #3b82f6); border: none; }}
        .container {{ padding: 24px 28px; flex: 1; }}
        
        .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .kpi-box {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }}
        .kpi-lbl {{ font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }}
        .kpi-val {{ font-size: 24px; font-weight: 800; font-family: 'JetBrains Mono'; margin-top: 4px; }}
        
        .toolbar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; gap: 12px; }}
        .search-box {{ width: 320px; background: #090e1a; border: 1px solid var(--border); padding: 9px 13px; border-radius: 8px; color: #fff; font-size: 13px; outline: none; }}
        
        .table-wrap {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }}
        th {{ background: #0c1424; color: var(--text-muted); font-size: 11px; text-transform: uppercase; padding: 12px 16px; border-bottom: 1px solid var(--border); }}
        td {{ padding: 12px 16px; border-bottom: 1px solid #162238; }}
        tr:hover td {{ background: rgba(30, 41, 59, 0.4); }}
        
        .status-pill {{ padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }}
        
        /* Modal */
        .modal-bg {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px); z-index: 100; align-items: center; justify-content: center; }}
        .modal {{ background: var(--bg-card); border: 1px solid var(--border); width: 440px; border-radius: 14px; padding: 24px; box-shadow: 0 15px 35px rgba(0,0,0,0.6); }}
        .modal h3 {{ margin-bottom: 16px; font-size: 18px; }}
        .form-group {{ margin-bottom: 14px; }}
        .form-group label {{ display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 5px; font-weight: 600; text-transform: uppercase; }}
        .form-group input, .form-group select {{ width: 100%; background: #090e1a; border: 1px solid var(--border); color: #fff; padding: 9px 12px; border-radius: 7px; font-size: 13px; outline: none; }}
        .modal-actions {{ display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }}
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <span class="badge">🇵🇰 PSX MASTER ADMIN</span>
            <div>
                <h1 style="font-size: 16px; font-weight: 700;">PSX FDS Pro Control Deck</h1>
                <p style="font-size: 11px; color: var(--text-muted);">Manage paid licenses, subscription expiries, and live PSX data cache</p>
            </div>
        </div>
        <div style="display: flex; gap: 10px; align-items: center;">
            <span style="font-size: 11px; color: #94a3b8;">Exchange Cache: <b>{last_scanned}</b></span>
            <button class="btn btn-blue" onclick="triggerRescan()">🔄 Re-Scan Market</button>
            <a href="/admin/logout" class="btn">🚪 Logout</a>
        </div>
    </header>

    <div class="container">
        <!-- KPI Row -->
        <div class="kpi-row">
            <div class="kpi-box">
                <div class="kpi-lbl">Total Registered Users</div>
                <div class="kpi-val" style="color: #60a5fa;">{total_users}</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-lbl">Active Subscriptions</div>
                <div class="kpi-val" style="color: #34d399;">{active_count}</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-lbl">Expired / Needs Renewal</div>
                <div class="kpi-val" style="color: #f87171;">{expired_count}</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-lbl">Official PSX Status</div>
                <div class="kpi-val" style="color: #fbbf24; font-size: 16px; margin-top: 10px;">🟢 Connected (DPS)</div>
            </div>
        </div>

        <!-- Toolbar -->
        <div class="toolbar">
            <input type="text" id="searchInput" class="search-box" placeholder="🔍 Search by email, name, or payment notes..." oninput="filterUsers()">
            <button class="btn btn-green" onclick="openAddModal()">➕ Add New Paid User</button>
        </div>

        <!-- Users Table -->
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>User / Email</th>
                        <th>Plan</th>
                        <th>Expires On</th>
                        <th>Remaining</th>
                        <th>Status</th>
                        <th>Payment Notes</th>
                        <th style="text-align: right;">License Actions</th>
                    </tr>
                </thead>
                <tbody id="userTableBody">
                    <!-- Populated via JS -->
                </tbody>
            </table>
        </div>
    </div>

    <!-- Add User Modal -->
    <div class="modal-bg" id="addModal">
        <div class="modal">
            <h3>➕ Create New Paid User</h3>
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" id="newEmail" placeholder="customer@gmail.com" required>
            </div>
            <div class="form-group">
                <label>Full Name / Phone (Optional)</label>
                <input type="text" id="newName" placeholder="Ahmed Khan (0300-1234567)">
            </div>
            <div class="form-group">
                <label>Password</label>
                <div style="display: flex; gap: 6px;">
                    <input type="text" id="newPassword" placeholder="Set user password" required>
                    <button class="btn" type="button" onclick="generatePassword()">🎲 Gen</button>
                </div>
            </div>
            <div class="form-group">
                <label>Subscription Duration</label>
                <select id="newPlanDays">
                    <option value="30">1 Month (30 Days)</option>
                    <option value="90">3 Months (90 Days)</option>
                    <option value="180">6 Months (180 Days)</option>
                    <option value="365">1 Year (365 Days)</option>
                    <option value="36500">Lifetime Access</option>
                </select>
            </div>
            <div class="form-group">
                <label>Payment Notes / Reference</label>
                <input type="text" id="newNotes" placeholder="e.g. Paid Rs. 15,000 via Nayapay Ref #89281">
            </div>
            <div class="modal-actions">
                <button class="btn" onclick="closeAddModal()">Cancel</button>
                <button class="btn btn-green" onclick="submitNewUser()">Create & Activate</button>
            </div>
        </div>
    </div>

    <script>
        const USERS = {users_json};

        function renderTable(list) {{
            const tbody = document.getElementById('userTableBody');
            tbody.innerHTML = '';
            if (list.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #94a3b8; padding: 24px;">No users found. Click "+ Add New Paid User" to create one.</td></tr>';
                return;
            }}
            list.forEach(u => {{
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="color: #64748b; font-family: 'JetBrains Mono';">#${{u.id}}</td>
                    <td>
                        <div style="font-weight: 700;">${{u.email}}</div>
                        <div style="font-size: 11px; color: #64748b;">${{u.name}}</div>
                    </td>
                    <td><span style="font-weight: 600; color: #93c5fd;">${{u.plan}}</span></td>
                    <td style="font-family: 'JetBrains Mono';">${{u.expires_at}}</td>
                    <td>
                        <span style="font-family: 'JetBrains Mono'; font-weight: 700; color: ${{u.days_left > 5 ? '#34d399' : u.days_left > 0 ? '#fbbf24' : '#f87171'}}">
                            ${{u.days_left}} Days
                        </span>
                    </td>
                    <td>
                        <span class="status-pill" style="background: ${{u.status_color}}22; color: ${{u.status_color}}; border: 1px solid ${{u.status_color}}44;">
                            ${{u.status_text}}
                        </span>
                    </td>
                    <td style="font-size: 11px; color: #94a3b8; max-width: 180px;">${{u.notes}}</td>
                    <td style="text-align: right;">
                        <button class="btn btn-green" style="padding: 4px 8px; font-size: 11px;" onclick="extendUser(${{u.id}}, 30)" title="Extend +30 Days">+30d</button>
                        <button class="btn" style="padding: 4px 8px; font-size: 11px;" onclick="extendUser(${{u.id}}, 365)" title="Extend +1 Year">+1y</button>
                        <button class="btn" style="padding: 4px 8px; font-size: 11px;" onclick="toggleUserStatus(${{u.id}}, ${{u.is_active}})">${{u.is_active ? '⏸️' : '▶️'}}</button>
                        <button class="btn" style="padding: 4px 8px; font-size: 11px; color: #ef4444;" onclick="deleteUser(${{u.id}})" title="Delete User">🗑️</button>
                    </td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterUsers() {{
            const q = document.getElementById('searchInput').value.toLowerCase();
            const filtered = USERS.filter(u => u.email.toLowerCase().includes(q) || u.name.toLowerCase().includes(q) || u.notes.toLowerCase().includes(q));
            renderTable(filtered);
        }}

        function openAddModal() {{
            document.getElementById('addModal').style.display = 'flex';
            generatePassword();
        }}
        function closeAddModal() {{ document.getElementById('addModal').style.display = 'none'; }}

        function generatePassword() {{
            const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$';
            let pass = '';
            for (let i = 0; i < 10; i++) pass += chars.charAt(Math.floor(Math.random() * chars.length));
            document.getElementById('newPassword').value = pass;
        }}

        async function submitNewUser() {{
            const email = document.getElementById('newEmail').value.trim();
            const name = document.getElementById('newName').value.trim();
            const password = document.getElementById('newPassword').value.trim();
            const days = parseInt(document.getElementById('newPlanDays').value);
            const notes = document.getElementById('newNotes').value.trim();

            if (!email || !password) {{ alert('Please enter both Email and Password'); return; }}

            const res = await fetch('/admin/api/users', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ email, name, password, days, notes }})
            }});
            const data = await res.json();
            if (data.status === 'success') {{
                alert('User created successfully! Send credentials to customer:\\nEmail: ' + email + '\\nPassword: ' + password);
                window.location.reload();
            }} else {{
                alert('Error: ' + data.message);
            }}
        }}

        async function extendUser(id, days) {{
            if (!confirm(`Extend subscription for user #${{id}} by +${{days}} days?`)) return;
            const res = await fetch(`/admin/api/users/${{id}}/extend`, {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ days }})
            }});
            const data = await res.json();
            if (data.status === 'success') window.location.reload();
        }}

        async function toggleUserStatus(id, currentStatus) {{
            const action = currentStatus ? 'pause' : 'activate';
            if (!confirm(`Are you sure you want to ${{action}} user #${{id}}?`)) return;
            const res = await fetch(`/admin/api/users/${{id}}/toggle-status`, {{ method: 'POST' }});
            const data = await res.json();
            if (data.status === 'success') window.location.reload();
        }}

        async function deleteUser(id) {{
            if (!confirm(`PERMANENT DELETE: Remove user #${{id}} and all associated licenses?`)) return;
            const res = await fetch(`/admin/api/users/${{id}}`, {{ method: 'DELETE' }});
            const data = await res.json();
            if (data.status === 'success') window.location.reload();
        }}

        async function triggerRescan() {{
            alert('Triggering official PSX market re-scan in background...');
            await fetch('/admin/api/rescan', {{ method: 'POST' }});
            window.location.reload();
        }}

        window.onload = () => renderTable(USERS);
    </script>
</body>
</html>"""

# ────────────────────────────────────────────────────────────────────
# 6. ADMIN API ENDPOINTS (MANAGE USERS & EXTENSIONS)
# ────────────────────────────────────────────────────────────────────
class NewUserPayload(BaseModel):
    email: str
    password: str
    name: Optional[str] = None
    days: int = 30
    notes: Optional[str] = None

class ExtendPayload(BaseModel):
    days: int = 30

@app.post("/admin/api/users")
async def admin_create_user(request: Request, payload: NewUserPayload):
    if not is_admin_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    hashed, salt = hash_password(payload.password)
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + datetime.timedelta(days=payload.days)
    plan_name = f"{payload.days} Days" if payload.days < 3650 else "Lifetime"

    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO users (email, name, password_hash, salt, plan, created_at, expires_at, is_active, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
            """, (payload.email.lower().strip(), payload.name, hashed, salt, plan_name, now.isoformat(), exp.isoformat(), payload.notes))
            conn.commit()
        return {"status": "success", "message": "User created successfully"}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "A user with this email already exists"}

@app.post("/admin/api/users/{user_id}/extend")
async def admin_extend_user(request: Request, user_id: int, payload: ExtendPayload):
    if not is_admin_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    now = datetime.datetime.now(datetime.timezone.utc)
    with get_db() as conn:
        row = conn.execute("SELECT expires_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        current_exp = datetime.datetime.fromisoformat(row["expires_at"])
        # If already expired, start from today; otherwise add to current expiry
        base_date = max(now, current_exp)
        new_exp = base_date + datetime.timedelta(days=payload.days)

        conn.execute("UPDATE users SET expires_at = ?, is_active = 1 WHERE id = ?", (new_exp.isoformat(), user_id))
        conn.commit()
    return {"status": "success", "new_expiry": new_exp.isoformat()}

@app.post("/admin/api/users/{user_id}/toggle-status")
async def admin_toggle_status(request: Request, user_id: int):
    if not is_admin_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    with get_db() as conn:
        row = conn.execute("SELECT is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        new_status = 0 if row["is_active"] == 1 else 1
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
    return {"status": "success", "new_status": new_status}

@app.delete("/admin/api/users/{user_id}")
async def admin_delete_user(request: Request, user_id: int):
    if not is_admin_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.execute("DELETE FROM client_tokens WHERE user_id = ?", (user_id,))
        conn.commit()
    return {"status": "success", "message": "User deleted"}

@app.post("/admin/api/rescan")
async def admin_rescan_market(request: Request):
    if not is_admin_authenticated(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    scan_official_psx_market()
    return {"status": "success", "message": "Scan completed"}

# ────────────────────────────────────────────────────────────────────
# 7. PUBLIC CLIENT AUTH & DATA API (POWERS .EXE AND WEB COCKPIT)
# ────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/login")
async def client_login(payload: LoginRequest, request: Request):
    email = payload.email.lower().strip()
    _key = "login:" + _client_ip(request) + ":" + email
    if _locked(_key):
        return JSONResponse(status_code=429, content={"status": "error", "message": "Too many failed attempts. Try again in 15 minutes."})

    # 1. Direct Master Admin Login Bypass
    if (email == ADMIN_USER.lower() or email == f"{ADMIN_USER.lower()}@crtalgo.online") and _same(payload.password, ADMIN_PASSWORD):
        token = "admin_" + secrets.token_urlsafe(32)
        with get_db() as conn:
            admin_row = conn.execute("SELECT id FROM users WHERE email = 'admin@crtalgo.online'").fetchone()
            if not admin_row:
                p_hash, salt = hash_password(ADMIN_PASSWORD)
                now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                exp_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).isoformat()
                cur = conn.execute(
                    "INSERT INTO users (email, name, password_hash, salt, plan, created_at, expires_at, is_active, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('admin@crtalgo.online', 'Master Administrator', p_hash, salt, 'Lifetime Master', now_iso, exp_iso, 1, 'Auto-provisioned Admin Account')
                )
                admin_id = cur.lastrowid
            else:
                admin_id = admin_row["id"]

            token_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
            conn.execute("INSERT INTO client_tokens (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                         (token, admin_id, datetime.datetime.now(datetime.timezone.utc).isoformat(), token_exp.isoformat()))
            conn.commit()

        return {
            "status": "success",
            "token": token,
            "user": {
                "email": ADMIN_USER,
                "name": "Master Administrator",
                "plan": "Lifetime Master",
                "expires_at": "Lifetime",
                "days_left": 9999
            }
        }

    # 2. Standard Client License Authentication
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            _fail(_key)
            return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid email or password."})

        if not verify_password(payload.password, row["password_hash"], row["salt"]):
            _fail(_key)
            return JSONResponse(status_code=401, content={"status": "error", "message": "Invalid email or password."})

        if row["is_active"] != 1:
            return JSONResponse(status_code=403, content={"status": "error", "message": "Your account has been paused by administrator. Please contact support."})

        now = datetime.datetime.now(datetime.timezone.utc)
        exp_dt = datetime.datetime.fromisoformat(row["expires_at"])
        if now > exp_dt:
            return JSONResponse(status_code=403, content={
                "status": "expired",
                "message": f"Your subscription expired on {exp_dt.strftime('%d-%b-%Y')}. Please contact admin to renew.",
                "expires_at": exp_dt.strftime("%d-%b-%Y")
            })

        days_left = max(0, (exp_dt - now).days)
        token = secrets.token_urlsafe(40)
        token_exp = now + datetime.timedelta(days=30)
        conn.execute("INSERT INTO client_tokens (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                     (token, row["id"], now.isoformat(), token_exp.isoformat()))
        conn.commit()

        return {
            "status": "success",
            "token": token,
            "user": {
                "email": row["email"],
                "name": row["name"] or row["email"],
                "plan": row["plan"],
                "expires_at": exp_dt.strftime("%d-%b-%Y"),
                "days_left": days_left
            }
        }

@app.get("/api/verify")
async def client_verify_token(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token header")
    token = authorization.split(" ")[1]
    user_info = verify_client_token(token)
    if not user_info:
        raise HTTPException(status_code=403, detail="Token invalid or subscription expired")
    return {"status": "success", "user": user_info}

@app.get("/api/market-data")
async def client_market_data(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token header")
    token = authorization.split(" ")[1]
    user_info = verify_client_token(token)
    if not user_info:
        raise HTTPException(status_code=403, detail="Subscription inactive or expired")

    return {
        "status": "success",
        "last_scanned": _market_cache["last_scanned"],
        "stocks": _market_cache["stocks"],
        "charts": _market_cache["charts"],
        "user": user_info
    }

@app.get("/api/chart/{symbol}")
async def get_stock_chart(symbol: str, authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer ") or not verify_client_token(authorization.split(" ", 1)[1]):
        raise HTTPException(status_code=401, detail="Authentication required")
    sym = re.sub(r"[^A-Z0-9]", "", symbol.upper())[:12]
    if sym in _market_cache["charts"]:
        return {"status": "success", "chart": _market_cache["charts"][sym]}
    
    # Try fetching on-demand from DPS timeseries
    try:
        s = requests.Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://dps.psx.com.pk/"
        }
        r = s.get("https://dps.psx.com.pk/", headers=headers, timeout=5)
        m = re.search(r'window\.__ps\s*=\s*({[^}]+})', r.text)
        if m:
            token = json.loads(m.group(1)).get("_k")
            s.headers.update({"X-Req-Id": token})
            r_ts = s.get(f"https://dps.psx.com.pk/timeseries/eod/{sym}", timeout=6)
            if r_ts.status_code == 200:
                raw = r_ts.json().get("data", [])
                if raw:
                    bars = []
                    for d in raw[:160]:
                        dt = datetime.datetime.fromtimestamp(d[0], datetime.timezone.utc).strftime("%Y-%m-%d")
                        close_p = round(float(d[1]), 2)
                        vol = int(d[2] or 0)
                        open_p = round(float(d[3] if len(d) > 3 and d[3] is not None else d[1]), 2)
                        high_p = round(max(open_p, close_p), 2)     # PSX EOD feed has no high/low: do not invent wicks
                        low_p = round(min(open_p, close_p), 2)
                        bars.append({"time": dt, "open": open_p, "high": high_p, "low": low_p, "close": close_p, "volume": vol})
                    bars = sorted(bars, key=lambda x: x["time"])
                    
                    sma20, sma50 = [], []
                    closes = [b["close"] for b in bars]
                    for i in range(len(bars)):
                        if i >= 19: sma20.append({"time": bars[i]["time"], "value": round(sum(closes[i-19:i+1])/20.0, 2)})
                        if i >= 49: sma50.append({"time": bars[i]["time"], "value": round(sum(closes[i-49:i+1])/50.0, 2)})
                    
                    chart_obj = {"bars": bars, "sma20": sma20, "sma50": sma50, "markers": []}
                    _market_cache["charts"][sym] = chart_obj
                    return {"status": "success", "chart": chart_obj}
    except Exception:
        pass

    return {"status": "not_found", "message": f"Chart not found for {sym}"}

# ────────────────────────────────────────────────────────────────────
# 8. ROOT HEALTH CHECK ROUTE
# ────────────────────────────────────────────────────────────────────
@app.get("/")
async def root_status():
    return {
        "service": "PSX FDS Pro Central Engine",
        "status": "online",
        "version": "3.2.0",
        "admin_portal": "/admin",
        "cached_symbols": len(_market_cache["stocks"]),
        "last_scanned": _market_cache["last_scanned"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
