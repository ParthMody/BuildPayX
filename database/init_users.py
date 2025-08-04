import os
import sqlite3
import json
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "buildpay.db")
print("Initializing database at:", DB_PATH)

db = sqlite3.connect(DB_PATH)
c = db.cursor()

# ─── Drop existing tables ────────────────────────────────────────────
c.execute("DROP TABLE IF EXISTS ledger")
c.execute("DROP TABLE IF EXISTS purchase_orders")
c.execute("DROP TABLE IF EXISTS users")

# ─── Create users table with role hierarchy ──────────────────────────
c.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL, -- head_contractor, pm, cfo, etc.
    head_contractor_id INTEGER,
    FOREIGN KEY(head_contractor_id) REFERENCES users(id)
)
""")

# ─── Create purchase_orders table ───────────────────────────────────
c.execute("""
CREATE TABLE purchase_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_number TEXT,
    supplier TEXT,
    description TEXT,
    advance_pct INTEGER,
    delivery_days INTEGER,
    insurance_status TEXT,
    claim_count INTEGER,
    amount FLOAT DEFAULT 0.0,
    scenario_tag TEXT,
    status TEXT DEFAULT 'pending',
    features_json TEXT,
    requester_id INTEGER,
    approved_by_pm INTEGER,
    approved_reason_pm TEXT,
    approved_by_cfo INTEGER,
    approved_reason_cfo TEXT,
    FOREIGN KEY(requester_id) REFERENCES users(id)
)
""")

# ─── Create ledger table ─────────────────────────────────────────────
c.execute("""
CREATE TABLE ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_id INTEGER,
    performed_by INTEGER,
    action TEXT,
    remarks TEXT,
    timestamp TEXT,
    FOREIGN KEY(po_id) REFERENCES purchase_orders(id),
    FOREIGN KEY(performed_by) REFERENCES users(id)
)
""")

# ─── Insert demo users ───────────────────────────────────────────────
users = [
    ("alice", "alicepass", "head_contractor", None),
    ("dave",  "davepass",  "pm", None),
    ("emma",  "emmapass",  "cfo", None),
    ("frank", "frankpass", "project_accountant", None),
    ("george", "georgepass", "project_director", None),
    ("harry", "harrypass", "ext_qs", None),
    ("ian", "ianpass", "commercial_manager", None),
]

for username, password, role, head_id in users:
    pw_hash = generate_password_hash(password)
    c.execute("""
        INSERT INTO users (username, password_hash, role, head_contractor_id)
        VALUES (?, ?, ?, ?)
    """, (username, pw_hash, role, head_id))

db.commit()

# ─── Get user IDs ────────────────────────────────────────────────────
def get_user_id(username):
    return c.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]

alice_id = get_user_id('alice')

# ─── Insert demo POs (uploaded by head contractor) ───────────────────
demo_pos = [
    ("PO001", "IronBuild Ltd", "Steel Delivery",          85, 3, "valid",   0, 32000.0, "green"),
    ("PO002", "CementWorks",   "Late Cement Supply",      85, 7, "expired", 1, 67000.0, "yellow"),
    ("PO003", "PlumbX Pty",    "Urgent Plumbing Install", 85, 5, "valid",   2, 95000.0, "red"),
]

demo_features = [
    {"advance_pct": 85, "delivery_days": 3, "insurance_status": 1, "claim_count": 0},
    {"advance_pct": 85, "delivery_days": 7, "insurance_status": 0, "claim_count": 1},
    {"advance_pct": 85, "delivery_days": 5, "insurance_status": 1, "claim_count": 2},
]

for (po_number, supplier, desc, adv, days, ins_status, claims, amount, tag), feats in zip(demo_pos, demo_features):
    status = "auto-approved" if tag == "green" else "awaiting-review"
    c.execute("""
        INSERT INTO purchase_orders (
            po_number, supplier, description,
            advance_pct, delivery_days, insurance_status,
            claim_count, amount, scenario_tag, status,
            features_json, requester_id,
            approved_by_pm, approved_reason_pm,
            approved_by_cfo, approved_reason_cfo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        po_number, supplier, desc,
        adv, days, ins_status,
        claims, amount, tag, status,
        json.dumps(feats), alice_id,
        None, None,
        None, None
    ))

    po_id = c.lastrowid
    action = "Auto-approved (green)" if tag == "green" else "Marked for review"
    c.execute("""
        INSERT INTO ledger (po_id, performed_by, action, timestamp)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    """, (po_id, alice_id, action))

db.commit()
db.close()
print("Database initialized: POs now uploaded by Head Contractor only.")