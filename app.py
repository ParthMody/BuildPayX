import os
import sqlite3
import csv
import json
from flask import (
    Flask, g, render_template, request,
    redirect, url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from predict import predict_scenario
# from weasyprint import HTML

app = Flask(__name__)
app.secret_key = "hello-world"  # Change this for production

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database", "buildpay.db")

# ======================= DB Helpers =============================
def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")  # Recommended
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ======================= Auth & Role Helpers =====================
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Login required", "danger")
                return redirect(url_for('login'))
            db = get_db()
            user = db.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            if not user or user['role'] not in roles:
                flash("Unauthorized access", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

ROLE_LANDING = {
    'subcontractor':  'dashboard',
    'head_contractor': 'hc_dashboard',
    'pm': 'pm_landing',
    'cfo': 'cfo_landing'
}

@app.context_processor
def utility_functions():
    def status_class(status):
        s = status.lower()
        if "approved" in s: return "bg-success"
        if "reject"   in s: return "bg-danger"
        return "bg-warning"
    def scenario_class(tag):
        t = tag.lower()
        if "green"  in t: return "bg-success"
        if "yellow" in t: return "bg-warning"
        if "red"    in t: return "bg-danger"
        return "bg-secondary"
    def status_icon(status):
        s = status.lower()
        if "approved" in s: return "bi-check-circle"
        if "reject"   in s: return "bi-x-circle"
        return "bi-exclamation-circle"
    def scenario_icon(tag):
        t = tag.lower()
        if "green"  in t: return "bi-check2-circle"
        if "yellow" in t: return "bi-exclamation-circle"
        if "red"    in t: return "bi-x-circle"
        return "bi-question-circle"
    return dict(
        status_class=status_class,
        scenario_class=scenario_class,
        status_icon=status_icon,
        scenario_icon=scenario_icon
    )

# ======================= Core Logic ===========================
def compute_buildscore(user_id):
    db = get_db()

    total_pos, approved_pos = db.execute("""
        SELECT COUNT(*), SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END)
        FROM purchase_orders WHERE requester_id = ?
    """, (user_id,)).fetchone()

    if not total_pos or total_pos == 0:
        return 0  # No POs means BuildScore must be zero

    approval_score = (approved_pos / total_pos * 100) if approved_pos else 0

    avg_days = db.execute("""
        SELECT AVG(delivery_days) FROM purchase_orders
        WHERE requester_id = ?
    """, (user_id,)).fetchone()[0] or 10
    delivery_score = max(0, (10 - avg_days)) * 10

    avg_claims = db.execute("""
        SELECT AVG(claim_count) FROM purchase_orders
        WHERE requester_id = ?
    """, (user_id,)).fetchone()[0] or 2
    claim_score = max(0, (2 - avg_claims)) * 50

    tag_counts = dict(db.execute("""
        SELECT scenario_tag, COUNT(*) FROM purchase_orders
        WHERE requester_id = ? GROUP BY scenario_tag
    """, (user_id,)).fetchall())
    total_tags = sum(tag_counts.values())
    tag_score = 0
    if total_tags > 0:
        weights = {'green': 100, 'yellow': 60, 'red': 30}
        tag_score = sum(weights.get(tag, 50) * count for tag, count in tag_counts.items()) / total_tags

    final_score = (
        0.25 * approval_score +
        0.25 * delivery_score +
        0.25 * claim_score +
        0.25 * tag_score
    )
    return round(final_score)

def buildscore_tier(score):
    if score >= 85:
        return 'Platinum'
    elif score >= 70:
        return 'Gold'
    elif score >= 50:
        return 'Silver'
    else:
        return 'Bronze'


# ======================= AUTH ===========================
@app.route('/')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form['username'].strip()
        pw   = request.form['password']
        role = request.form['role']
        # Accept only allowed roles
        if not user or not pw or role not in ROLE_LANDING:
            flash('All fields required & valid role.', 'danger')
            return render_template('signup.html')
        db = get_db()
        try:
            pw_hash = generate_password_hash(pw)
            cur = db.execute("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",
                             (user, pw_hash, role))
            db.commit()
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'danger')
            return render_template('signup.html')

        session.clear()
        session['user_id'] = cur.lastrowid
        session['role']    = role
        flash(f'Welcome, {user}!', 'success')
        return redirect(url_for(ROLE_LANDING[role]))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = request.form['username'].strip()
        pw   = request.form['password']
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
        if row and check_password_hash(row['password_hash'], pw):
            session.clear()
            session['user_id'] = row['id']
            session['role']    = row['role']
            landing = ROLE_LANDING.get(row['role'], 'dashboard')
            return redirect(url_for(landing))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =================== HEAD CONTRACTOR ROUTES ===================
@app.route('/hc/dashboard')
@login_required
@roles_required('head_contractor')
def hc_dashboard():
    db = get_db()
    hc_id = session['user_id']

    # Get all subcontractors for this HC
    subs = db.execute(
        "SELECT id, username FROM users WHERE head_contractor_id = ? AND role = 'subcontractor'", (hc_id,)
    ).fetchall()

    # Group their POs (optional for tables)
    grouped_pos = []
    for sub in subs:
        pos = db.execute(
            "SELECT * FROM purchase_orders WHERE requester_id = ? ORDER BY id DESC", (sub['id'],)
        ).fetchall()
        grouped_pos.append({'subcontractor': sub['username'], 'pos': pos})

    # For chart: Prepare PO counts and SC names in sync
    po_counts = []
    subcontractor_names = []
    total_pos = 0
    red_pos = 0

    for sub in subs:
        count = db.execute(
            "SELECT COUNT(*) FROM purchase_orders WHERE requester_id = ?", (sub['id'],)
        ).fetchone()[0]
        po_counts.append(count)
        subcontractor_names.append(sub['username'])
        total_pos += count
        red_count = db.execute(
            "SELECT COUNT(*) FROM purchase_orders WHERE requester_id = ? AND scenario_tag = 'red'", (sub['id'],)
        ).fetchone()[0]
        red_pos += red_count

    # Defensive programming: If there are no subs, defaults
    if not po_counts:
        po_counts = [0]
        subcontractor_names = ['None']

    # Optional: Retention/Risk Score logic
    retention_score = 68

    return render_template(
        'hc_dashboard.html',
        grouped_pos=grouped_pos,
        po_counts=po_counts,
        subcontractor_names=subcontractor_names,
        total_pos=total_pos,
        red_pos=red_pos,
        retention_score=retention_score
    )

@app.route('/subcontractors_list')
@login_required
@roles_required('head_contractor')
def subcontractors_list():
    db = get_db()
    hc_id = session['user_id']
    subs = db.execute("""
        SELECT u.id, u.username, COUNT(po.id) AS po_count
        FROM users u
        LEFT JOIN purchase_orders po ON po.requester_id = u.id
        WHERE u.role = 'subcontractor' AND u.head_contractor_id = ?
        GROUP BY u.id
    """, (hc_id,)).fetchall()
    return render_template('hc_subcontractors.html', subs=subs)

@app.route('/head_po_overview')
@login_required
@roles_required('head_contractor')
def head_po_overview():
    db = get_db()
    hc_id = session['user_id']
    pos = db.execute("""
        SELECT po.*, u.username AS requester_name
        FROM purchase_orders po
        JOIN users u ON po.requester_id = u.id
        WHERE u.head_contractor_id = ? AND u.role = 'subcontractor'
        ORDER BY po.id DESC
    """, (hc_id,)).fetchall()
    return render_template('hc_po_overview.html', pos=pos)

@app.route('/head_notifications')
@login_required
@roles_required('head_contractor')
def head_notifications():
    db = get_db()
    hc_id = session['user_id']
    pos = db.execute("""
        SELECT po.*, u.username AS requester_name
        FROM purchase_orders po
        JOIN users u ON po.requester_id = u.id
        WHERE po.status IN ('awaiting-review', 'pending-cfo', 'override-approved')
          AND u.head_contractor_id = ? AND u.role = 'subcontractor'
        ORDER BY po.id DESC
    """, (hc_id,)).fetchall()
    return render_template('hc_notifications.html', pos=pos)

# ================ SUBCONTRACTOR (SUPPLIER) ROUTES =============
@app.route('/dashboard')
@login_required
@roles_required('subcontractor')
def dashboard():
    db = get_db()
    score = compute_buildscore(session['user_id'])  # already integer
    # Fetch username for the profile card
    username = db.execute(
        "SELECT username FROM users WHERE id = ?", (session['user_id'],)
    ).fetchone()["username"]
    tier = buildscore_tier(score)
    return render_template('materialSupplier.html', score=score, tier=tier, username=username)

@app.route('/profile')
@login_required
def profile():
    return render_template('ms-profile.html')

@app.route('/msnotifications')
@login_required
def msnotifications():
    return render_template('ms-noti.html')

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html')

@app.route('/submit-claim')
@login_required
@roles_required('subcontractor')
def submit_claim():
    return render_template('ms-form.html')

@app.route('/claim-status')
@login_required
@roles_required('subcontractor')
def claim_status():
    return render_template('ms-claims.html')

@app.route('/api/claims')
@login_required
@roles_required('subcontractor')
def get_claims():
    db = get_db()
    cursor = db.execute("""
        SELECT id, po_number, description AS project, status, amount
        FROM purchase_orders
        WHERE requester_id = ?
    """, (session['user_id'],))
    rows = cursor.fetchall()
    claims = [
        {
            'id': row['id'],
            'po_number': row['po_number'],
            'project': row['project'],
            'status': row['status'],
            'amount': row['amount']
        }
        for row in rows
    ]
    return jsonify(claims)

@app.route('/upload', methods=['POST'])
@login_required
@roles_required('subcontractor')
def upload_po():
    file = request.files.get('po_file')
    if not file or not file.filename.lower().endswith('.csv'):
        flash('Only CSV allowed.', 'danger')
        return redirect(url_for('dashboard'))

    tmp_path = os.path.join(BASE_DIR, 'temp_' + secure_filename(file.filename))
    file.save(tmp_path)
    db = get_db()

    inserted = 0
    with open(tmp_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                advance_pct = int(row['advance_pct'].strip())
                delivery_days = int(row['delivery_days'].strip())
                insurance_status_str = row['insurance_status'].strip().lower()
                insurance_valid = 1 if insurance_status_str == "valid" else 0
                claim_count = int(row['claim_count'].strip())
                amount = float(row['amount'].strip() if row.get('amount') else 0.0)

                # --- ALL model features expected ---
                feats = {
                    "po_amount": amount,
                    "po_days": delivery_days,
                    "supplier_score": float(row.get("supplier_score", 0.8)),
                    "retention_rate": float(row.get("retention_rate", 0.05)),
                    "compliance_score": float(row.get("compliance_score", 0.8)),
                    "early_payment_flag": int(row.get("early_payment_flag", 0)),
                    "subcontractor_history": int(row.get("subcontractor_history", 1)),
                }

                tag_result = predict_scenario(feats)
                print("Predict result:", tag_result)
                if isinstance(tag_result, dict) and 'prediction' in tag_result:
                    classmap = {0: 'green', 1: 'yellow', 2: 'red'}
                    tag = classmap.get(tag_result['prediction'], 'unknown')
                elif isinstance(tag_result, str):
                    tag = tag_result
                else:
                    tag = 'unknown'

                status = "auto-approved" if tag == "green" else "awaiting-review"

                cur = db.execute(
                    """
                    INSERT INTO purchase_orders (
                        po_number, supplier, description,
                        advance_pct, delivery_days, insurance_status,
                        claim_count, amount, scenario_tag, status,
                        features_json, requester_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row['po_number'],
                        row['supplier'],
                        row['description'],
                        advance_pct,
                        delivery_days,
                        insurance_valid,
                        claim_count,
                        amount,
                        tag,
                        status,
                        json.dumps(feats),
                        session['user_id']
                    )
                )

                po_id = cur.lastrowid
                action = "Auto-approved (green)" if tag == "green" else "Marked for review"
                db.execute(
                    """
                    INSERT INTO ledger (po_id, performed_by, action, timestamp)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """, (po_id, session['user_id'], action)
                )
                inserted += 1
                print(f"Inserted PO: {row['po_number']} (ID {po_id})")
            except Exception as e:
                flash(f"Row failed: {row} – {str(e)}", 'danger')
                print(f"[UPLOAD ERROR] Row: {row}\n[ERROR]: {e}")


    db.commit()
    os.remove(tmp_path)
    if inserted > 0:
        flash(f'{inserted} PO(s) uploaded & logged.', 'success')
    else:
        flash('No POs were inserted (see errors above).', 'danger')
    return redirect(url_for('dashboard'))

# ================ PROJECT MANAGER ROUTES =============
@app.route('/projectmanager')
@login_required
@roles_required('pm')
def pm_landing():
    return render_template('projectmanager.html')

@app.route('/notifications')
@login_required
def notifications():
    return render_template('pmo-noti.html')

@app.route('/pmo/users')
@login_required
@roles_required('pm')
def pmo_users():
    db = get_db()
    users = db.execute("""
        SELECT u.id, u.username, COUNT(po.id) AS po_count
        FROM users u
        JOIN purchase_orders po ON po.requester_id = u.id
        WHERE u.role = 'subcontractor'
        GROUP BY u.id
    """).fetchall()
    return render_template('pm-users.html', users=users)

@app.route('/pmo/user/<int:user_id>')
@login_required
@roles_required('pm')
def pmo_user_uploads(user_id):
    db = get_db()
    pos = db.execute("""
        SELECT * FROM purchase_orders
        WHERE requester_id = ?
        ORDER BY id DESC
    """, (user_id,)).fetchall()
    requester = db.execute(
        "SELECT username FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return render_template('pm-user-uploads.html', pos=pos, requester=requester)

@app.route('/po/<int:po_id>')
@login_required
def po_detail(po_id):
    db = get_db()
    po = db.execute(
        "SELECT * FROM purchase_orders WHERE id = ?", (po_id,)
    ).fetchone()
    if not po:
        flash("PO not found", "danger")
        return redirect(url_for('dashboard'))

    ledger_entries = db.execute("""
        SELECT timestamp, users.username AS performed_by, action, remarks
        FROM ledger
        JOIN users ON users.id = ledger.performed_by
        WHERE po_id = ?
        ORDER BY timestamp ASC
    """, (po_id,)).fetchall()
    uploader = db.execute(
        "SELECT username FROM users WHERE id = ?", (po['requester_id'],)
    ).fetchone()['username']
    return render_template(
        'pm-po-details.html',
        po=po,
        ledger=ledger_entries,
        uploader=uploader,
        viewer_role='pm'
    )

@app.route('/pmo/approve/<int:po_id>', methods=['POST'])
@login_required
@roles_required('pm')
def pmo_approve(po_id):
    reason = request.form.get('reason', '').strip()
    db = get_db()
    po = db.execute("""
        SELECT requester_id, scenario_tag, approved_by_cfo
        FROM purchase_orders
        WHERE id = ?
    """, (po_id,)).fetchone()
    if not po:
        flash("Purchase order not found.", "danger")
        return redirect(url_for('pm_landing'))
    requester_id, risk_color, approved_by_cfo = po
    risk_color = risk_color.lower()
    if risk_color == 'red':
        new_status = 'fully-approved' if approved_by_cfo else 'pending-cfo'
    else:
        new_status = 'fully-approved'
    db.execute("""
        UPDATE purchase_orders
        SET status = ?, approved_by_pm = ?, approved_reason_pm = ?
        WHERE id = ?
    """, (new_status, session['user_id'], reason, po_id))
    db.execute("""
        INSERT INTO ledger (po_id, performed_by, action, remarks, timestamp)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (po_id, session['user_id'], 'PM approved', reason))
    db.commit()
    flash(f"PO marked as {new_status.replace('-', ' ').capitalize()}.", 'success')
    return redirect(url_for('pmo_user_uploads', user_id=requester_id))

@app.route('/pmo/reject/<int:po_id>', methods=['POST'])
@login_required
@roles_required('pm')
def pmo_reject(po_id):
    reason = request.form.get('reason', '').strip()
    db = get_db()
    db.execute("""
        UPDATE purchase_orders
        SET status = 'rejected',
            approved_by_pm = ?, approved_reason_pm = ?
        WHERE id = ?
    """, (session['user_id'], reason, po_id))
    db.execute("""
        INSERT INTO ledger (po_id, performed_by, action, remarks, timestamp)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (po_id, session['user_id'], 'PM rejected', reason))
    db.commit()
    flash("PO rejected by PM.", "warning")
    return redirect(url_for('pm_landing'))

# ===================== CFO ROUTES ========================
@app.route('/cfo')
@login_required
@roles_required('cfo')
def cfo_landing():
    db = get_db()
    paid = db.execute("SELECT COUNT(*) FROM purchase_orders WHERE status = 'paid'").fetchone()[0]
    pending = db.execute("SELECT COUNT(*) FROM purchase_orders WHERE status IN ('fully-approved', 'approved', 'pending-cfo')").fetchone()[0]
    compliant = db.execute("SELECT COUNT(*) FROM purchase_orders WHERE status = 'fully-approved'").fetchone()[0]
    stats = {"paid": paid, "pending": pending, "compliant": compliant}
    return render_template('cfo.html', stats=stats)


@app.route('/cfonotifications')
@login_required
def cfonotifications():
    return render_template('cfo-noti.html')

@app.route('/cfoprofile')
@login_required
def cfoprofile():
    return render_template('cfo-profile.html')

@app.route('/cfo/users')
@login_required
@roles_required('cfo')
def cfo_users():
    db = get_db()
    users = db.execute("""
        SELECT u.id, u.username, COUNT(po.id) AS po_count
        FROM users u
        JOIN purchase_orders po ON po.requester_id = u.id
        WHERE u.role = 'subcontractor'
        GROUP BY u.id
    """).fetchall()
    return render_template('cfo-users.html', users=users)

@app.route('/cfo/user/<int:user_id>')
@login_required
@roles_required('cfo')
def cfo_user_uploads(user_id):
    db = get_db()
    # Show *all* POs for the user
    pos = db.execute("""
        SELECT * FROM purchase_orders
        WHERE requester_id = ?
        ORDER BY id DESC
    """, (user_id,)).fetchall()
    requester = db.execute(
        "SELECT username FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return render_template('cfo-user-uploads.html', pos=pos, requester=requester)


@app.route('/cfo/po/<int:po_id>')
@login_required
def po_detail_cfo(po_id):
    db = get_db()
    po = db.execute(
        "SELECT * FROM purchase_orders WHERE id = ?", (po_id,)
    ).fetchone()
    if not po:
        flash("PO not found", "danger")
        return redirect(url_for('dashboard'))
    ledger_entries = db.execute("""
        SELECT timestamp, users.username AS performed_by, action, remarks
        FROM ledger
        JOIN users ON users.id = ledger.performed_by
        WHERE po_id = ?
        ORDER BY timestamp ASC
    """, (po_id,)).fetchall()
    uploader = db.execute(
        "SELECT username FROM users WHERE id = ?", (po['requester_id'],)
    ).fetchone()['username']
    return render_template(
        'cfo-po-details.html',
        po=po,
        ledger=ledger_entries,
        uploader=uploader,
        viewer_role='cfo'
    )

@app.route('/cfo/approve/<int:po_id>', methods=['POST'])
@login_required
@roles_required('cfo')
def cfo_approve(po_id):
    reason = request.form.get('reason', '').strip()
    db = get_db()
    po = db.execute("""
        SELECT status, approved_by_pm, scenario_tag
        FROM purchase_orders
        WHERE id = ?
    """, (po_id,)).fetchone()
    if not po:
        flash("PO not found.", "danger")
        return redirect(url_for('dashboard'))
    current_status, approved_by_pm, risk_color = po
    risk_color = risk_color.lower()
    if risk_color == 'red':
        if approved_by_pm:
            new_status = 'fully-approved'
            action = 'CFO approved (final)'
        else:
            new_status = 'pending-pm'
            action = 'CFO approved (awaiting PM approval)'
    else:
        new_status = 'fully-approved' if approved_by_pm else 'override-approved'
        action = 'CFO approved (final)' if approved_by_pm else 'CFO override approved'
    db.execute("""
        UPDATE purchase_orders
        SET status = ?, approved_by_cfo = ?, approved_reason_cfo = ?
        WHERE id = ?
    """, (new_status, session['user_id'], reason, po_id))
    db.execute("""
        INSERT INTO ledger (po_id, performed_by, action, remarks, timestamp)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (po_id, session['user_id'], action, reason))
    db.commit()
    flash(f"PO marked as {new_status.replace('-', ' ').capitalize()}.", 'success')
    return redirect(url_for('po_detail_cfo', po_id=po_id))


@app.route('/cfo/reject/<int:po_id>', methods=['POST'])
@login_required
@roles_required('cfo')
def cfo_reject(po_id):
    reason = request.form.get('reason', '').strip()
    db = get_db()
    db.execute("""
        UPDATE purchase_orders
        SET status = 'cfo-rejected',
            approved_by_cfo = ?, approved_reason_cfo = ?
        WHERE id = ?
    """, (session['user_id'], reason, po_id))
    db.execute("""
        INSERT INTO ledger (po_id, performed_by, action, remarks, timestamp)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (po_id, session['user_id'], 'CFO rejected', reason))
    db.commit()
    flash("PO rejected by CFO.", 'warning')
    return redirect(url_for('po_detail_cfo', po_id=po_id))

# --- CFO Batch Payment Table ---
@app.route('/cfo/batch-payments', methods=['GET', 'POST'])
@login_required
@roles_required('cfo')
def cfo_batch_payments():
    db = get_db()
    if request.method == "POST":
        # Mark selected POs as paid (IDs from checkboxes)
        po_ids = request.form.getlist('po_id')
        for po_id in po_ids:
            db.execute("UPDATE purchase_orders SET status = 'paid' WHERE id = ?", (po_id,))
            db.execute(
                "INSERT INTO ledger (po_id, performed_by, action, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (po_id, session['user_id'], 'CFO marked paid')
            )
        db.commit()
        flash(f"{len(po_ids)} PO(s) marked as paid.", "success")
        return redirect(url_for('cfo_batch_payments'))
    # Only fully-approved and not-yet-paid POs are eligible for batch payment
    pos = db.execute("""
        SELECT po.*, u.username AS requester_name
        FROM purchase_orders po
        JOIN users u ON po.requester_id = u.id
        WHERE po.status = 'fully-approved'
        ORDER BY po.id ASC
    """).fetchall()
    return render_template('cfo-batch-payments.html', pos=pos)

@app.route('/cfo/reconciliation')
@login_required
@roles_required('cfo')
def cfo_reconciliation():
    db = get_db()
    pos = db.execute("""
        SELECT po.po_number, po.amount, po.status, po.id, u.username,
            (SELECT timestamp FROM ledger WHERE po_id=po.id AND action LIKE '%paid%' ORDER BY id DESC LIMIT 1) AS paid_date
        FROM purchase_orders po
        JOIN users u ON po.requester_id = u.id
        WHERE po.status = 'paid'
        ORDER BY po.id DESC
    """).fetchall()

    sync_data = []
    for row in pos:
        # row is a sqlite3.Row, so use only ['field'] access, not .get()
        synced = "Yes" if int(row['id']) % 3 != 0 else "Pending"
        notes = "Auto sync" if synced == "Yes" else "Manual sync required"
        sync_data.append({
            "po_number": row['po_number'],
            "paid_date": row['paid_date'] or "N/A",
            "requester": row['username'],
            "amount": row['amount'],
            "synced": synced,
            "notes": notes
        })
    return render_template('cfo-reconciliation.html', sync_data=sync_data)

@app.route('/compliance-report')
@login_required
def compliance_report():
    db = get_db()
    current_role = session['role']  # e.g. 'cfo', 'pm', 'subcontractor', 'head_contractor'
    report_role = current_role  # Each user only sees their own role's view

    if report_role == 'cfo':
        # Show all paid POs
        table_data = db.execute("""
            SELECT po.po_number, po.amount, po.status, u.username as requester, 
                   (SELECT timestamp FROM ledger WHERE po_id=po.id AND action LIKE '%paid%' ORDER BY id DESC LIMIT 1) as paid_date
            FROM purchase_orders po
            JOIN users u ON po.requester_id = u.id
            WHERE po.status = 'paid'
            ORDER BY paid_date DESC
        """).fetchall()

    elif report_role == 'pm':
        # Show all pending (awaiting-review) and rejected (not yet paid/approved) POs
        table_data = db.execute("""
            SELECT po.po_number, po.amount, po.status, u.username as requester,
                   (SELECT timestamp FROM ledger WHERE po_id=po.id ORDER BY id ASC LIMIT 1) as created_date
            FROM purchase_orders po
            JOIN users u ON po.requester_id = u.id
            WHERE po.status IN ('awaiting-review', 'rejected')
            ORDER BY created_date DESC
        """).fetchall()

    elif report_role == 'head_contractor':
        # Show a scorecard: one row per subcontractor with total POs and total paid
        table_data = db.execute("""
            SELECT u.username, 
                   COUNT(po.id) as total_pos,
                   SUM(CASE WHEN po.status='paid' THEN 1 ELSE 0 END) as paid_pos
            FROM users u
            LEFT JOIN purchase_orders po ON po.requester_id = u.id
            WHERE u.role='subcontractor'
            GROUP BY u.id
            ORDER BY total_pos DESC
        """).fetchall()

    elif report_role == 'subcontractor':
        # Show this user's own POs (all statuses)
        table_data = db.execute("""
            SELECT po.po_number, po.amount, po.status,
                   (SELECT timestamp FROM ledger WHERE po_id=po.id ORDER BY id ASC LIMIT 1) as created_date
            FROM purchase_orders po
            WHERE po.requester_id = ?
            ORDER BY created_date DESC
        """, (session["user_id"],)).fetchall()
    else:
        table_data = []

    roles = {current_role: current_role.title()}  # For consistent signature in your template
    return render_template(
        "compliance-report.html",
        report_role=report_role,
        table_data=table_data,
        roles=roles
    )

# @app.route('/compliance-report', methods=['GET', 'POST'])
# @login_required
# def compliance_report():
#     db = get_db()
#     report_role = None
#     table_data = []
#     current_role = session['role']

#     # Default: show only user’s own role, or let admin see all
#     if request.method == 'POST':
#         report_role = request.form.get('role_select')
#     else:
#         report_role = current_role

#     # CFO: Paid POs
#     if report_role == 'cfo':
#         table_data = db.execute("""
#             SELECT po.po_number, po.amount, po.status, u.username, po.updated_at
#             FROM purchase_orders po
#             JOIN users u ON po.requester_id = u.id
#             WHERE po.status = 'paid'
#             ORDER BY po.updated_at DESC
#         """).fetchall()
#     # PM: Rejected/pending POs
#     elif report_role == 'pm':
#         table_data = db.execute("""
#             SELECT po.po_number, po.amount, po.status, u.username, po.updated_at
#             FROM purchase_orders po
#             JOIN users u ON po.requester_id = u.id
#             WHERE po.status IN ('awaiting-review', 'rejected')
#             ORDER BY po.updated_at DESC
#         """).fetchall()
#     # Head Contractor: Scorecard summary (dummy example)
#     elif report_role == 'head_contractor':
#         # For demo, show subs and counts:
#         table_data = db.execute("""
#             SELECT u.username, COUNT(po.id) as total_pos, 
#                    SUM(CASE WHEN po.status='paid' THEN 1 ELSE 0 END) as paid_pos
#             FROM users u
#             LEFT JOIN purchase_orders po ON po.requester_id=u.id
#             WHERE u.role='subcontractor'
#             GROUP BY u.id
#             ORDER BY total_pos DESC
#         """).fetchall()
#     # Subcontractor: Show own POs
#     elif report_role == 'subcontractor':
#         table_data = db.execute("""
#             SELECT po.po_number, po.amount, po.status, po.updated_at
#             FROM purchase_orders po
#             WHERE po.requester_id = ?
#             ORDER BY po.updated_at DESC
#         """, (session["user_id"],)).fetchall()

#     roles = [
#         ("cfo", "CFO"),
#         ("pm", "PMO"),
#         ("head_contractor", "Head Contractor"),
#         ("subcontractor", "Subcontractor")
#     ]
#     return render_template("compliance-report.html", report_role=report_role, table_data=table_data, roles=roles)


# =================== TEST API ===========================
@app.route('/api/test')
def test_api():
    return jsonify({"message": "Backend is connected!"})

if __name__ == '__main__':
    app.run(debug=True)