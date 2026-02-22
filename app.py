import hashlib, hmac, json, random, time, os, sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response, stream_with_context, g, send_from_directory

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cardioeye-secret-2026")
DB_PATH = "/app/cardioeye.db" if os.path.exists("/app") else os.path.join(os.path.dirname(os.path.abspath(__file__)), "cardioeye.db")
DB_TYPE = "sqlite"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def query(sql, params=(), one=False, commit=False):
    db = get_db()
    cur = db.execute(sql, params)
    if commit:
        db.commit()
        return cur.lastrowid
    return cur.fetchone() if one else cur.fetchall()

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

@app.route("/api/<path:p>", methods=["OPTIONS"])
def options_handler(p):
    return jsonify({"ok": True})

@app.route("/")
def serve_frontend():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "CardioEye.html")

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def make_token(user_id, role):
    import base64
    payload = json.dumps({"uid": user_id, "role": role, "exp": (datetime.utcnow() + timedelta(days=7)).isoformat()})
    sig = hmac.new(app.config["SECRET_KEY"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(payload.encode()).decode() + "." + sig

def verify_token(token):
    import base64
    try:
        b64, sig = token.rsplit(".", 1)
        payload_bytes = base64.b64decode(b64)
        expected = hmac.new(app.config["SECRET_KEY"].encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("bad signature")
        data = json.loads(payload_bytes)
        if datetime.fromisoformat(data["exp"]) < datetime.utcnow():
            raise ValueError("token expired")
        return data["uid"], data["role"]
    except Exception as e:
        raise ValueError(str(e))

def get_current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    token = auth[7:]
    try:
        row = query("SELECT 1 FROM revoked_tokens WHERE token=?", (token,), one=True)
        if row:
            return None, None
        uid, role = verify_token(token)
        user = query("SELECT * FROM users WHERE id=?", (uid,), one=True)
        return user, role
    except Exception:
        return None, None

def require_auth(roles=None):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def wrapper(*args, **kwargs):
            user, role = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            if roles and role not in roles:
                return jsonify({"error": "Forbidden"}), 403
            g.current_user = user
            g.current_role = role
            return f(*args, **kwargs)
        return wrapper
    return decorator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'patient',
    age INTEGER, gender TEXT, patient_id TEXT, doctor_id TEXT,
    license TEXT, specialization TEXT, hospital TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token TEXT PRIMARY KEY, revoked_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS vitals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    hr REAL, spo2 REAL, bp_sys INTEGER, bp_dia INTEGER,
    hrv REAL, arrhythmia TEXT DEFAULT 'None', risk_score REAL DEFAULT 0,
    recorded_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    type TEXT NOT NULL, title TEXT NOT NULL, message TEXT,
    acknowledged INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS clinical_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doctor_id INTEGER NOT NULL, patient_id INTEGER NOT NULL,
    note TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS doctor_patient (
    doctor_id INTEGER NOT NULL, patient_id INTEGER NOT NULL,
    assigned_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (doctor_id, patient_id)
);
CREATE TABLE IF NOT EXISTS waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL, model TEXT DEFAULT 'general',
    joined_at TEXT DEFAULT (datetime('now'))
);
"""

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)
        cur = conn.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            _seed(conn)
        conn.commit()
    print("✅ Database ready at", DB_PATH)

def _seed(conn):
    patients = [
        ("arjun.sharma@demo.com",  "demo1234", "Arjun Sharma",  62, "Male",   "CE0010001"),
        ("sunita.rao@demo.com",    "demo1234", "Sunita Rao",     71, "Female", "CE0010002"),
        ("rajesh.kumar@demo.com",  "demo1234", "Rajesh Kumar",   55, "Male",   "CE0010003"),
        ("priya.mehta@demo.com",   "demo1234", "Priya Mehta",    38, "Female", "CE0010004"),
        ("vikram.singh@demo.com",  "demo1234", "Vikram Singh",   50, "Male",   "CE0010005"),
        ("kavita.patel@demo.com",  "demo1234", "Kavita Patel",   67, "Female", "CE0010006"),
        ("deepak.nair@demo.com",   "demo1234", "Deepak Nair",    55, "Male",   "CE0010007"),
        ("ananya.iyer@demo.com",   "demo1234", "Ananya Iyer",    29, "Female", "CE0010008"),
    ]
    pids = []
    for email, pw, name, age, gender, pid in patients:
        cur = conn.execute(
            "INSERT INTO users(email,password,name,role,age,gender,patient_id) VALUES(?,?,?,?,?,?,?)",
            (email, hash_password(pw), name, "patient", age, gender, pid)
        )
        pids.append(cur.lastrowid)
    doc = conn.execute(
        "INSERT INTO users(email,password,name,role,age,gender,doctor_id,license,specialization,hospital) VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("dr.demo@cardioeye.com", hash_password("doctor1234"), "Dr. Demo Cardiologist",
         "doctor", 45, "Male", "DOC20261234", "MCI-98765", "Cardiology", "CardioEye Medical Centre")
    )
    doc_id = doc.lastrowid
    for pid in pids:
        conn.execute("INSERT INTO doctor_patient VALUES(?,?,datetime('now'))", (doc_id, pid))
    for uid, hr, spo2, bps, bpd, hrv, arr, risk in [
        (pids[0], 95,  97, 145, 92, 28, "AFib",        72),
        (pids[1], 110, 94, 158, 95, 22, "AFib",        85),
        (pids[2], 82,  95, 138, 88, 30, "PVC",         55),
        (pids[3], 88,  98, 122, 78, 44, "PAC",         32),
        (pids[4], 72,  99, 128, 82, 50, "None",        20),
        (pids[5], 68,  97, 118, 76, 42, "None",        28),
        (pids[6], 48,  96, 110, 70, 35, "Sinus Brady", 38),
        (pids[7], 78,  99, 115, 72, 55, "None",        12),
    ]:
        conn.execute("INSERT INTO vitals(user_id,hr,spo2,bp_sys,bp_dia,hrv,arrhythmia,risk_score) VALUES(?,?,?,?,?,?,?,?)",
                     (uid, hr, spo2, bps, bpd, hrv, arr, risk))
    for uid, typ, title, msg in [
        (pids[0], "critical", "Abnormal Heart Rate", "Heart rate exceeded 120 BPM"),
        (pids[0], "warning",  "Irregular Heartbeat", "Possible AFib episode detected"),
        (pids[0], "info",     "Daily Report Ready",  "Your health summary is ready"),
        (pids[1], "critical", "Tachycardia Alert",   "Heart rate 110 BPM"),
        (pids[1], "warning",  "Low SpO2",            "Oxygen saturation at 94%"),
    ]:
        conn.execute("INSERT INTO alerts(user_id,type,title,message) VALUES(?,?,?,?)", (uid, typ, title, msg))

def generate_ecg_point(index, arrhythmia="None"):
    cycle = index % (45 if arrhythmia == "AFib" else 50)
    noise = random.gauss(0, 0.015)
    if arrhythmia == "AFib":
        if cycle < 3: return random.random() * 0.2 + noise
        if cycle == 3: return 0.2 + noise
        if cycle == 4: return -0.3 + noise
        if cycle == 5: return 1.5 + random.random() * 0.4 + noise
        if cycle == 6: return -0.2 + noise
        if 7 <= cycle < 18: return random.random() * 0.15 + noise
        return random.random() * 0.1 + noise
    if arrhythmia == "PVC" and cycle == 15: return 2.2 + noise
    if cycle < 5: return noise
    if cycle == 5: return 0.2 + noise
    if cycle == 6: return -0.3 + noise
    if cycle == 7: return 1.5 + noise
    if cycle == 8: return -0.2 + noise
    if cycle == 9: return 0.3 + noise
    if 10 <= cycle < 30: return 0.1 + noise
    return noise

def _calculate_risk(hr, spo2, bps, bpd, arrhythmia):
    score = 0
    if hr > 120: score += 30
    elif hr > 100: score += 15
    elif hr < 50: score += 20
    elif hr < 60: score += 10
    if spo2 < 90: score += 30
    elif spo2 < 95: score += 15
    if bps > 160: score += 20
    elif bps > 140: score += 10
    if arrhythmia and arrhythmia not in ("None", ""):
        score += 25 if arrhythmia in ("AFib", "VTach") else 10
    return min(100, round(score, 1))

def _recommendation(score):
    if score > 60: return "Immediate medical attention recommended."
    if score > 30: return "Monitor closely. Schedule a check-up."
    return "Continue regular monitoring. Stay healthy!"

@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pw = data.get("password", "")
    role = data.get("role", "patient")
    age = data.get("age")
    gender = data.get("gender", "")
    if not name or not email or not pw:
        return jsonify({"error": "name, email and password are required"}), 400
    if len(pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if role not in ("patient", "doctor"):
        return jsonify({"error": "role must be patient or doctor"}), 400
    if query("SELECT id FROM users WHERE email=?", (email,), one=True):
        return jsonify({"error": "Email already registered"}), 409
    h = hash_password(pw)
    if role == "doctor":
        doctor_id = "DOC" + str(int(time.time() * 1000))[-8:]
        uid = query(
            "INSERT INTO users(email,password,name,role,age,gender,doctor_id,license,specialization,hospital) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (email, h, name, "doctor", age, gender, doctor_id,
             data.get("license",""), data.get("specialization","General Physician"), data.get("hospital","")), commit=True)
        return jsonify({"message": "Doctor account created", "token": make_token(uid, "doctor"),
                        "user": {"id": uid, "name": name, "email": email, "role": "doctor", "doctor_id": doctor_id}}), 201
    else:
        patient_id = "CE" + str(int(time.time() * 1000))[-10:]
        uid = query("INSERT INTO users(email,password,name,role,age,gender,patient_id) VALUES(?,?,?,?,?,?,?)",
                    (email, h, name, "patient", age, gender, patient_id), commit=True)
        query("INSERT INTO alerts(user_id,type,title,message) VALUES(?,?,?,?)",
              (uid, "info", "Welcome to CardioEye!", "Your cardiac monitoring journey begins now."), commit=True)
        return jsonify({"message": "Patient account created", "token": make_token(uid, "patient"),
                        "user": {"id": uid, "name": name, "email": email, "role": "patient",
                                 "patient_id": patient_id, "age": age, "gender": gender}}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    pw = data.get("password", "")
    role = data.get("role", "patient")
    user = query("SELECT * FROM users WHERE email=?", (email,), one=True)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user = dict(user)
    if user["password"] != hash_password(pw):
        return jsonify({"error": "Incorrect password"}), 401
    if role and user["role"] != role:
        return jsonify({"error": f"Account is registered as {user['role']}, not {role}"}), 403
    user.pop("password", None)
    return jsonify({"message": "Login successful", "token": make_token(user["id"], user["role"]), "user": user})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            query("INSERT INTO revoked_tokens(token) VALUES(?)", (auth[7:],), commit=True)
        except Exception:
            pass
    return jsonify({"message": "Logged out"})

@app.route("/api/auth/me", methods=["GET"])
@require_auth()
def me():
    user = dict(g.current_user)
    user.pop("password", None)
    return jsonify(user)

@app.route("/api/patients", methods=["GET"])
@require_auth(roles=["doctor"])
def list_patients():
    doc_id = dict(g.current_user)["id"]
    rows = query("""
        SELECT u.id, u.name, u.email, u.age, u.gender, u.patient_id,
               v.hr, v.spo2, v.bp_sys, v.bp_dia, v.hrv, v.arrhythmia, v.risk_score, v.recorded_at
        FROM users u
        JOIN doctor_patient dp ON dp.patient_id=u.id AND dp.doctor_id=?
        LEFT JOIN vitals v ON v.user_id=u.id AND v.id=(SELECT MAX(id) FROM vitals WHERE user_id=u.id)
        WHERE u.role='patient' ORDER BY u.name
    """, (doc_id,))
    patients = []
    for r in rows:
        p = dict(r)
        p["bp"] = f"{p.pop('bp_sys','?')}/{p.pop('bp_dia','?')}"
        score = p.get("risk_score") or 0
        hr = p.get("hr") or 70
        arr = p.get("arrhythmia") or "None"
        p["status"] = "critical" if (score > 60 or hr > 110 or hr < 50) else "warning" if (score > 30 or arr not in ("None", None)) else "stable"
        patients.append(p)
    return jsonify(patients)

@app.route("/api/patients/<int:patient_id>", methods=["GET"])
@require_auth()
def get_patient(patient_id):
    if g.current_role == "patient" and dict(g.current_user)["id"] != patient_id:
        return jsonify({"error": "Forbidden"}), 403
    p = query("SELECT id,name,email,age,gender,patient_id,created_at FROM users WHERE id=? AND role='patient'", (patient_id,), one=True)
    if not p:
        return jsonify({"error": "Patient not found"}), 404
    result = dict(p)
    v = query("SELECT * FROM vitals WHERE user_id=? ORDER BY id DESC LIMIT 1", (patient_id,), one=True)
    if v:
        vd = dict(v)
        result["vitals"] = {"hr": vd["hr"], "spo2": vd["spo2"], "hrv": vd["hrv"],
                            "bp": f"{vd['bp_sys']}/{vd['bp_dia']}", "arrhythmia": vd["arrhythmia"],
                            "risk_score": vd["risk_score"], "recorded_at": str(vd["recorded_at"])}
    return jsonify(result)

@app.route("/api/patients/<int:patient_id>/notes", methods=["POST"])
@require_auth(roles=["doctor"])
def add_note(patient_id):
    data = request.get_json() or {}
    note_text = (data.get("note") or "").strip()
    if not note_text:
        return jsonify({"error": "note is required"}), 400
    nid = query("INSERT INTO clinical_notes(doctor_id,patient_id,note) VALUES(?,?,?)",
                (dict(g.current_user)["id"], patient_id, note_text), commit=True)
    return jsonify({"message": "Note saved", "note_id": nid}), 201

@app.route("/api/patients/<int:patient_id>/notes", methods=["GET"])
@require_auth()
def get_notes(patient_id):
    notes = query("""SELECT cn.id, cn.note, cn.created_at, u.name as doctor_name, u.specialization
        FROM clinical_notes cn JOIN users u ON u.id=cn.doctor_id
        WHERE cn.patient_id=? ORDER BY cn.id DESC""", (patient_id,))
    return jsonify([dict(n) for n in notes])

@app.route("/api/vitals/current", methods=["GET"])
@require_auth()
def current_vitals():
    uid = dict(g.current_user)["id"]
    v = query("SELECT * FROM vitals WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,), one=True)
    if not v:
        return jsonify({"error": "No vitals recorded yet"}), 404
    vd = dict(v)
    vd["hr"] = round(float(vd["hr"]) + random.gauss(0, 2), 1)
    vd["spo2"] = round(min(100, float(vd["spo2"]) + random.gauss(0, 0.3)), 1)
    vd["bp"] = f"{vd.pop('bp_sys')}/{vd.pop('bp_dia')}"
    vd["timestamp"] = datetime.utcnow().isoformat()
    return jsonify(vd)

@app.route("/api/vitals/history", methods=["GET"])
@require_auth()
def vitals_history():
    uid = dict(g.current_user)["id"]
    limit = 7 if request.args.get("period") == "7d" else 24
    rows = query("SELECT hr,spo2,bp_sys,bp_dia,hrv,arrhythmia,risk_score,recorded_at FROM vitals WHERE user_id=? ORDER BY id DESC LIMIT ?", (uid, limit))
    return jsonify([{**dict(r), "bp": f"{dict(r)['bp_sys']}/{dict(r)['bp_dia']}"} for r in rows])

@app.route("/api/vitals/ingest", methods=["POST"])
def ingest_vitals():
    data = request.get_json() or {}
    patient_id_str = data.get("patient_id")
    if not patient_id_str:
        return jsonify({"error": "patient_id required"}), 400
    user = query("SELECT id FROM users WHERE patient_id=?", (patient_id_str,), one=True)
    if not user:
        return jsonify({"error": "Patient not found"}), 404
    hr = float(data.get("hr", 72))
    spo2 = float(data.get("spo2", 98))
    bps = int(data.get("bp_sys", 120))
    bpd = int(data.get("bp_dia", 80))
    hrv = float(data.get("hrv", 50))
    arr = data.get("arrhythmia", "None")
    risk = _calculate_risk(hr, spo2, bps, bpd, arr)
    uid = dict(user)["id"]
    vid = query("INSERT INTO vitals(user_id,hr,spo2,bp_sys,bp_dia,hrv,arrhythmia,risk_score) VALUES(?,?,?,?,?,?,?,?)",
                (uid, hr, spo2, bps, bpd, hrv, arr, risk), commit=True)
    return jsonify({"message": "Vitals recorded", "vitals_id": vid, "risk_score": risk})

@app.route("/api/ecg/stream", methods=["GET"])
def ecg_stream():
    token = request.args.get("token", "")
    try:
        uid, role = verify_token(token)
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401
    arrhythmia = "None"
    try:
        v = query("SELECT arrhythmia FROM vitals WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,), one=True)
        if v:
            arrhythmia = dict(v).get("arrhythmia", "None")
    except Exception:
        pass
    def generate():
        i = 0
        while True:
            pt = generate_ecg_point(i, arrhythmia)
            yield f"data: {json.dumps({'index': i, 'value': round(pt, 4), 'ts': time.time()})}\n\n"
            i += 1
            time.sleep(0.05)
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/alerts", methods=["GET"])
@require_auth()
def get_alerts():
    uid = dict(g.current_user)["id"]
    rows = query("SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 50", (uid,))
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@require_auth()
def ack_alert(alert_id):
    uid = dict(g.current_user)["id"]
    if not query("SELECT id FROM alerts WHERE id=? AND user_id=?", (alert_id, uid), one=True):
        return jsonify({"error": "Alert not found"}), 404
    query("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,), commit=True)
    return jsonify({"message": "Alert acknowledged"})

@app.route("/api/reports/daily", methods=["GET"])
@require_auth()
def daily_report():
    uid = dict(g.current_user)["id"]
    rows = query("SELECT hr,spo2,bp_sys,bp_dia,hrv,arrhythmia,risk_score,recorded_at FROM vitals WHERE user_id=? ORDER BY id DESC LIMIT 24", (uid,))
    records = [dict(r) for r in rows]
    if not records:
        return jsonify({"error": "No data available"}), 404
    hrs = [r["hr"] for r in records if r.get("hr")]
    spo2s = [r["spo2"] for r in records if r.get("spo2")]
    risks = [r["risk_score"] for r in records if r.get("risk_score") is not None]
    status = "Critical" if any((r.get("risk_score") or 0) > 60 for r in records) else "Warning" if any((r.get("risk_score") or 0) > 30 for r in records) else "Stable"
    return jsonify({"generated_at": datetime.utcnow().isoformat(), "period": "Last 24 readings",
                    "heart_rate": {"min": round(min(hrs),1) if hrs else None, "max": round(max(hrs),1) if hrs else None, "avg": round(sum(hrs)/len(hrs),1) if hrs else None},
                    "spo2": {"min": round(min(spo2s),1) if spo2s else None, "avg": round(sum(spo2s)/len(spo2s),1) if spo2s else None},
                    "risk_score_avg": round(sum(risks)/len(risks),1) if risks else None,
                    "arrhythmia_detected": any(r.get("arrhythmia") not in (None,"None") for r in records),
                    "total_readings": len(records), "status": status})

@app.route("/api/reports/risk", methods=["GET"])
@require_auth()
def risk_score():
    uid = dict(g.current_user)["id"]
    v = query("SELECT * FROM vitals WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,), one=True)
    if not v:
        return jsonify({"error": "No vitals data"}), 404
    vd = dict(v)
    score = _calculate_risk(vd["hr"], vd["spo2"], vd["bp_sys"], vd["bp_dia"], vd["arrhythmia"])
    factors = []
    if vd["hr"] > 100: factors.append(f"Tachycardia (HR {vd['hr']} BPM)")
    if vd["hr"] < 60: factors.append(f"Bradycardia (HR {vd['hr']} BPM)")
    if vd["spo2"] < 95: factors.append(f"Low SpO2 ({vd['spo2']}%)")
    if vd["bp_sys"] > 140: factors.append(f"High BP ({vd['bp_sys']}/{vd['bp_dia']} mmHg)")
    if vd["arrhythmia"] not in (None,"None",""): factors.append(f"Arrhythmia: {vd['arrhythmia']}")
    return jsonify({"risk_score": score, "risk_level": "High" if score > 60 else "Moderate" if score > 30 else "Low",
                    "contributing_factors": factors, "recommendation": _recommendation(score),
                    "calculated_at": datetime.utcnow().isoformat()})

@app.route("/api/doctors/patients", methods=["GET"])
@require_auth(roles=["doctor"])
def doctor_patients():
    return list_patients()

@app.route("/api/doctors/assign", methods=["POST"])
@require_auth(roles=["doctor"])
def assign_patient():
    data = request.get_json() or {}
    patient_email = (data.get("patient_email") or "").strip().lower()
    patient_row = query("SELECT id FROM users WHERE email=? AND role='patient'", (patient_email,), one=True)
    if not patient_row:
        return jsonify({"error": "Patient not found"}), 404
    try:
        query("INSERT INTO doctor_patient(doctor_id,patient_id) VALUES(?,?)",
              (dict(g.current_user)["id"], dict(patient_row)["id"]), commit=True)
    except Exception:
        return jsonify({"message": "Patient already assigned"})
    return jsonify({"message": "Patient assigned successfully"})

@app.route("/api/waitlist", methods=["POST"])
def waitlist():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    model = data.get("model", "general")
    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    try:
        query("INSERT INTO waitlist(email,model) VALUES(?,?)", (email, model), commit=True)
        return jsonify({"message": f"You're on the waitlist!"}), 201
    except Exception:
        return jsonify({"message": "You're already on the waitlist!"}), 200

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "CardioEye Backend", "version": "3.0.0",
                    "db": DB_TYPE, "timestamp": datetime.utcnow().isoformat()})

with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"DB init error: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"CardioEye v3 running on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
