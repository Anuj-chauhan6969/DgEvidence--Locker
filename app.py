"""
app.py – Digital Evidence Locker (Full Upgrade)
Features: 2FA OTP login, encrypted uploads, case management, admin dashboard,
          delete-request workflow, audit trail, search/filter, settings.
"""
from flask import (Flask, render_template, send_from_directory, redirect,
                   url_for, session, flash, request, jsonify, abort)
import os, re, uuid, datetime, threading, time, functools, tempfile, shutil
from dotenv import load_dotenv

load_dotenv()

from database import db
from email_util import (generate_otp, send_otp, send_upload_notification,
                        send_status_notification,
                        send_delete_request_admin_notification,
                        send_delete_request_status,
                        send_delete_confirmation_otp)
from database import ADMIN_EMAIL
from encryption_util import encrypt_evidence, compute_sha256, decrypt_evidence, ENC_EXT

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-only-change-this-secret')
app.permanent_session_lifetime = datetime.timedelta(hours=8)

UPLOADS_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
TEMP_DIR    = os.path.join(os.path.dirname(__file__), 'tmp_previews')
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR,    exist_ok=True)

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
ALLOWED_TYPES = {
    '.jpg','.jpeg','.png','.gif','.webp','.heic','.bmp','.svg',
    '.mp4','.mov','.avi','.mkv','.webm','.wmv','.flv',
    '.mp3','.wav','.ogg','.flac','.m4a','.aac','.wma',
    '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.odt','.csv',
    '.txt',
}

def classify_file(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext in {'.jpg','.jpeg','.png','.gif','.webp','.heic','.bmp','.svg'}: return 'image'
    if ext in {'.mp4','.mov','.avi','.mkv','.webm','.wmv','.flv'}: return 'video'
    if ext in {'.mp3','.wav','.ogg','.flac','.m4a','.aac','.wma'}: return 'audio'
    if ext in {'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.odt','.csv'}: return 'doc'
    if ext == '.txt': return 'text'
    return 'file'

def human_size(b: int) -> str:
    for unit in ['B','KB','MB','GB']:
        if b < 1024: return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} TB'

def get_ip():
    return request.remote_addr or 'unknown'

def is_valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@(gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|[\w.-]+\.eu|[\w.-]+\.in|dgevidencelocker\.com)$'
    return bool(re.match(pattern, email))

# ── Decorators ───────────────────────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or not session.get('otp_verified'):
            flash('Please complete login first.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or not session.get('otp_verified'):
            flash('Please login first.', 'danger')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return wrapper

def current_user():
    return {
        'id':       session.get('user_id'),
        'username': session.get('user'),
        'email':    session.get('email'),
        'role':     session.get('role', 'user'),
    }

# ── Public Routes ────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    if 'user_id' in session and session.get('otp_verified'):
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/verify-otp')
def verify_otp_page():
    if 'pending_email' not in session:
        return redirect(url_for('login'))
    return render_template('verify_otp.html',
                           purpose=session.get('otp_purpose', 'login'),
                           email=session.get('pending_email', ''))

# ── Auth ─────────────────────────────────────────────────────────────────────
@app.route('/auth/register', methods=['POST'])
def auth_register():
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip()
    mobile   = request.form.get('mobile', '').strip()
    password = request.form.get('password', '').strip()
    confirm  = request.form.get('confirm_password', '').strip()

    if not all([username, email, password]):
        flash('Please fill all required fields.', 'danger')
        return redirect(url_for('register'))
    if not is_valid_email(email):
        flash('Please enter a valid email address.', 'danger')
        return redirect(url_for('register'))
    if password != confirm:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('register'))
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'danger')
        return redirect(url_for('register'))

    # Store pending registration in session
    session['pending_reg'] = {'username': username, 'email': email,
                               'mobile': mobile, 'password': password}
    session['pending_email'] = email
    session['otp_purpose']   = 'register'

    otp = generate_otp()
    db.store_otp(email, otp, 'register')
    send_otp(email, otp, 'register')
    flash('OTP sent to your email. Please verify to complete registration.', 'info')
    return redirect(url_for('verify_otp_page'))

@app.route('/auth/login', methods=['POST'])
def auth_login():
    email    = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    if not is_valid_email(email):
        flash('Please enter a valid email address.', 'danger')
        return redirect(url_for('login'))

    result = db.verify_user(email, password)
    if not result:
        flash('Invalid email or password. Please try again.', 'danger')
        db.log_audit(None, 'LOGIN_FAILED', email, 'Invalid credentials', get_ip())
        return redirect(url_for('login'))

    user_id, username, role = result
    # Store partially-authenticated state
    session['pending_user_id'] = user_id
    session['pending_email']   = email
    session['pending_username']= username
    session['pending_role']    = role
    session['otp_purpose']     = 'login'

    otp = generate_otp()
    db.store_otp(email, otp, 'login')
    send_otp(email, otp, 'login')
    flash('Credentials verified. Enter the OTP sent to your email.', 'info')
    return redirect(url_for('verify_otp_page'))

@app.route('/auth/verify-otp', methods=['POST'])
def auth_verify_otp():
    otp     = request.form.get('otp', '').strip()
    purpose = session.get('otp_purpose', 'login')
    email   = session.get('pending_email')

    if not email:
        flash('Session expired. Please start again.', 'danger')
        return redirect(url_for('login'))

    if not db.verify_otp(email, otp, purpose):
        flash('Invalid or expired OTP. Please try again.', 'danger')
        return redirect(url_for('verify_otp_page'))

    if purpose == 'register':
        reg = session.pop('pending_reg', {})
        if not reg:
            flash('Registration session expired.', 'danger')
            return redirect(url_for('register'))
        if not db.add_user(reg['username'], reg['email'], reg['password'],
                           reg.get('mobile', ''), silent=True):
            flash('Email already registered.', 'warning')
            return redirect(url_for('login'))
        db.log_audit(None, 'REGISTER', email, 'New user registered', get_ip())
        flash('Registration successful! You can now login.', 'success')
        session.pop('pending_email', None)
        session.pop('otp_purpose', None)
        return redirect(url_for('login'))

    # Login 2FA verified
    user_id  = session.pop('pending_user_id', None)
    username = session.pop('pending_username', None)
    role     = session.pop('pending_role', 'user')
    session.pop('pending_email', None)
    session.pop('otp_purpose', None)

    session.permanent = True
    session['user_id']     = user_id
    session['user']        = username
    session['email']       = email
    session['role']        = role
    session['otp_verified']= True

    db.log_audit(user_id, 'LOGIN', email, f'Login successful', get_ip())
    flash(f'Welcome back, {username}! 🔐', 'success')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('home'))

@app.route('/auth/resend-otp', methods=['POST'])
def resend_otp():
    email   = session.get('pending_email')
    purpose = session.get('otp_purpose', 'login')
    if not email:
        flash('Session expired.', 'danger')
        return redirect(url_for('login'))
    otp = generate_otp()
    db.store_otp(email, otp, purpose)
    send_otp(email, otp, purpose)
    flash('New OTP sent to your email.', 'info')
    return redirect(url_for('verify_otp_page'))

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    email   = session.get('email')
    db.log_audit(user_id, 'LOGOUT', email or '', '', get_ip())
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# ── User Dashboard ───────────────────────────────────────────────────────────
@app.route('/home')
@login_required
def home():
    user  = current_user()
    stats = db.get_user_stats(user['id'])
    stats['storage_human'] = human_size(stats['storage_bytes'])
    recent_evidence = db.get_evidence_by_user(user['id'])[:4]
    recent_logs     = db.get_audit_logs(user_id=user['id'], limit=5)
    return render_template('home.html', user=user, stats=stats,
                           recent_evidence=recent_evidence,
                           recent_logs=recent_logs)

# ── Upload ───────────────────────────────────────────────────────────────────
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    user   = current_user()
    cases  = db.get_cases(user['id'])

    if request.method == 'POST':
        evidence_type = request.form.get('evidence_type', 'anyfile')
        case_ref      = request.form.get('case_id', '').strip()
        title         = request.form.get('title', '').strip()
        description   = request.form.get('description', '').strip()
        category      = request.form.get('category', '')
        collected_at  = request.form.get('collected_at', '')
        location      = request.form.get('location', '')
        tags          = request.form.get('tags', '')
        priority      = request.form.get('priority', 'medium')
        text_note     = request.form.get('text_note', '').strip()
        enc_password  = request.form.get('enc_password', '').strip()
        sec_question  = request.form.get('security_question', '').strip()
        sec_answer    = request.form.get('security_answer', '').strip()

        if not enc_password or not sec_question or not sec_answer:
            flash('Encryption password and security question are required.', 'danger')
            return render_template('upload.html', user=user, cases=cases)

        saved_count = 0

        if evidence_type == 'text':
            if not text_note:
                flash('Please enter some text.', 'danger')
                return render_template('upload.html', user=user, cases=cases)

            # Save text as .txt
            evidence_id  = 'EV-' + str(uuid.uuid4())[:12].upper()
            safe_title   = re.sub(r'[^\w\-]', '_', title or 'note')
            note_fname   = f'{safe_title}_{evidence_id}.txt'
            raw_path     = os.path.join(UPLOADS_DIR, note_fname)
            with open(raw_path, 'w', encoding='utf-8') as f:
                f.write(f'Evidence ID: {evidence_id}\nCase: {case_ref}\nTitle: {title}\n'
                        f'Description: {description}\nCategory: {category}\n'
                        f'Collected: {collected_at}\nLocation: {location}\n'
                        f'Tags: {tags}\nPriority: {priority}\n\n--- Note ---\n{text_note}')

            sha256  = compute_sha256(raw_path)
            orig_sz = os.path.getsize(raw_path)
            enc_path = encrypt_evidence(raw_path, enc_password)
            stored  = os.path.basename(enc_path)

            db.add_evidence(user['id'], evidence_id, case_ref, note_fname, stored,
                            'text', orig_sz, sha256, title, description,
                            category, tags, priority, location, collected_at,
                            sec_question, sec_answer)
            db.log_audit(user['id'], 'UPLOAD', evidence_id, f'Text note: {note_fname}', get_ip())
            send_upload_notification(user['email'], user['username'], evidence_id, note_fname)
            saved_count = 1

        else:
            files = request.files.getlist('evidence_file')
            if not files or all(f.filename == '' for f in files):
                flash('Please select at least one file.', 'danger')
                return render_template('upload.html', user=user, cases=cases)

            for f in files:
                if not f or not f.filename:
                    continue
                ext = os.path.splitext(f.filename)[1].lower()
                if ext not in ALLOWED_TYPES:
                    flash(f'File type "{ext}" not allowed.', 'danger')
                    continue

                evidence_id = 'EV-' + str(uuid.uuid4())[:12].upper()
                safe_name   = re.sub(r'[^\w\-.]', '_', f.filename)
                raw_path    = os.path.join(UPLOADS_DIR, f'{evidence_id}_{safe_name}')
                f.save(raw_path)

                if os.path.getsize(raw_path) > MAX_FILE_SIZE:
                    os.remove(raw_path)
                    flash(f'File "{f.filename}" exceeds 500 MB limit.', 'danger')
                    continue

                sha256   = compute_sha256(raw_path)
                orig_sz  = os.path.getsize(raw_path)
                ftype    = classify_file(f.filename)
                enc_path = encrypt_evidence(raw_path, enc_password)
                stored   = os.path.basename(enc_path)

                db.add_evidence(user['id'], evidence_id, case_ref, f.filename, stored,
                                ftype, orig_sz, sha256, title, description,
                                category, tags, priority, location, collected_at,
                                sec_question, sec_answer)
                db.log_audit(user['id'], 'UPLOAD', evidence_id,
                             f'File: {f.filename} ({ftype})', get_ip())
                send_upload_notification(user['email'], user['username'], evidence_id, f.filename)
                saved_count += 1

        if saved_count:
            flash(f'✅ {saved_count} evidence item(s) uploaded, encrypted & secured!', 'success')
        return redirect(url_for('my_evidence'))

    return render_template('upload.html', user=user, cases=cases)

# ── My Evidence ──────────────────────────────────────────────────────────────
@app.route('/my-evidence')
@login_required
def my_evidence():
    user    = current_user()
    query   = request.args.get('q', '')
    ftype   = request.args.get('type', '')
    dfrom   = request.args.get('from', '')
    dto     = request.args.get('to', '')

    evidences = db.search_evidence(user['id'], query, ftype, dfrom, dto)

    EMOJI_MAP = {'image':'🖼️','video':'🎥','audio':'🎙️','doc':'📄','text':'✏️','file':'📎'}
    ev_list = []
    type_counts = {}
    for e in evidences:
        e = dict(e)
        e['emoji'] = EMOJI_MAP.get(e['file_type'], '📎')
        e['size_human'] = human_size(e['file_size'])
        e['short_hash'] = e['sha256_hash'][:16] + '…'
        
        # Map to template expectations
        e['type']          = e['file_type']
        e['filename']      = e['original_name']
        e['case_id']       = e['case_ref']
        e['modified_date'] = e['uploaded_at'][:10]
        try:
            # Try parsing timestamp for sorting
            dt_str = e['uploaded_at']
            if '.' in dt_str: dt_str = dt_str.split('.')[0]
            e['modified_ts'] = int(datetime.datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S').timestamp())
        except:
            e['modified_ts'] = 0

        type_counts[e['file_type']] = type_counts.get(e['file_type'], 0) + 1
        ev_list.append(e)

    # Check pending delete requests
    pending_del = {r['evidence_id'] for r in db.get_user_delete_requests(user['id'])
                   if r['status'] == 'pending'}
    return render_template('my_evidence.html', user=user, evidences=ev_list,
                           type_counts=type_counts, pending_deletes=pending_del,
                           query=query, filter_type=ftype, date_from=dfrom, date_to=dto)

# ── Serve / Download evidence (decrypts on-the-fly) ─────────────────────────
@app.route('/evidence/download/<evidence_id>')
@login_required
def download_evidence(evidence_id):
    user  = current_user()
    ev    = db.get_evidence_by_id(evidence_id)
    if not ev:
        abort(404)
    # Only owner or admin
    if ev['user_id'] != user['id'] and user['role'] != 'admin':
        abort(403)

    # Support password from session (temporary unlock)
    password = session.get(f'unlocked_{evidence_id}')
    if not password:
        flash('Authentication required to download evidence.', 'warning')
        return redirect(url_for('my_evidence'))

    enc_path = os.path.join(UPLOADS_DIR, ev['stored_filename'])
    if not os.path.exists(enc_path):
        abort(404)

    # Decrypt to temp
    tmp_name = ev['original_name']
    tmp_path = os.path.join(TEMP_DIR, f'{uuid.uuid4()}_{tmp_name}')
    try:
        decrypt_evidence(enc_path, tmp_path, password)
        db.log_audit(user['id'], 'DOWNLOAD', evidence_id,
                     f'Downloaded: {ev["original_name"]}', get_ip())
        response = send_from_directory(TEMP_DIR, os.path.basename(tmp_path),
                                       as_attachment=True,
                                       download_name=ev['original_name'])
        # Schedule temp file deletion
        def _cleanup(p):
            time.sleep(30)
            if os.path.exists(p):
                os.remove(p)
        threading.Thread(target=_cleanup, args=(tmp_path,), daemon=True).start()
        return response
    except Exception as e:
        flash(f'Download failed: Incorrect password or corrupted file.', 'danger')
        session.pop(f'unlocked_{evidence_id}', None) # Clear invalid password
        return redirect(url_for('my_evidence'))

# ── Evidence preview (inline) ─────────────────────────────────────────────────
@app.route('/evidence/preview/<evidence_id>')
@login_required
def preview_evidence(evidence_id):
    user = current_user()
    ev   = db.get_evidence_by_id(evidence_id)
    if not ev or (ev['user_id'] != user['id'] and user['role'] != 'admin'):
        abort(403)
        
    password = session.get(f'unlocked_{evidence_id}')
    if not password:
        return "Authentication required", 401

    enc_path = os.path.join(UPLOADS_DIR, ev['stored_filename'])
    if not os.path.exists(enc_path):
        abort(404)
    tmp_path = os.path.join(TEMP_DIR, f'{uuid.uuid4()}_{ev["original_name"]}')
    try:
        decrypt_evidence(enc_path, tmp_path, password)
        def _cleanup(p):
            time.sleep(60)
            if os.path.exists(p): os.remove(p)
        threading.Thread(target=_cleanup, args=(tmp_path,), daemon=True).start()
        return send_from_directory(TEMP_DIR, os.path.basename(tmp_path))
    except:
        return "Decryption failed", 500

# ── Security Verification AJAX ─────────────────────────────────────────────
@app.route('/evidence/verify-answer', methods=['POST'])
@login_required
def verify_security_answer_route():
    ev_id  = request.form.get('evidence_id')
    answer = request.form.get('answer', '').strip()
    print(f'[DEBUG] verify-answer route: ev_id={ev_id}, answer_received="{answer}"')
    
    is_locked, locked_until = db.is_evidence_locked(ev_id)
    if is_locked:
        return jsonify({'success': False, 'message': f'Locked until {locked_until}'}), 403
        
    if db.verify_security_answer(ev_id, answer):
        print(f'[DEBUG] verify-answer: SUCCESS for {ev_id}')
        return jsonify({'success': True})
    else:
        print(f'[DEBUG] verify-answer: FAILED for {ev_id}')
        db.record_failed_attempt(ev_id)
        is_locked, locked_until = db.is_evidence_locked(ev_id)
        msg = "Incorrect answer."
        if is_locked:
            msg = f"3/3 failed attempts. File is locked for 24h until {locked_until}."
        return jsonify({'success': False, 'message': msg}), 401

@app.route('/evidence/verify-password', methods=['POST'])
@login_required
def verify_evidence_password_route():
    ev_id = request.form.get('evidence_id')
    pwd   = request.form.get('password', '').strip()
    
    is_locked, locked_until = db.is_evidence_locked(ev_id)
    if is_locked:
        return jsonify({'success': False, 'message': f'Locked until {locked_until}'}), 403
        
    ev = db.get_evidence_by_id(ev_id)
    if not ev: return jsonify({'success': False, 'message': 'Not found'}), 404
    
    enc_path = os.path.join(UPLOADS_DIR, ev['stored_filename'])
    from encryption_util import validate_password
    if validate_password(enc_path, pwd):
        db.reset_failed_attempts(ev_id)
        session[f'unlocked_{ev_id}'] = pwd
        # Auto-lock after 10 minutes of inactivity? (Simplified for now)
        return jsonify({'success': True})
    else:
        db.record_failed_attempt(ev_id)
        is_locked, locked_until = db.is_evidence_locked(ev_id)
        msg = "Incorrect password."
        if is_locked:
            msg = f"3/3 failed attempts. File is locked for 24h until {locked_until}."
        return jsonify({'success': False, 'message': msg}), 401

@app.route('/evidence/check-lock/<evidence_id>')
@login_required
def check_lock(evidence_id):
    is_locked, locked_until = db.is_evidence_locked(evidence_id)
    ev = db.get_evidence_by_id(evidence_id)
    return jsonify({
        'is_locked': is_locked,
        'locked_until': locked_until,
        'question': ev['security_question'] if ev else None
    })

# ── Delete Request ────────────────────────────────────────────────────────────
@app.route('/evidence/request-delete', methods=['POST'])
@login_required
def request_delete():
    user        = current_user()
    evidence_id = request.form.get('evidence_id', '').strip()
    reason      = request.form.get('reason', '').strip()

    if not evidence_id or not reason:
        flash('Please provide a reason for deletion.', 'danger')
        return redirect(url_for('my_evidence'))

    ev = db.get_evidence_by_id(evidence_id)
    if not ev or ev['user_id'] != user['id']:
        flash('Evidence not found.', 'danger')
        return redirect(url_for('my_evidence'))

    if db.create_delete_request(evidence_id, user['id'], reason):
        db.log_audit(user['id'], 'DELETE_REQUEST', evidence_id, reason, get_ip())
        send_delete_request_admin_notification(ADMIN_EMAIL, user['username'], evidence_id, reason)
        flash('🗑️ Delete request submitted. Awaiting admin approval.', 'info')
    else:
        flash('A delete request is already pending for this evidence.', 'warning')
    return redirect(url_for('my_evidence'))

# ── Cases ─────────────────────────────────────────────────────────────────────
@app.route('/cases')
@login_required
def cases():
    user     = current_user()
    all_cases = db.get_cases(user['id'])
    return render_template('cases.html', user=user, cases=all_cases)

@app.route('/cases/create', methods=['POST'])
@login_required
def create_case():
    user = current_user()
    name = request.form.get('name', '').strip()
    desc = request.form.get('description', '').strip()
    if not name:
        flash('Case name is required.', 'danger')
        return redirect(url_for('cases'))
    case_id = db.create_case(user['id'], name, desc)
    if case_id:
        db.log_audit(user['id'], 'CREATE_CASE', case_id, name, get_ip())
        flash(f'✅ Case {case_id} created successfully!', 'success')
    else:
        flash('Failed to create case.', 'danger')
    return redirect(url_for('cases'))

# ── Recent Activity ───────────────────────────────────────────────────────────
@app.route('/recent-activity')
@login_required
def recent_activity():
    user = current_user()
    logs = db.get_audit_logs(user_id=user['id'], limit=100)
    return render_template('recent_activity.html', user=user, logs=logs)

# ── Search ────────────────────────────────────────────────────────────────────
@app.route('/search')
@login_required
def search():
    user  = current_user()
    query = request.args.get('q', '').strip()
    ftype = request.args.get('type', '')
    dfrom = request.args.get('from', '')
    dto   = request.args.get('to', '')
    results = db.search_evidence(user['id'], query, ftype, dfrom, dto)
    EMOJI_MAP = {'image':'🖼️','video':'🎥','audio':'🎙️','doc':'📄','text':'✏️','file':'📎'}
    ev_list = []
    for e in results:
        e = dict(e)
        e['emoji'] = EMOJI_MAP.get(e['file_type'], '📎')
        e['size_human'] = human_size(e['file_size'])
        e['short_hash'] = e['sha256_hash'][:16] + '…'
        ev_list.append(e)
    return render_template('search.html', user=user, results=ev_list,
                           query=query, filter_type=ftype, date_from=dfrom, date_to=dto)

# ── Settings ─────────────────────────────────────────────────────────────────
@app.route('/test-settings')
@login_required
def test_settings():
    """Test route to debug settings issue"""
    user = current_user()
    
    # Test database schema
    try:
        conn = db.get_conn()
        cur = conn.execute("PRAGMA table_info(delete_requests)")
        columns = cur.fetchall()
        conn.close()
        schema_info = "<br><br><h3>Delete Requests Table Schema:</h3><ul>"
        for col in columns:
            schema_info += f"<li>{col['name']} ({col['type']})</li>"
        schema_info += "</ul>"
    except Exception as e:
        schema_info = f"<br><br><h3>Database Schema Error:</h3><p>{e}</p>"
    
    return f"""
    <h1>Debug Info</h1>
    <p>Current User: {user}</p>
    <p>Session Role: {session.get('role')}</p>
    <p>User Role from current_user(): {user.get('role')}</p>
    <p>User ID: {user.get('id')}</p>
    <p>Username: {user.get('username')}</p>
    <p>Email: {user.get('email')}</p>
    {schema_info}
    <br><a href="/settings">Go to Settings</a>
    """

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    user         = current_user()
    
    # Debug: Print user info to check role
    print(f"[DEBUG] Settings route - User: {user}")
    print(f"[DEBUG] Session role: {session.get('role')}")
    print(f"[DEBUG] Session data: {dict(session)}")
    
    # Check if user is actually admin and redirect to admin settings
    if user.get('role') == 'admin':
        print("[DEBUG] Admin user accessing /settings, redirecting to admin settings")
        return redirect(url_for('admin_settings'))
    
    print(f"[DEBUG] Getting user details for user ID: {user.get('id')}")
    user_details = db.get_user_by_id(user['id'])
    print(f"[DEBUG] User details from DB: {user_details}")
    
    print(f"[DEBUG] Getting delete requests for user ID: {user.get('id')}")
    try:
        del_requests = db.get_user_delete_requests(user['id'])
        print(f"[DEBUG] Delete requests retrieved successfully: {len(del_requests)} items")
    except Exception as e:
        print(f"[DEBUG] ERROR getting delete requests: {e}")
        del_requests = []
    
    # Ensure user_details is not None
    if not user_details:
        print("[DEBUG] User details is None, creating fallback")
        user_details = {
            'username': user.get('username', 'Unknown'),
            'email': user.get('email', 'unknown@example.com'),
            'mobile': '',
            'role': user.get('role', 'user'),
            'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    # Ensure del_requests is not None
    if not del_requests:
        print("[DEBUG] Delete requests is None, setting to empty list")
        del_requests = []
    
    # Calculate pending OTP count for the notification badge
    pending_otp_count = sum(1 for r in del_requests if r['status'] == 'otp_pending')
    
    print(f"[DEBUG] Rendering user settings template with {len(del_requests)} delete requests and {pending_otp_count} pending OTPs")
    return render_template('settings.html', user=user, user_details=user_details,
                           del_requests=del_requests, pending_otp_count=pending_otp_count)

@app.route('/admin/settings', methods=['GET'])
@admin_required
def admin_settings():
    user         = current_user()
    user_details = db.get_user_by_id(user['id'])
    del_requests = db.get_user_delete_requests(user['id'])
    
    # Ensure user_details is not None
    if not user_details:
        user_details = {
            'username': user.get('username', 'Unknown'),
            'email': user.get('email', 'unknown@example.com'),
            'mobile': '',
            'role': user.get('role', 'admin'),
            'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    # Ensure del_requests is not None
    if not del_requests:
        del_requests = []
    
    return render_template('admin_settings.html', user=user, user_details=user_details,
                           del_requests=del_requests)

@app.route('/settings/update-profile', methods=['POST'])
@login_required
def update_profile():
    user     = current_user()
    username = request.form.get('username', '').strip()
    mobile   = request.form.get('mobile', '').strip()
    if not username:
        flash('Username cannot be empty.', 'danger')
        return redirect(url_for('settings'))
    if db.update_profile(user['id'], username, mobile):
        session['user'] = username
        db.log_audit(user['id'], 'UPDATE_PROFILE', '', 'Profile updated', get_ip())
        flash('✅ Profile updated successfully.', 'success')
    else:
        flash('Failed to update profile.', 'danger')
    return redirect(url_for('settings'))

@app.route('/settings/change-password', methods=['POST'])
@login_required
def change_password():
    user        = current_user()
    current_pwd = request.form.get('current_password', '')
    new_pwd     = request.form.get('new_password', '')
    confirm_pwd = request.form.get('confirm_password', '')

    if not current_pwd or not new_pwd or not confirm_pwd:
        flash('All password fields are required.', 'danger')
        return redirect(url_for('settings'))

    if new_pwd != confirm_pwd:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('settings'))

    if not db.verify_user(user['email'], current_pwd):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('settings'))

    if db.update_password(user['id'], new_pwd):
        db.log_audit(user['id'], 'PASSWORD_CHANGE', '', 'Password changed', get_ip())
        flash('✅ Password updated successfully.', 'success')
    else:
        flash('Failed to update password.', 'danger')
    return redirect(url_for('settings'))

@app.route('/verify-delete-otp/<int:req_id>', methods=['POST'])
@login_required
def verify_delete_otp(req_id):
    """Verify OTP for delete confirmation."""
    user = current_user()
    otp = request.form.get('otp', '').strip()

    if not otp:
        flash('OTP is required.', 'danger')
        return redirect(url_for('settings'))

    # Verify the OTP
    if db.verify_delete_confirmation_otp(req_id, otp):
        # OTP verified, now proceed with actual deletion
        stored_file = db.resolve_delete_request(req_id, True, 'OTP verified by user')
        if stored_file:
            db.log_audit(user['id'], 'DELETE_CONFIRMED', str(req_id), 
                        f'User confirmed deletion with OTP', get_ip())
            flash('✅ Evidence deleted successfully after OTP verification.', 'success')
        else:
            flash('Failed to delete evidence after OTP verification.', 'danger')
    else:
        db.log_audit(user['id'], 'OTP_FAILED_DELETE', str(req_id), 
                    f'Invalid OTP provided for delete confirmation', get_ip())
        flash('❌ Invalid OTP. Delete confirmation failed.', 'danger')

    return redirect(url_for('settings'))

# ── Admin Dashboard ───────────────────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_dashboard():
    user  = current_user()
    stats = db.get_admin_stats()
    return render_template('admin_dashboard.html', user=user, stats=stats,
                           all_users=db.get_all_users(),
                           all_evidence=db.get_all_evidence(),
                           delete_requests=db.get_delete_requests(),
                           audit_logs=db.get_audit_logs(limit=100),
                           all_otps=db.get_all_otps(limit=100))

@app.route('/admin/user/delete/<int:uid>', methods=['POST'])
@admin_required
def admin_delete_user(uid):
    user = current_user()
    if uid == user['id']:
        flash('You cannot delete your own admin account.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if db.delete_user(uid):
        db.log_audit(user['id'], 'DELETE_USER', str(uid), 'User permanently deleted', get_ip())
        flash('User permanently deleted.', 'success')
    else:
        flash('Failed to delete user.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/audit-logs/delete/<int:log_id>', methods=['POST'])
@admin_required
def admin_delete_log(log_id):
    if db.delete_audit_log(log_id):
        flash('Audit log entry removed.', 'success')
    else:
        flash('Failed to remove log entry.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/audit-logs/clear', methods=['POST'])
@admin_required
def admin_clear_logs():
    if db.clear_all_audit_logs():
        db.log_audit(session.get('user_id'), 'CLEAR_LOGS', 'ALL', 'Audit logs cleared by admin', get_ip())
        flash('All audit logs cleared.', 'warning')
    else:
        flash('Failed to clear audit logs.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/otps/delete/<int:otp_id>', methods=['POST'])
@admin_required
def admin_delete_otp(otp_id):
    if db.delete_otp(otp_id):
        flash('OTP record deleted.', 'success')
    else:
        flash('Failed to delete OTP record.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/otps/clear', methods=['POST'])
@admin_required
def admin_clear_otps():
    if db.clear_all_otps():
        db.log_audit(session.get('user_id'), 'CLEAR_OTPS', 'ALL', 'OTP store cleared by admin', get_ip())
        flash('All OTP records cleared.', 'warning')
    else:
        flash('Failed to clear OTP store.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/evidence/verify/<evidence_id>', methods=['POST'])
@admin_required
def admin_verify_evidence(evidence_id):
    user   = current_user()
    status = request.form.get('status', 'verified')
    ev     = db.get_evidence_by_id(evidence_id)
    if not ev:
        flash('Evidence not found.', 'danger')
    else:
        db.update_evidence_status(evidence_id, status)
        db.log_audit(user['id'], 'VERIFY_EVIDENCE', evidence_id, f'Status → {status}', get_ip())
        # Notify user
        owner = db.get_user_by_id(ev['user_id'])
        if owner:
            send_status_notification(owner['email'], owner['username'], evidence_id, status)
        flash(f'✅ Evidence {evidence_id} marked as {status}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/case/status/<case_id>', methods=['POST'])
@admin_required
def admin_update_case(case_id):
    user   = current_user()
    status = request.form.get('status', 'verified')
    db.update_case_status(case_id, status)
    db.log_audit(user['id'], 'UPDATE_CASE', case_id, f'Status → {status}', get_ip())
    flash(f'Case {case_id} updated to {status}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-request/<int:req_id>', methods=['POST'])
@admin_required
def admin_resolve_delete(req_id):
    user       = current_user()
    approved   = request.form.get('action') == 'approve'
    admin_note = request.form.get('note', '').strip()

    # Get request info before resolving - more robustly
    reqs = db.get_delete_requests()
    req  = next((r for r in reqs if str(r['id']) == str(req_id)), None)

    if not req:
        flash(f'Delete request #{req_id} not found.', 'danger')
        print(f"[DEBUG] Request {req_id} not found in {len(reqs)} requests")
        return redirect(url_for('admin_dashboard'))

    if approved:
        # Generate OTP and send to user for confirmation
        otp = generate_otp()
        print(f"[DEBUG] Generated OTP: {otp} for delete request {req_id}")
        
        if db.store_delete_confirmation_otp(req_id, otp):
            print(f"[DEBUG] OTP {otp} stored successfully in database for req {req_id}")
            owner = db.get_user_by_id(req['user_id'])
            
            if owner:
                print(f"[DEBUG] Owner found: {owner['username']} ({owner['email']})")
                try:
                    email_sent = send_delete_confirmation_otp(owner['email'], owner['username'], req['evidence_id'], otp)
                    print(f"[DEBUG] Email send result: {email_sent}")
                    
                    if email_sent:
                        # Update request status to 'otp_pending'
                        db.update_delete_request_status(req_id, 'otp_pending', admin_note)
                        db.log_audit(user['id'], 'OTP_SENT_DELETE', req['evidence_id'],
                                     f'Admin sent OTP for delete confirmation', get_ip())
                        flash('🔐 OTP sent to user for delete confirmation. Please check your Gmail!', 'info')
                        print(f"[DEBUG] Status updated to otp_pending and OTP sent via email.")
                    else:
                        print(f"[DEBUG] send_delete_confirmation_otp returned False")
                        flash('Failed to send OTP email. Please check SMTP settings.', 'danger')
                except Exception as e:
                    print(f"[DEBUG] Exception during email send: {e}")
                    flash(f'Error sending email: {e}', 'danger')
            else:
                print(f"[DEBUG] Owner not found for user_id {req['user_id']}")
                flash('User owner not found.', 'danger')
        else:
            print(f"[DEBUG] Failed to store OTP in database")
            flash('Failed to generate OTP and store in database.', 'danger')
    else:
        # Reject the request
        print(f"[DEBUG] Admin rejecting delete request {req_id}")
        db.resolve_delete_request(req_id, False, admin_note)
        # Get owner info for notification
        owner = db.get_user_by_id(req['user_id'])
        if req and owner:
            send_delete_request_status(owner['email'], owner['username'],
                                       req['evidence_id'], False)
        db.log_audit(user['id'], 'REJECT_DELETE', '',
                     f'Admin rejected delete request #{req_id}', get_ip())
        flash('Delete request rejected.', 'info')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/toggle/<int:uid>', methods=['POST'])
@admin_required
def admin_toggle_user(uid):
    user = current_user()
    db.toggle_user_active(uid)
    db.log_audit(user['id'], 'TOGGLE_USER', str(uid), 'Active status toggled', get_ip())
    flash('User status updated.', 'success')
    return redirect(url_for('admin_dashboard'))

# ── Legacy static file route ───────────────────────────────────────────────────
@app.route('/uploads/<path:filename>')
@login_required
def serve_upload(filename):
    # This is a fallback for legacy template code using url_for('serve_upload')
    # Better to use download_evidence or preview_evidence
    return send_from_directory(UPLOADS_DIR, filename)

@app.route('/evidence/delete-legacy/<path:filename>')
@login_required
def delete_evidence(filename):
    # Fallback to catch delete button clicks in templates
    flash('Please use the Delete Request system to remove evidence.', 'warning')
    return redirect(url_for('my_evidence'))

# ── Run ────────────────────────────────────────────────────────────────────────
def open_browser():
    time.sleep(1.5)
    import webbrowser
    webbrowser.open('http://localhost:5001')

if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        threading.Thread(target=open_browser, daemon=True).start()
    app.run(debug=True, host='0.0.0.0', port=5001, use_reloader=True)
