"""Main Flask application for 请输入文本 magazine submission system."""
import os
import json
import secrets
import hashlib
import hmac
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, send_file, g, abort
from flask_cors import CORS
from database import get_db, init_db, hash_password, verify_password, is_legacy_password, migrate_password, check_password_strength

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = secrets.token_hex(32)

# ─── Request logging (superadmins only) ───
LOG_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(LOG_DIR, exist_ok=True)
request_logger = logging.getLogger('request_log')
request_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(os.path.join(LOG_DIR, 'requests.log'))
_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
request_logger.addHandler(_handler)

@app.before_request
def log_request():
    if request.path.startswith('/api/') and request.path != '/api/submit-status':
        ip = request.remote_addr
        method = request.method
        path = request.path
        username = '-'
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if token:
            try:
                db = get_db()
                row = db.execute(
                    "SELECT u.username FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=?",
                    (token,)
                ).fetchone()
                if row:
                    username = row['username']
                db.close()
            except Exception:
                pass
        request_logger.info(f'{ip} {username} {method} {path}')

# ─── Signed URL for uploads ───
UPLOAD_SECRET = app.secret_key[:32]

def make_signed_url(filename, expires_in=3600):
    exp = int(time.time()) + expires_in
    sig = hmac.new(UPLOAD_SECRET.encode(), f'{filename}:{exp}'.encode(), hashlib.sha256).hexdigest()[:16]
    return f'/uploads/{filename}?exp={exp}&sig={sig}'

def verify_signed_url(filename, exp, sig):
    if int(time.time()) > int(exp):
        return False
    expected = hmac.new(UPLOAD_SECRET.encode(), f'{filename}:{exp}'.encode(), hashlib.sha256).hexdigest()[:16]
    return hmac.compare_digest(sig, expected)

CORS(app, origins=['https://open.lladlam.top'])

# ─── Rate limiter (in-memory) ───
_login_attempts = defaultdict(list)
RATE_LIMIT = 5
RATE_WINDOW = 300  # 5 minutes

def is_rate_limited(ip):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < RATE_WINDOW]
    if len(_login_attempts[ip]) >= RATE_LIMIT:
        return True
    _login_attempts[ip].append(now)
    return False

# ─── Security headers ───
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.loli.net; font-src https://fonts.loli.net; img-src 'self' data: blob:; connect-src 'self'"
    return resp

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

ALLOWED_EXTENSIONS = {
    '笔哩笔哩': {'.doc', '.docx', '.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.zip', '.rar', '.7z'},
    '笔上不足': {'.doc', '.docx', '.txt', '.pdf', '.zip', '.rar', '.7z'},
    '笔下有娱': {'.doc', '.docx', '.txt', '.pdf', '.zip', '.rar', '.7z'},
    '给我刊刊': {'.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.zip', '.rar', '.7z'},
    '评评无奇': {'.doc', '.docx', '.txt', '.pdf', '.zip', '.rar', '.7z'},
    '字由字在': {'.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.zip', '.rar', '.7z'},
    '被诗咬了': {'.doc', '.docx', '.txt', '.pdf', '.zip', '.rar', '.7z'},
    '诗不打烊': {'.doc', '.docx', '.txt', '.pdf', '.zip', '.rar', '.7z'},
}

def validate_upload(f, category):
    if not f or not f.filename:
        return True, ''
    ext = os.path.splitext(f.filename)[1].lower()
    allowed = ALLOWED_EXTENSIONS.get(category)
    if allowed and ext not in allowed:
        return False, f'不支持的文件格式 {ext}，允许: {", ".join(sorted(allowed))}'
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > MAX_FILE_SIZE:
        return False, f'文件大小 {size // 1024 // 1024}MB 超过 10MB 限制'
    return True, ''

# ─── Auth helpers ───

def get_current_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT u.* FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires_at>datetime('now')",
        (token,)
    ).fetchone()
    db.close()
    return dict(row) if row else None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': '请先登录'}), 401
        if user['banned']:
            return jsonify({'error': '账号已被封禁'}), 403
        g.user = user
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if g.user['role'] not in roles:
                return jsonify({'error': '权限不足'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─── Logs (superadmins) ───

@app.route('/api/logs', methods=['GET'])
@role_required('superadmins')
def get_logs():
    log_path = os.path.join(LOG_DIR, 'requests.log')
    if not os.path.exists(log_path):
        return jsonify({'logs': ''})
    with open(log_path, 'r') as f:
        lines = f.readlines()
    limit = min(int(request.args.get('limit', '200')), 1000)
    return jsonify({'logs': ''.join(lines[-limit:])})

# ─── Auth routes ───

@app.route('/api/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if is_rate_limited(ip):
        return jsonify({'error': '登录尝试过于频繁，请5分钟后重试'}), 429
    data = request.json
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (data.get('username', ''),)).fetchone()
    if not user or not verify_password(user['password'], data.get('password', '')):
        db.close()
        return jsonify({'error': '用户名或密码错误'}), 401
    if user['banned']:
        db.close()
        return jsonify({'error': '账号已被封禁'}), 403
    token = secrets.token_hex(32)
    if is_legacy_password(user["password"]):
        migrate_password(db, user["id"], data.get("password", ""))
    db.execute("INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))",
               (user['id'], token))
    db.commit()
    db.close()
    return jsonify({'token': token, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    if len(username) < 2 or len(username) > 20:
        return jsonify({'error': '用户名长度2-20字符'}), 400
    ok, msg = check_password_strength(password)
    if not ok:
        return jsonify({'error': msg}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        db.close()
        return jsonify({'error': '注册失败'}), 409
    pwd = hash_password(password)
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'users')", (username, pwd))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    token = secrets.token_hex(32)
    if is_legacy_password(user["password"]):
        migrate_password(db, user["id"], data.get("password", ""))
    db.execute("INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))",
               (user['id'], token))
    db.commit()
    db.close()
    return jsonify({'token': token, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

@app.route('/api/me', methods=['GET'])
@login_required
def me():
    return jsonify({'id': g.user['id'], 'username': g.user['username'], 'role': g.user['role'], 'avatar': g.user['avatar']})

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token=?", (token,))
    db.commit()
    db.close()
    return jsonify({'ok': True})

@app.route('/api/logout-all', methods=['POST'])
@login_required
def logout_all():
    db = get_db()
    db.execute("DELETE FROM sessions WHERE user_id=?", (g.user['id'],))
    db.commit()
    db.close()
    return jsonify({'ok': True})

# ─── Settings (public) ───

@app.route('/api/submit-status', methods=['GET'])
def submit_status():
    db = get_db()
    s = {r['key']: r['value'] for r in db.execute("SELECT key, value FROM settings").fetchall()}
    db.close()
    open_setting = s.get('submit_open', '1')
    start = s.get('submit_start', '')
    end = s.get('submit_end', '')
    is_open = False
    if open_setting == '1':
        if start and end:
            now = datetime.now().isoformat()
            is_open = start <= now <= end
        else:
            # No time range set, open setting is the authority
            is_open = True
    return jsonify({'open': is_open, 'start': start, 'end': end})

# ─── Submissions (users) ───

@app.route('/api/submissions', methods=['GET'])
@login_required
def my_submissions():
    db = get_db()
    rows = db.execute(
        "SELECT id, category, title, status, submitted_at, last_edited_at FROM submissions WHERE user_id=? ORDER BY submitted_at DESC",
        (g.user['id'],)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/submissions', methods=['POST'])
@login_required
def create_submission():
    db = get_db()
    # Check open status
    s = {r['key']: r['value'] for r in db.execute("SELECT key, value FROM settings").fetchall()}
    open_setting = s.get('submit_open', '1')
    start, end = s.get('submit_start', ''), s.get('submit_end', '')
    if open_setting != '1':
        db.close()
        return jsonify({'error': '投稿通道暂未开放'}), 403
    if start and end:
        now = datetime.now().isoformat()
        if not (start <= now <= end):
            db.close()
            return jsonify({'error': '不在投稿时间范围内'}), 403

    wait_enabled = s.get('wait_period_enabled', '1') == '1'

    # Handle form data
    category = request.form.get('category', '')
    title = request.form.get('title', '').strip()
    author_name = request.form.get('author_name', '').strip()
    contact = request.form.get('contact', '').strip()
    author_bio = request.form.get('author_bio', '')
    content = request.form.get('content', '')
    synopsis = request.form.get('synopsis', '')
    creation_note = request.form.get('creation_note', '')

    if not category or not title or not author_name or not contact:
        db.close()
        return jsonify({'error': '请填写必填项'}), 400

    # Handle file upload
    file_path = ''
    if 'file' in request.files:
        f = request.files['file']
        if f.filename:
            ok, msg = validate_upload(f, category)
            if not ok:
                db.close()
                return jsonify({'error': msg}), 400
            ext = os.path.splitext(f.filename)[1]
            fname = f"{g.user['id']}_{int(datetime.now().timestamp())}{ext}"
            fpath = os.path.join(UPLOAD_DIR, fname)
            f.save(fpath)
            file_path = fname

    lock_time = "datetime('now', '+30 minutes')" if wait_enabled else "NULL"
    status_val = 'reviewing' if wait_enabled else 'pending'

    db.execute(f'''INSERT INTO submissions
        (user_id, category, title, author_name, contact, author_bio, content, synopsis, creation_note, file_path, status, edit_locked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, {lock_time})''',
        (g.user['id'], category, title, author_name, contact, author_bio, content, synopsis, creation_note, file_path, status_val))
    db.commit()
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.close()
    if wait_enabled:
        return jsonify({'id': sub_id, 'message': '投稿成功，30分钟内可修改（审核者暂不可见）'})
    return jsonify({'id': sub_id, 'message': '投稿成功'})

@app.route('/api/submissions/<int:sub_id>', methods=['GET'])
@login_required
def get_submission(sub_id):
    db = get_db()
    row = db.execute("SELECT * FROM submissions WHERE id=? AND user_id=?", (sub_id, g.user['id'])).fetchone()
    db.close()
    if not row:
        return jsonify({'error': '稿件不存在'}), 404
    r = dict(row)
    r['can_edit'] = r['edit_locked_at'] and datetime.now().isoformat() < r['edit_locked_at']
    r['file_url'] = make_signed_url(r['file_path']) if r['file_path'] else ''
    # Hide review info during waiting period OR during post-review revocation window
    in_revocation = r['edit_locked_at'] and datetime.now().isoformat() < r['edit_locked_at']
    if r['status'] == 'reviewing' or (r['status'] in ('passed', 'failed') and in_revocation):
        r['status'] = 'pending'
        r['review_reason'] = ''
        r['reviewed_by'] = None
        r['reviewed_at'] = None
    return jsonify(r)

@app.route('/api/submissions/<int:sub_id>', methods=['PUT'])
@login_required
def edit_submission(sub_id):
    db = get_db()
    row = db.execute("SELECT * FROM submissions WHERE id=? AND user_id=?", (sub_id, g.user['id'])).fetchone()
    if not row:
        db.close()
        return jsonify({'error': '稿件不存在'}), 404
    if not row['edit_locked_at'] or datetime.now().isoformat() >= row['edit_locked_at']:
        db.close()
        return jsonify({'error': '已过30分钟修改期，无法修改'}), 403

    title = request.form.get('title', row['title']).strip()
    author_name = request.form.get('author_name', row['author_name']).strip()
    contact = request.form.get('contact', row['contact']).strip()
    author_bio = request.form.get('author_bio', row['author_bio'])
    content = request.form.get('content', row['content'])
    synopsis = request.form.get('synopsis', row['synopsis'])
    creation_note = request.form.get('creation_note', row['creation_note'])

    file_path = row['file_path']
    if 'file' in request.files:
        f = request.files['file']
        if f.filename:
            ok, msg = validate_upload(f, row['category'])
            if not ok:
                db.close()
                return jsonify({'error': msg}), 400
            # Delete old file
            if file_path:
                old = os.path.join(UPLOAD_DIR, file_path)
                if os.path.exists(old):
                    os.remove(old)
            ext = os.path.splitext(f.filename)[1]
            fname = f"{g.user['id']}_{int(datetime.now().timestamp())}{ext}"
            fpath = os.path.join(UPLOAD_DIR, fname)
            f.save(fpath)
            file_path = fname

    db.execute('''UPDATE submissions SET title=?, author_name=?, contact=?, author_bio=?,
        content=?, synopsis=?, creation_note=?, file_path=?, last_edited_at=CURRENT_TIMESTAMP,
        edit_locked_at=datetime('now', '+30 minutes'), status='pending', review_reason='' WHERE id=?''',
        (title, author_name, contact, author_bio, content, synopsis, creation_note, file_path, sub_id))
    db.commit()
    db.close()
    return jsonify({'message': '修改成功，重新进入30分钟等待期'})

# ─── Review (admins & superadmins) ───

@app.route('/api/review/list', methods=['GET'])
@role_required('superadmins', 'admins')
def review_list():
    sort = request.args.get('sort', 'time')  # time or category
    status = request.args.get('status', 'all')
    db = get_db()
    # Hide submissions still within waiting period
    query = "SELECT s.id, s.title, s.category, CASE WHEN s.status='reviewing' AND s.edit_locked_at <= datetime('now') THEN 'pending' ELSE s.status END as status, s.submitted_at, u.username FROM submissions s JOIN users u ON s.user_id=u.id WHERE NOT (s.status = 'reviewing' AND s.edit_locked_at > datetime('now'))"
    params = []
    conditions = []
    if status != 'all':
        if status == 'pending':
            conditions.append("(s.status=? OR (s.status='reviewing' AND s.edit_locked_at <= datetime('now')))")
            params.append(status)
        else:
            conditions.append("s.status=?")
            params.append(status)
    if conditions:
        query += " AND " + " AND ".join(conditions)
    if sort == 'category':
        query += " ORDER BY s.category, s.submitted_at DESC"
    else:
        query += " ORDER BY s.submitted_at DESC"
    rows = db.execute(query, params).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/review/<int:sub_id>', methods=['GET'])
@role_required('superadmins', 'admins')
def review_detail(sub_id):
    db = get_db()
    row = db.execute(
        "SELECT s.*, u.username FROM submissions s JOIN users u ON s.user_id=u.id WHERE s.id=?",
        (sub_id,)
    ).fetchone()
    db.close()
    if not row:
        return jsonify({'error': '稿件不存在'}), 404
    r = dict(row)
    r['file_url'] = make_signed_url(r['file_path']) if r['file_path'] else ''
    return jsonify(r)

@app.route('/api/review/<int:sub_id>', methods=['POST'])
@role_required('superadmins', 'admins')
def review_action(sub_id):
    data = request.json
    action = data.get('action')  # 'pass' or 'fail'
    reason = data.get('reason', '').strip()
    if action not in ('pass', 'fail'):
        return jsonify({'error': '无效操作'}), 400
    if not reason:
        return jsonify({'error': '请填写原因'}), 400

    db = get_db()
    row = db.execute("SELECT * FROM submissions WHERE id=?", (sub_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': '稿件不存在'}), 404

    status = 'passed' if action == 'pass' else 'failed'
    db.execute('''UPDATE submissions SET status=?, review_reason=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP,
        edit_locked_at=datetime('now', '+30 minutes') WHERE id=?''',
        (status, reason, g.user['id'], sub_id))
    db.commit()
    db.close()
    return jsonify({'message': f'已{"通过" if action=="pass" else "不通过"}，30分钟内可更改'})

@app.route('/api/review/<int:sub_id>/revoke', methods=['POST'])
@role_required('superadmins', 'admins')
def review_revoke(sub_id):
    db = get_db()
    row = db.execute("SELECT * FROM submissions WHERE id=?", (sub_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': '稿件不存在'}), 404
    s = {r['key']: r['value'] for r in db.execute("SELECT key, value FROM settings").fetchall()}
    if s.get('wait_period_enabled', '1') == '1':
        if not row['edit_locked_at'] or datetime.now().isoformat() >= row['edit_locked_at']:
            db.close()
            return jsonify({'error': '已过30分钟，无法撤回'}), 403

    db.execute("UPDATE submissions SET status='reviewing', review_reason='', reviewed_by=NULL, reviewed_at=NULL WHERE id=?", (sub_id,))
    db.commit()
    db.close()
    return jsonify({'message': '已撤回审核结果'})

@app.route('/api/review/download', methods=['GET'])
@role_required('superadmins', 'admins')
def review_download():
    """Download all submissions as CSV + files as zip."""
    import csv, io, zipfile
    sort = request.args.get('sort', 'time')
    status = request.args.get('status', 'all')
    db = get_db()
    query = "SELECT s.*, CASE WHEN s.status='reviewing' AND s.edit_locked_at <= datetime('now') THEN 'pending' ELSE s.status END as display_status, u.username FROM submissions s JOIN users u ON s.user_id=u.id WHERE NOT (s.status = 'reviewing' AND s.edit_locked_at > datetime('now'))"
    params = []
    if status != 'all':
        query += " AND s.status=?"
        params.append(status)
    if sort == 'category':
        query += " ORDER BY s.category, s.submitted_at DESC"
    else:
        query += " ORDER BY s.submitted_at DESC"
    rows = db.execute(query, params).fetchall()
    db.close()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # CSV summary
        csv_buf = io.StringIO()
        writer = csv.writer(csv_buf)
        writer.writerow(['作品名', '类型', '投稿人', '联系方式', '提交时间', '状态', '审核原因'])
        for r in rows:
            writer.writerow([
                r['title'], r['category'], r['author_name'], r['contact'],
                r['submitted_at'], r['display_status'], r['review_reason'] or ''
            ])
        zf.writestr('稿件汇总.csv', csv_buf.getvalue().encode('utf-8-sig'))

        # Individual text files + attachments
        for r in rows:
            safe_title = r['title'].replace('/', '_').replace('\\', '_')[:30]
            prefix = f"{safe_title}_{r['username']}"
            # Text detail
            text = f"""作品名: {r['title']}
类型: {r['category']}
投稿人: {r['author_name']}
联系方式: {r['contact']}
作者简介: {r['author_bio'] or ''}
提交时间: {r['submitted_at']}
状态: {r['status']}
审核原因: {r['review_reason'] or ''}

--- 作品内容 ---
{r['content'] or ''}

--- 作品梗概 ---
{r['synopsis'] or ''}

--- 创作思路 ---
{r['creation_note'] or ''}
"""
            zf.writestr(f"{prefix}/详情.txt", text.encode('utf-8'))
            # Attachment
            if r['file_path']:
                fpath = os.path.join(UPLOAD_DIR, r['file_path'])
                if os.path.exists(fpath):
                    ext = os.path.splitext(r['file_path'])[1]
                    zf.write(fpath, f"{prefix}/附件{ext}")

    buf.seek(0)
    return send_file(buf, mimetype='application/zip', as_attachment=True, download_name='稿件导出.zip')

@app.route('/api/review/download/<int:sub_id>', methods=['GET'])
@role_required('superadmins', 'admins')
def review_download_single(sub_id):
    """Download single submission as zip."""
    import io, zipfile
    db = get_db()
    r = db.execute("SELECT s.*, u.username FROM submissions s JOIN users u ON s.user_id=u.id WHERE s.id=?", (sub_id,)).fetchone()
    db.close()
    if not r:
        return jsonify({'error': '稿件不存在'}), 404

    safe_title = r['title'].replace('/', '_').replace('\\', '_')[:30]
    prefix = f"{safe_title}_{r['username']}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        text = f"""作品名: {r['title']}
类型: {r['category']}
投稿人: {r['author_name']}
联系方式: {r['contact']}
作者简介: {r['author_bio'] or ''}
提交时间: {r['submitted_at']}
状态: {r['status']}
审核原因: {r['review_reason'] or ''}

--- 作品内容 ---
{r['content'] or ''}

--- 作品梗概 ---
{r['synopsis'] or ''}

--- 创作思路 ---
{r['creation_note'] or ''}
"""
        zf.writestr(f"{prefix}/详情.txt", text.encode('utf-8'))
        if r['file_path']:
            fpath = os.path.join(UPLOAD_DIR, r['file_path'])
            if os.path.exists(fpath):
                ext = os.path.splitext(r['file_path'])[1]
                zf.write(fpath, f"{prefix}/附件{ext}")

    buf.seek(0)
    return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=f'{safe_title}.zip')

# ─── User management (superadmins) ───

@app.route('/api/users', methods=['GET'])
@role_required('superadmins')
def list_users():
    db = get_db()
    rows = db.execute("SELECT id, username, role, banned, created_at FROM users ORDER BY created_at").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@role_required('superadmins')
def create_user():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'users')
    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    if role not in ('superadmins', 'admins', 'users'):
        return jsonify({'error': '无效角色'}), 400
    db = get_db()
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        db.close()
        return jsonify({'error': '用户名已存在'}), 409
    db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               (username, hash_password(password), role))
    db.commit()
    db.close()
    return jsonify({'message': '用户创建成功'})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@role_required('superadmins')
def update_user(user_id):
    data = request.json
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': '用户不存在'}), 404

    # Prevent removing last superadmin
    if user['role'] == 'superadmins' and data.get('role') and data['role'] != 'superadmins':
        count = db.execute("SELECT COUNT(*) as c FROM users WHERE role='superadmins'").fetchone()['c']
        if count <= 1:
            db.close()
            return jsonify({'error': '至少保留一个superadmin'}), 400

    if data.get('password'):
        db.execute("UPDATE users SET password=? WHERE id=?", (hash_password(data['password']), user_id))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    if data.get('role'):
        db.execute("UPDATE users SET role=? WHERE id=?", (data['role'], user_id))
    if 'banned' in data:
        db.execute("UPDATE users SET banned=? WHERE id=?", (1 if data['banned'] else 0, user_id))
    db.commit()
    db.close()
    return jsonify({'message': '更新成功'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@role_required('superadmins')
def delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': '用户不存在'}), 404
    if user['role'] == 'superadmins':
        count = db.execute("SELECT COUNT(*) as c FROM users WHERE role='superadmins'").fetchone()['c']
        if count <= 1:
            db.close()
            return jsonify({'error': '不能删除最后一个superadmin'}), 400
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    db.close()
    return jsonify({'message': '用户已删除'})

@app.route('/api/users/<int:user_id>/submissions', methods=['GET'])
@role_required('superadmins')
def user_submissions(user_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, category, title, status, submitted_at FROM submissions WHERE user_id=? ORDER BY submitted_at DESC",
        (user_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users/<int:user_id>/reviews', methods=['GET'])
@role_required('superadmins', 'admins')
def user_reviews(user_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, title, category, status, review_reason, reviewed_at FROM submissions WHERE reviewed_by=? ORDER BY reviewed_at DESC",
        (user_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

# ─── Settings (self) ───

@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    db = get_db()
    s = {r['key']: r['value'] for r in db.execute("SELECT key, value FROM settings").fetchall()}
    db.close()
    result = {'username': g.user['username'], 'avatar': g.user['avatar']}
    if g.user['role'] == 'superadmins':
        result['submit_open'] = s.get('submit_open', '1')
        result['submit_start'] = s.get('submit_start', '')
        result['submit_end'] = s.get('submit_end', '')
        result['wait_period_enabled'] = s.get('wait_period_enabled', '1')
    return jsonify(result)

@app.route('/api/settings', methods=['PUT'])
@login_required
def update_settings():
    data = request.json
    db = get_db()
    if data.get('username'):
        existing = db.execute("SELECT id FROM users WHERE username=? AND id!=?", (data['username'], g.user['id'])).fetchone()
        if existing:
            db.close()
            return jsonify({'error': '用户名已存在'}), 409
        db.execute("UPDATE users SET username=? WHERE id=?", (data['username'], g.user['id']))
    if data.get('password'):
        # Verify old password first
        old_pwd = data.get('old_password', '')
        if not old_pwd:
            db.close()
            return jsonify({'error': '请输入旧密码'}), 400
        user = db.execute("SELECT password FROM users WHERE id=?", (g.user['id'],)).fetchone()
        if not verify_password(user['password'], old_pwd):
            db.close()
            return jsonify({'error': '旧密码错误'}), 400
        ok, msg = check_password_strength(data['password'])
        if not ok:
            db.close()
            return jsonify({'error': msg}), 400
        db.execute("UPDATE users SET password=? WHERE id=?", (hash_password(data['password']), g.user['id']))
        db.execute("DELETE FROM sessions WHERE user_id=?", (g.user["id"],))
    if data.get('avatar') is not None:
        db.execute("UPDATE users SET avatar=? WHERE id=?", (data['avatar'], g.user['id']))

    # Admin settings
    if g.user['role'] == 'superadmins':
        for key in ('submit_open', 'submit_start', 'submit_end', 'wait_period_enabled'):
            if key in data:
                db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(data[key])))

    db.commit()
    db.close()
    return jsonify({'message': '设置已更新'})

# ─── Static files ───

@app.route('/admin')
def admin_page():
    resp = send_file('admin.html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    exp = request.args.get('exp', '')
    sig = request.args.get('sig', '')
    if not exp or not sig or not verify_signed_url(filename, exp, sig):
        abort(403)
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/')
def index():
    resp = send_file('index.html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp

# ─── Init & run ───

init_db()

# Create sessions table
with get_db() as conn:
    conn.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    # Clean up expired sessions on startup
    conn.execute("DELETE FROM sessions WHERE expires_at <= datetime('now')")
    conn.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7675, debug=False)
