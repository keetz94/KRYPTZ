from __future__ import annotations
import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import random
import uuid
from collections import defaultdict
from cryptography.fernet import Fernet
import hashlib
import time
from pathlib import Path
import secrets

user_last_warning_time = {}
user_last_message_time = {}
user_fps = defaultdict(set)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(48)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////root/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
ARCHIVE_FOLDER = 'static/archives'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

for folder in [UPLOAD_FOLDER, ARCHIVE_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

room_members = defaultdict(dict)
user_sids = defaultdict(set)

def _load_or_create_fernet_key(path: str) -> str:
    p = Path(path)
    if p.exists():
        return p.read_text(encoding="utf-8").strip()

    key = Fernet.generate_key().decode("utf-8")
    p.write_text(key, encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass
    return key

def get_cipher_suite() -> Fernet:
    raw_key = os.environ.get("CHAT_SECRET_KEY")
    if raw_key:
        return Fernet(raw_key.encode("utf-8"))

    key_file = os.environ.get("CHAT_SECRET_KEY_FILE", "chat_secret.key")
    key = _load_or_create_fernet_key(key_file)
    return Fernet(key.encode("utf-8"))

cipher_suite = get_cipher_suite()


def generate_captcha():
    n1 = random.randint(1, 9)
    n2 = random.randint(1, 9)
    session['captcha_res'] = n1 + n2
    return n1, n2

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def archive_and_delete_room_messages(room_id: int):

    try:
        msgs = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp).all()
        if not msgs: return

        # Dosya adı oluştur
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"room_{room_id}_archive_{timestamp}.txt"
        filepath = os.path.join(ARCHIVE_FOLDER, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"--- ARCHIVE ROOM ID: {room_id} | DATE: {timestamp} ---\n\n")
            for m in msgs:
                # Mesajı çöz
                try: content = cipher_suite.decrypt(m.content.encode('utf-8')).decode()
                except: content = "[ENCRYPTED/ERROR]"
                
                img_info = f"[IMAGE: {m.image}]" if m.image else ""
                line = f"[{m.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {m.username}: {content} {img_info}\n"
                f.write(line)

        for m in msgs: 
            db.session.delete(m)
        db.session.commit()
        return filename
    except Exception as e:
        print(f"Archive Error: {e}")
        return None

def archive_and_delete_channel(room_id: int):
    try:
        Message.query.filter_by(room_id=room_id).delete()
        ChatRoom.query.filter_by(id=room_id).delete()
        db.session.commit()
    except: pass

def enforce_not_banned():
    if not current_user.is_authenticated:
        return False
    u = User.query.get(current_user.id)
    if u and u.is_banned:
        emit('banned', {'msg': f'BANNED: {u.ban_reason or ""}'.strip()}, to=request.sid)
        disconnect() 
        return False
    return True

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(255), nullable=True)
    avatar = db.Column(db.String(255), default="https://api.dicebear.com/9.x/bottts-neutral/svg?seed=default")

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    topic = db.Column(db.Text, default="KRYPTZ hiçbir zaman %100 gizlilik garantisi vermez.")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(50))
    content = db.Column(db.Text)
    image = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class BannedFingerprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fp_hash = db.Column(db.String(64), unique=True, nullable=False)
    reason = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def get_fingerprint_hash(): 
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    ua = request.headers.get("User-Agent", "")
    raw = f"{ip}|{ua}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from flask_login import logout_user

@app.before_request
def kick_banned_on_http():
    if current_user.is_authenticated:
        u = User.query.get(current_user.id)
        if u and u.is_banned:
            logout_user()
            return redirect(url_for('login'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('rooms'))
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        captcha_input = request.form.get('captcha', '')
        
        real_captcha = session.get('captcha_res')
        if not real_captcha or str(real_captcha) != captcha_input:
            flash("Wrong Math Answer", "error")
            n1, n2 = generate_captcha()
            return render_template('login.html', c1=n1, c2=n2)

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.is_banned: flash(f"Banned: {user.ban_reason}", "error")
            elif not user.is_approved: flash("Wait For Approval", "error")
            else:
                login_user(user)
                user_fps[user.id].add(get_fingerprint_hash())
                return redirect(url_for('rooms'))
        else: flash("Login Failed", "error")
            
    n1, n2 = generate_captcha()
    return render_template('login.html', c1=n1, c2=n2)

@app.route('/register', methods=['GET', 'POST'])
def register():
        fp = get_fingerprint_hash()
        banrow = BannedFingerprint.query.filter_by(fp_hash=fp).first() if fp else None
        if banrow:
            flash(f"This device/IP banned: {banrow.reason or 'BANNED'}", "error")
            return redirect(url_for('login'))
    
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            captcha_input = request.form.get('captcha', '').strip()
            real_captcha = session.get('captcha_res')
            if not real_captcha or str(real_captcha) != captcha_input:
                flash("Wrong Math Answer", "error")
                n1, n2 = generate_captcha()
                return render_template('register.html', c1=n1, c2=n2)
    
            if not username or not password:
                flash("Username ya da password eksik.", "error")
                n1, n2 = generate_captcha()
                return render_template('register.html', c1=n1, c2=n2)

            if not request.form.get('agree'):
                flash("Devam etmek için Kullanıcı Sözleşmesi ve KVKK metnini kabul etmelisin.", "error")
                n1, n2 = generate_captcha()
                return render_template('register.html', c1=n1, c2=n2)
    
            if User.query.filter_by(username=username).first():
                flash('Username Taken', "error")
                n1, n2 = generate_captcha()
                return render_template('register.html', c1=n1, c2=n2)
    
            hashed = generate_password_hash(password, method='pbkdf2:sha256')
            default_avatar = f"https://api.dicebear.com/9.x/bottts-neutral/svg?seed={username}"
    
            new_user = User(
                username=username,
                password=hashed,
                is_approved=False,
                avatar=default_avatar
            )
            db.session.add(new_user)
            db.session.commit()
    
            flash("Registered. Wait for Approval.", "success")
            return redirect(url_for('login'))
    
        n1, n2 = generate_captcha()
        return render_template('register.html', c1=n1, c2=n2)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        seed = request.form.get('seed', '').strip()
        if not seed: seed = current_user.username
        new_avatar = f"https://api.dicebear.com/9.x/bottts-neutral/svg?seed={seed}"
        current_user.avatar = new_avatar
        db.session.commit()
        flash("Avatar Updated!", "success")
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

@app.route('/rooms')
@login_required
def rooms():
    all_rooms = ChatRoom.query.all()
    pending_count = User.query.filter_by(is_approved=False).count()
    return render_template('rooms.html', rooms=all_rooms, is_admin=current_user.is_admin, username=current_user.username, pending_count=pending_count, user=current_user)

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin: return "403", 403
    users = User.query.all()
    pending = [u for u in users if not u.is_approved]
    approved = [u for u in users if u.is_approved]
    return render_template('admin.html', pending=pending, users=approved)

@app.route('/admin/approve/<int:id>')
@login_required
def approve_user(id):
    if not current_user.is_admin: return "403", 403
    user = User.query.get_or_404(id)
    user.is_approved = True
    db.session.commit()
    flash("User Approved", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle/<int:id>')
@login_required
def toggle_admin(id):
    if not current_user.is_admin: return "403", 403
    user = User.query.get_or_404(id)
    if user.username == 'admin' or user.id == current_user.id: return redirect(url_for('admin_panel'))
    user.is_admin = not user.is_admin
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/room/<int:room_id>', methods=['GET', 'POST'])
@login_required
def enter_room(room_id):
            room = ChatRoom.query.get_or_404(room_id)
        
            if current_user.is_admin:
                session['room_id'] = room.id
                session['authorized_room_id'] = room.id
                return redirect(url_for('chat'))
        
            if session.get('authorized_room_id') == room.id:
                session['room_id'] = room.id
                return redirect(url_for('chat'))
        
            if request.method == 'POST':
                pw = request.form.get('password', '')
                if check_password_hash(room.password, pw):
                    session['authorized_room_id'] = room.id
                    session['room_id'] = room.id
                    return redirect(url_for('chat'))
        
                flash("Wrong Password", "error")
        
            return render_template('enter_room.html', room=room)
        

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files: return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(path)
        return jsonify({'filename': unique_filename})
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/chat')
@login_required
def chat():
    room_id = session.get('room_id')
    if not room_id: return redirect(url_for('rooms'))
    room = ChatRoom.query.get(room_id)
    
    messages_db = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp).all()
    users = User.query.all()
    avatar_map = {u.username: u.avatar for u in users}
    pending_count = User.query.filter_by(is_approved=False).count()
    
    decrypted_msgs = []
    for m in messages_db:
        try: content = cipher_suite.decrypt(m.content.encode('utf-8')).decode()
        except: content = "[UNREADABLE]"
        m.temp_avatar = avatar_map.get(m.username, "https://api.dicebear.com/9.x/bottts-neutral/svg?seed=unknown")
        m.temp_content = content
        decrypted_msgs.append(m)

    return render_template('chat.html', room=room, messages=decrypted_msgs, user=current_user, pending_count=pending_count)

@app.route('/admin/create_room', methods=['GET', 'POST'])
@login_required
def create_room():
    if not current_user.is_admin: return "403", 403
    if request.method == 'POST':
        name = request.form.get('name')
        pw = request.form.get('password')
        room = ChatRoom(name=name, password=generate_password_hash(pw, method='pbkdf2:sha256'))
        db.session.add(room)
        db.session.commit()
        return redirect(url_for('rooms'))
    return render_template('create_room.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('room_id', None)
    session.pop('authorized_room_id', None)
    logout_user()
    return redirect(url_for('login'))

@app.route('/delete_user/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return "403", 403

    u = User.query.get_or_404(id)

    # kendini veya ana admin'i silme
    if u.id == current_user.id or u.username == 'admin':
        flash("Bu kullanıcı silinemez.", "error")
        return redirect(url_for('admin_panel'))

    try:
        Message.query.filter_by(username=u.username).delete()
    except Exception:
        pass

    try:
        user_sids.pop(u.id, None)
        user_fps.pop(u.id, None)
        for rid in list(room_members.keys()):
            room_members[rid].pop(u.username, None)
    except Exception:
        pass

    db.session.delete(u)
    db.session.commit()

    flash("User deleted.", "success")
    return redirect(url_for('admin_panel'))


@app.route('/ban_user/<int:id>', methods=['POST'])
@login_required
def ban_user(id):
    if not current_user.is_admin:
        return "403", 403

    user = User.query.get_or_404(id)

    reason = request.form.get('reason', '').strip()
    user.is_banned = True
    user.ban_reason = reason or "BANNED"
    db.session.commit()

    fps = list(user_fps.get(user.id, set()))
    for fp in fps:
        if fp and not BannedFingerprint.query.filter_by(fp_hash=fp).first():
            db.session.add(BannedFingerprint(fp_hash=fp, reason=user.ban_reason))
    db.session.commit()

    # 2) Real-time kick (sende zaten vardı, aynen)
    for sid in list(user_sids.get(user.id, set())):
        try:
            socketio.emit('banned', {'msg': f'BANNED: {user.ban_reason}'}, to=sid)
            socketio.server.disconnect(sid)
        except Exception:
            pass

    flash(f"{user.username} banned.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/unban_user/<int:id>', methods=['POST'])
@login_required
def unban_user(id):
    if not current_user.is_admin: return "403", 403
    u = User.query.get_or_404(id)
    u.is_banned = False
    db.session.commit()
    flash("Unbanned", "success")
    return redirect(url_for('admin_panel'))

@app.route("/sitemap.xml")
def sitemap():
    pages = [
        ("https://keetz.xyz/", "weekly", "1.0"),
        ("https://keetz.xyz/terms", "yearly", "0.2"),
        ("https://keetz.xyz/privacy", "yearly", "0.2"),
    ]

    xml = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']

    for loc, freq, prio in pages:
        xml.append("  <url>")
        xml.append(f"    <loc>{loc}</loc>")
        xml.append(f"    <changefreq>{freq}</changefreq>")
        xml.append(f"    <priority>{prio}</priority>")
        xml.append("  </url>")

    xml.append("</urlset>")

    return Response("\n".join(xml), mimetype="application/xml")

@app.route('/terms')
def terms():
    return render_template("terms.html")

@app.route('/privacy')
def privacy():
    return render_template("privacy.html")

@app.route("/robots.txt")
def robots():
    txt = """User-agent: Googlebot
Disallow: /login
Disallow: /register

User-agent: Bingbot
Disallow: /login
Disallow: /register

User-agent: *
Disallow: /login
Disallow: /register

Sitemap: https://keetz.xyz/sitemap.xml
"""
    return Response(txt, mimetype="text/plain")


@socketio.on('join')
def on_join(data):
    if not enforce_not_banned(): 
        return  
    rid = session.get("room_id")
    if rid: 
        room_name = f"room_{rid}"
        join_room(room_name)
        user_sids[current_user.id].add(request.sid)
        room_members[rid][current_user.username] = current_user.avatar
        active_list = [{'username': u, 'avatar': a} for u, a in room_members[rid].items()]
        emit('update_user_list', {'users': active_list}, to=room_name)

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        user_sids.get(current_user.id, set()).discard(request.sid)

    rid = session.get("room_id")
    if rid and current_user.is_authenticated:
        if current_user.username in room_members[rid]:
            del room_members[rid][current_user.username]
        room_name = f"room_{rid}"
        active_list = [{'username': u, 'avatar': a} for u, a in room_members[rid].items()]
        emit('update_user_list', {'users': active_list}, to=room_name)

@socketio.on('typing')
def on_typing():
    if not enforce_not_banned(): 
        return
    rid = session.get("room_id")
    if rid: emit('display_typing', {'user': current_user.username, 'is_typing': True}, to=f"room_{rid}", include_self=False)

@socketio.on('stop_typing')
def on_stop_typing():
    rid = session.get("room_id")
    if rid: emit('display_typing', {'user': current_user.username, 'is_typing': False}, to=f"room_{rid}", include_self=False)

@socketio.on('message')
def handle_message(data):
    room_id = session.get("room_id")
    if not room_id:
        return

    try:
        user_key = current_user.id
        username = current_user.username
        user_avatar = current_user.avatar
    except:
        user_key = session.get('username')
        username = session.get('username')
        user_avatar = session.get('avatar')

    current_time = time.time()
    last_msg_time = user_last_message_time.get(user_key, 0)

    if current_time - last_msg_time < 0.5:
        last_warn = user_last_warning_time.get(user_key, 0)
        
        if current_time - last_warn < 3.0:
            return 

        emit('message', {
            'user': 'SYSTEM',
            'msg': 'Slow down! You are writing too fast!',
            'avatar': None,
            'image': None
        }, to=request.sid)
        
        user_last_warning_time[user_key] = current_time 
        return 
        
    user_last_message_time[user_key] = current_time

    msg_text = (data.get('msg') or '').strip()
    image_filename = data.get('image', None)
    room_channel = f"room_{room_id}"

    if not msg_text and not image_filename:
        return

    if msg_text.startswith('/clear'):
        if not current_user.is_admin:
            emit('message', {'user': 'SYSTEM', 'msg': 'No authorization!', 'avatar': None}, to=request.sid)
            return

        parts = msg_text.split()
        if len(parts) == 1:
            Message.query.filter_by(room_id=room_id).delete()
            db.session.commit()
            emit('cleared', to=room_channel)
            return
        try:
            n = int(parts[1])
        except (IndexError, ValueError):
            emit('message', {'user': 'SYSTEM', 'msg': 'Usage: /clear or /clear 50', 'avatar': None}, to=request.sid)
            return
        if n <= 0:
            emit('message', {'user': 'SYSTEM', 'msg': 'Number must > 0', 'avatar': None}, to=request.sid)
            return
        n = min(n, 500)
        ids = [m.id for m in Message.query.filter_by(room_id=room_id).order_by(Message.id.desc()).limit(n).all()]
        if ids:
            Message.query.filter(Message.id.in_(ids)).delete(synchronize_session=False)
            db.session.commit()
        emit('cleared', to=room_channel)
        return

    elif msg_text.startswith('/topic'):
        if not current_user.is_admin:
            emit('message', {'user': 'SYSTEM', 'msg': 'Topic can only changed by admins!', 'avatar': None}, to=request.sid)
            return

        parts = msg_text.split(' ', 1)
        if len(parts) == 1 or not parts[1].strip():
            emit('message', {'user': 'SYSTEM', 'msg': 'Usage: /topic new_topic', 'avatar': None}, to=request.sid)
            return
        room = ChatRoom.query.get(room_id)
        room.topic = parts[1].strip()
        db.session.commit()
        emit('update_topic', {'topic': room.topic}, to=room_channel)
        return

    elif msg_text.startswith('/deletechannel'):
        if not current_user.is_admin:
            emit('message', {'user': 'SYSTEM', 'msg': 'Admin Only!', 'avatar': None}, to=request.sid)
            return
        archive_and_delete_channel(room_id)
        emit('channel_deleted', to=room_channel)
        return

    elif msg_text.startswith('/'):
        emit('message', {'user': 'SYSTEM', 'msg': 'Unknown Command!', 'avatar': None}, to=request.sid)
        return
    
    encrypted_text = cipher_suite.encrypt(msg_text.encode('utf-8')).decode('utf-8')
    msg = Message(
        room_id=room_id, 
        username=current_user.username, 
        content=encrypted_text, 
        image=image_filename
    )
    db.session.add(msg)
    db.session.commit()

    emit('message', {
        'user': username,
        'msg': msg_text, 
        'image': image_filename,
        'avatar': user_avatar,
        'temp_content': msg_text
    }, to=room_channel)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_pw = os.environ.get("ADMIN_PASSWORD")
            if admin_pw:
                hashed_pw = generate_password_hash(admin_pw, method='pbkdf2:sha256')
                admin = User(
                    username='admin',
                    password=hashed_pw,
                    is_admin=True,
                    is_approved=True,
                    avatar="https://api.dicebear.com/9.x/bottts-neutral/svg?seed=DedSecAdmin"
                )
                db.session.add(admin)
                db.session.commit()

    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

