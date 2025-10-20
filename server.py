import sqlite3
import os
import hashlib
import json
import time
from flask import Flask, request, jsonify, g, send_from_directory, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
import uuid

# --- CONFIGURATION ---
DATABASE_NAME = "chatapp.db"
UPLOAD_FOLDER_AVATARS = 'uploads/avatars'
UPLOAD_FOLDER_ATTACHMENTS = 'uploads/attachments'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}

# --- FLASK APP SETUP ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.config['UPLOAD_FOLDER_AVATARS'] = UPLOAD_FOLDER_AVATARS
app.config['UPLOAD_FOLDER_ATTACHMENTS'] = UPLOAD_FOLDER_ATTACHMENTS
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

# Create upload directories if they don't exist
os.makedirs(UPLOAD_FOLDER_AVATARS, exist_ok=True)
os.makedirs(UPLOAD_FOLDER_ATTACHMENTS, exist_ok=True)


# --- DATABASE UTILITIES ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_NAME)
        db.row_factory = sqlite3.Row 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # --- FIX: Added last_seen column ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                password_hash TEXT NOT NULL,
                bio TEXT,
                avatar TEXT DEFAULT 'default.png',
                created_at INTEGER NOT NULL,
                is_admin BOOLEAN DEFAULT 0 NOT NULL,
                last_seen INTEGER
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER NOT NULL,
                user2_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user1_id) REFERENCES users (id),
                FOREIGN KEY (user2_id) REFERENCES users (id),
                UNIQUE(user1_id, user2_id)
            )
        """)
        
        # --- FIX: Added message_id for deletion and file info ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT,
                file_url TEXT,
                file_type TEXT,
                timestamp INTEGER NOT NULL,
                read_status BOOLEAN DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        """)

        admin_user_id = "admin"
        admin_password = "admin_password"
        admin_user = cursor.execute("SELECT id FROM users WHERE user_id = ?", (admin_user_id,)).fetchone()
        
        if not admin_user:
            print(f"Creating admin user '{admin_user_id}' with password '{admin_password}'...")
            password_hash = hash_password(admin_password)
            timestamp = int(time.time())
            cursor.execute(
                "INSERT INTO users (user_id, email, name, password_hash, created_at, is_admin, last_seen) VALUES (?, ?, ?, ?, ?, 1, ?)",
                (admin_user_id, "admin@app.com", "Administrator", password_hash, timestamp, timestamp)
            )
        else:
            cursor.execute("UPDATE users SET is_admin = 1 WHERE user_id = ?", (admin_user_id,))

        db.commit()
    print("Database initialized successfully.")

# --- HELPERS ---
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_from_token(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '): return None
    token = auth_header.split(' ')[1]
    try:
        user_id_internal = int(token)
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id_internal,)).fetchone()
        return user
    except (ValueError, TypeError, IndexError): return None

# --- AUTH & PRESENCE ENDPOINTS ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email, user_id, password, name = data.get('email'), data.get('user_id'), data.get('password'), data.get('name')
    if not all([email, user_id, password, name]): return jsonify({"error": "Missing required fields"}), 400
    db = get_db()
    if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone(): return jsonify({"error": "This email is already registered."}), 409
    if db.execute("SELECT id FROM users WHERE user_id = ?", (user_id,)).fetchone(): return jsonify({"error": "This User ID is already taken."}), 409
    password_hash, timestamp = hash_password(password), int(time.time())
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (user_id, email, name, password_hash, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, email, name, password_hash, timestamp, timestamp)
    )
    db.commit()
    return jsonify({"message": "User created successfully. Please log in."}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email, password = data.get('email'), data.get('password')
    if not email or not password: return jsonify({"error": "Email and password are required"}), 400
    db = get_db()
    user = db.execute( "SELECT id, user_id, email, is_admin FROM users WHERE email = ? AND password_hash = ?", (email, hash_password(password))).fetchone()
    if user:
        db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (int(time.time()), user['id']))
        db.commit()
        return jsonify({ "message": "Login successful!", "token": str(user['id']), "userId": user['user_id'], "email": user['email'], "isAdmin": bool(user['is_admin'])}), 200
    else: return jsonify({"error": "Invalid email or password."}), 401

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (int(time.time()), user['id']))
    db.commit()
    return jsonify({"status": "ok"}), 200

# --- PROFILE ENDPOINTS ---
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    if request.method == 'GET':
        return jsonify({ "userId": user['user_id'], "name": user['name'], "email": user['email'], "bio": user['bio'], "avatar": url_for('serve_avatar', filename=user['avatar'], _external=True)})
    if request.method == 'POST':
        db = get_db()
        if 'bio' in request.form: db.execute("UPDATE users SET bio = ? WHERE id = ?", (request.form['bio'], user['id']))
        if 'name' in request.form: db.execute("UPDATE users SET name = ? WHERE id = ?", (request.form['name'], user['id']))
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{user['id']}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER_AVATARS'], filename))
                db.execute("UPDATE users SET avatar = ? WHERE id = ?", (filename, user['id']))
        db.commit()
        return jsonify({"message": "Profile updated successfully"})

@app.route('/profile/<user_id>', methods=['GET'])
def get_public_profile(user_id):
    if not get_user_from_token(request.headers.get('Authorization')): return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    profile_user = db.execute("SELECT user_id, name, bio, avatar FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if not profile_user: return jsonify({"error": "User not found"}), 404
    return jsonify({ "userId": profile_user['user_id'], "name": profile_user['name'], "bio": profile_user['bio'], "avatar": url_for('serve_avatar', filename=profile_user['avatar'], _external=True)})

# --- CONNECTIONS ENDPOINTS ---
@app.route('/connections', methods=['GET'])
def get_connections():
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    results = db.execute("""
        SELECT u.user_id, u.name, u.avatar, u.last_seen FROM users u JOIN connections c ON u.id = c.user2_id WHERE c.user1_id = ?
        UNION
        SELECT u.user_id, u.name, u.avatar, u.last_seen FROM users u JOIN connections c ON u.id = c.user1_id WHERE c.user2_id = ?
    """, (user['id'], user['id'])).fetchall()
    return jsonify([{ "userId": r['user_id'], "name": r['name'], "avatar": url_for('serve_avatar', filename=r['avatar'], _external=True), "lastSeen": r['last_seen']} for r in results])

@app.route('/connections/add', methods=['POST'])
def add_connection():
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    friend_id_str = data.get('friend_id')
    if not friend_id_str: return jsonify({"error": "Friend ID is required"}), 400
    db = get_db()
    friend = db.execute("SELECT id FROM users WHERE user_id = ?", (friend_id_str,)).fetchone()
    if not friend: return jsonify({"error": "User not found"}), 404
    if friend['id'] == user['id']: return jsonify({"error": "You cannot add yourself"}), 400
    existing = db.execute("SELECT id FROM connections WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)", (user['id'], friend['id'], friend['id'], user['id'])).fetchone()
    if existing: return jsonify({"error": "You are already connected with this user"}), 409
    db.execute("INSERT INTO connections (user1_id, user2_id, created_at) VALUES (?, ?, ?)", (user['id'], friend['id'], int(time.time())))
    db.commit()
    return jsonify({"message": "Friend added successfully!"})

# --- MESSAGING ENDPOINTS ---
@app.route('/messages/<friend_user_id>', methods=['GET'])
def get_messages(friend_user_id):
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    friend = db.execute("SELECT id FROM users WHERE user_id = ?", (friend_user_id,)).fetchone()
    if not friend: return jsonify({"error": "Friend not found"}), 404
    messages = db.execute("""
        SELECT message_id, sender_id, content, file_url, file_type, timestamp FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC
    """, (user['id'], friend['id'], friend['id'], user['id'])).fetchall()
    history = [{ "messageId": m['message_id'], "type": "sent" if m['sender_id'] == user['id'] else "received", "content": m['content'], "fileUrl": url_for('serve_attachment', filename=m['file_url'], _external=True) if m['file_url'] else None, "fileType": m['file_type'], "timestamp": m['timestamp']} for m in messages]
    return jsonify(history)

@app.route('/messages', methods=['POST'])
def send_message():
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    friend_user_id, content = data.get('receiver_id'), data.get('content')
    if not friend_user_id or not content: return jsonify({"error": "Receiver ID and content are required"}), 400
    db = get_db()
    friend = db.execute("SELECT id FROM users WHERE user_id = ?", (friend_user_id,)).fetchone()
    if not friend: return jsonify({"error": "Receiver not found"}), 404
    db.execute("INSERT INTO messages (message_id, sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?, ?)", (str(uuid.uuid4()), user['id'], friend['id'], content, int(time.time())))
    db.commit()
    return jsonify({"message": "Message sent successfully"}), 201

@app.route('/messages/upload', methods=['POST'])
def upload_file():
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    receiver_id = request.form.get('receiver_id')
    if file.filename == '' or not receiver_id: return jsonify({"error": "No selected file or receiver"}), 400
    db = get_db()
    friend = db.execute("SELECT id FROM users WHERE user_id = ?", (receiver_id,)).fetchone()
    if not friend: return jsonify({"error": "Receiver not found"}), 404
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{user['id']}_{friend['id']}_{int(time.time())}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER_ATTACHMENTS'], filename))
        file_type = 'image' if file.mimetype.startswith('image/') else 'document'
        db.execute("INSERT INTO messages (message_id, sender_id, receiver_id, file_url, file_type, timestamp) VALUES (?, ?, ?, ?, ?, ?)", (str(uuid.uuid4()), user['id'], friend['id'], filename, file_type, int(time.time())))
        db.commit()
        return jsonify({"message": "File sent successfully"}), 201
    return jsonify({"error": "File type not allowed"}), 400

@app.route('/messages/<message_id>', methods=['DELETE'])
def unsend_message(message_id):
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user: return jsonify({"error": "Unauthorized"}), 401
    db = get_db()
    message = db.execute("SELECT sender_id FROM messages WHERE message_id = ?", (message_id,)).fetchone()
    if not message: return jsonify({"error": "Message not found"}), 404
    if message['sender_id'] != user['id']: return jsonify({"error": "You can only delete your own messages"}), 403
    db.execute("DELETE FROM messages WHERE message_id = ?", (message_id,))
    db.commit()
    return jsonify({"message": "Message deleted"}), 200

# --- ADMIN ENDPOINTS ---
@app.route('/admin/data', methods=['GET'])
def get_admin_data():
    user = get_user_from_token(request.headers.get('Authorization'))
    if not user or not user['is_admin']: return jsonify({"error": "Administrator access required"}), 403
    db = get_db()
    users = db.execute("SELECT user_id, email, name, password_hash, created_at FROM users ORDER BY created_at DESC").fetchall()
    total_users = db.execute("SELECT COUNT(id) FROM users").fetchone()[0]
    total_messages = db.execute("SELECT COUNT(id) FROM messages").fetchone()[0]
    return jsonify({ "stats": { "total_users": total_users, "total_messages": total_messages }, "users": [dict(u) for u in users]})

@app.route('/admin/chats/<target_user_id>', methods=['GET'])
def get_user_chats(target_user_id):
    admin_user = get_user_from_token(request.headers.get('Authorization'))
    if not admin_user or not admin_user['is_admin']: return jsonify({"error": "Administrator access required"}), 403
    db = get_db()
    target_user = db.execute("SELECT id FROM users WHERE user_id = ?", (target_user_id,)).fetchone()
    if not target_user: return jsonify({"error": "Target user not found"}), 404
    conversations = db.execute("""
        SELECT DISTINCT u.user_id, u.name, u.avatar FROM users u JOIN (
            SELECT receiver_id as user_id FROM messages WHERE sender_id = :target_id UNION
            SELECT sender_id as user_id FROM messages WHERE receiver_id = :target_id
        ) AS conv ON u.id = conv.user_id WHERE u.id != :target_id
    """, {"target_id": target_user['id']}).fetchall()
    return jsonify([{"userId": r['user_id'], "name": r['name'], "avatar": url_for('serve_avatar', filename=r['avatar'], _external=True)} for r in conversations])

@app.route('/admin/conversation/<user1_id>/<user2_id>', methods=['GET'])
def get_conversation_history(user1_id, user2_id):
    admin_user = get_user_from_token(request.headers.get('Authorization'))
    if not admin_user or not admin_user['is_admin']: return jsonify({"error": "Administrator access required"}), 403
    db = get_db()
    user1 = db.execute("SELECT id, user_id FROM users WHERE user_id = ?", (user1_id,)).fetchone()
    user2 = db.execute("SELECT id, user_id FROM users WHERE user_id = ?", (user2_id,)).fetchone()
    if not user1 or not user2: return jsonify({"error": "One or both users not found"}), 404
    messages = db.execute("""
        SELECT u_sender.user_id as sender_user_id, m.content, m.timestamp FROM messages m JOIN users u_sender ON m.sender_id = u_sender.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?) ORDER BY m.timestamp ASC
    """, (user1['id'], user2['id'], user2['id'], user1['id'])).fetchall()
    return jsonify([{"sender": m['sender_user_id'], "content": m['content'], "timestamp": m['timestamp']} for m in messages])

# --- HTML SERVING & UPLOADS ---
@app.route('/uploads/avatars/<path:filename>')
def serve_avatar(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER_AVATARS'], filename)

@app.route('/uploads/attachments/<path:filename>')
def serve_attachment(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER_ATTACHMENTS'], filename)

@app.route('/')
def serve_landing():
    return send_from_directory('.', 'landing.html')

@app.route('/<path:filename>')
def serve_page(filename):
    return send_from_directory('.', filename)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

