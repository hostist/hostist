import os, re, sqlite3, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("ABYSS_DATA_DIR", ROOT)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "abyss.db")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("ABYSS_SECRET", "replace-this-with-a-long-random-secret")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
socketio = SocketIO(app, cors_allowed_origins=[], async_mode="threading")
# Active voice sessions map Socket.IO connection IDs to authorized room names.
# This lets signaling verify that peers share the same server VC or DM call.
active_voice_sessions = {}

def connect():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, avatar TEXT DEFAULT '', bio TEXT DEFAULT '',
          status TEXT DEFAULT 'online', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS servers(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          owner_id INTEGER NOT NULL REFERENCES users(id), invite_code TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS memberships(
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          role TEXT NOT NULL DEFAULT 'member', joined_at TEXT NOT NULL,
          PRIMARY KEY(user_id,server_id)
        );
        CREATE TABLE IF NOT EXISTS channels(
          id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'text'
        );
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT, channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id), content TEXT NOT NULL, created_at TEXT NOT NULL,
          edited INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS friendships(
          id INTEGER PRIMARY KEY AUTOINCREMENT, requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          addressee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
          UNIQUE(requester_id,addressee_id)
        );
        CREATE TABLE IF NOT EXISTS dm_conversations(
          id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dm_members(
          conversation_id INTEGER NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY(conversation_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS dm_messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id INTEGER NOT NULL REFERENCES dm_conversations(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id), content TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id,id);
        CREATE INDEX IF NOT EXISTS idx_dm_messages_conversation ON dm_messages(conversation_id,id);
        """)

def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def logged_in():
    return "uid" in session

def require_auth(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not logged_in():
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return inner

def is_member(c, uid, sid):
    return c.execute("SELECT 1 FROM memberships WHERE user_id=? AND server_id=?", (uid,sid)).fetchone() is not None

def can_manage(c, uid, sid):
    row = c.execute("SELECT role FROM memberships WHERE user_id=? AND server_id=?", (uid,sid)).fetchone()
    return bool(row and row["role"] in ("owner","admin"))

def dm_allowed(c, uid, cid):
    return c.execute("SELECT 1 FROM dm_members WHERE conversation_id=? AND user_id=?", (cid,uid)).fetchone() is not None

def user_payload(row):
    return {"id": row["id"], "username": row["username"], "avatar": row["avatar"] or "", "status": row["status"]}

@app.route("/")
def home():
    return redirect(url_for("app_home" if logged_in() else "login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            flash("Username must be 3–20 characters using letters, numbers, or underscores.")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.")
        else:
            try:
                with connect() as c:
                    cur = c.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                                    (username,generate_password_hash(password),now()))
                    uid = cur.lastrowid
                    cur = c.execute("INSERT INTO servers(name,owner_id,invite_code,created_at) VALUES(?,?,?,?)",
                                    (username+"'s space",uid,secrets.token_urlsafe(8),now()))
                    sid = cur.lastrowid
                    c.execute("INSERT INTO memberships(user_id,server_id,role,joined_at) VALUES(?,?,?,?)",(uid,sid,"owner",now()))
                    c.execute("INSERT INTO channels(server_id,name,kind) VALUES(?,?,?)",(sid,"general","text"))
                    c.execute("INSERT INTO channels(server_id,name,kind) VALUES(?,?,?)",(sid,"voice","voice"))
                session["uid"], session["username"] = uid, username
                return redirect(url_for("app_home"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        with connect() as c:
            u = c.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
            if u and check_password_hash(u["password_hash"],password):
                session["uid"], session["username"] = u["id"],u["username"]
                c.execute("UPDATE users SET status='online' WHERE id=?",(u["id"],))
                return redirect(url_for("app_home"))
        flash("Incorrect username or password.")
    return render_template("auth.html", mode="login", prefill_username=request.args.get("username", ""))

@app.route("/logout")
def logout():
    if logged_in():
        with connect() as c:
            c.execute("UPDATE users SET status='offline' WHERE id=?",(session["uid"],))
    session.clear()
    return redirect(url_for("login"))

@app.route("/app")
@require_auth
def app_home():
    uid = session["uid"]
    sid = request.args.get("server",type=int)
    cid = request.args.get("channel",type=int)
    dm_id = request.args.get("dm",type=int)
    view = request.args.get("view", "servers")
    if view not in ("servers", "friends"):
        view = "servers"
    with connect() as c:
        servers = c.execute("""SELECT s.*,m.role FROM servers s JOIN memberships m ON m.server_id=s.id
                               WHERE m.user_id=? ORDER BY s.id""",(uid,)).fetchall()
        if not servers:
            return redirect(url_for("logout"))
        server_ids = [s["id"] for s in servers]
        if sid not in server_ids: sid = server_ids[0]
        channels = c.execute("SELECT * FROM channels WHERE server_id=? ORDER BY id",(sid,)).fetchall()
        if not channels:
            c.execute("INSERT INTO channels(server_id,name,kind) VALUES(?,?,?)",(sid,"general","text"))
            channels = c.execute("SELECT * FROM channels WHERE server_id=? ORDER BY id",(sid,)).fetchall()
        if cid not in [x["id"] for x in channels]: cid = next((x["id"] for x in channels if x["kind"]=="text"),channels[0]["id"])
        channel = next(x for x in channels if x["id"]==cid)
        members = c.execute("""SELECT u.id,u.username,u.avatar,u.status,m.role FROM users u
                              JOIN memberships m ON m.user_id=u.id WHERE m.server_id=? ORDER BY m.role,u.username""",(sid,)).fetchall()
        history = []
        if channel["kind"]=="text":
            history = c.execute("""SELECT m.content,m.created_at,u.username,u.avatar,m.id,m.user_id
                                   FROM messages m JOIN users u ON u.id=m.user_id
                                   WHERE m.channel_id=? ORDER BY m.id DESC LIMIT 100""",(cid,)).fetchall()
            history = list(reversed(history))
        friends = c.execute("""SELECT u.id,u.username,u.avatar,u.status FROM friendships f
                               JOIN users u ON u.id=CASE WHEN f.requester_id=? THEN f.addressee_id ELSE f.requester_id END
                               WHERE (f.requester_id=? OR f.addressee_id=?) AND f.status='accepted'
                               ORDER BY u.username""",(uid,uid,uid)).fetchall()
        pending = c.execute("""SELECT f.id,u.username FROM friendships f JOIN users u ON u.id=f.requester_id
                               WHERE f.addressee_id=? AND f.status='pending'""",(uid,)).fetchall()
        dms = c.execute("""SELECT dc.id,u.username,u.id AS other_id,u.avatar,u.status
                           FROM dm_conversations dc JOIN dm_members mine ON mine.conversation_id=dc.id AND mine.user_id=?
                           JOIN dm_members other ON other.conversation_id=dc.id AND other.user_id<>?
                           JOIN users u ON u.id=other.user_id ORDER BY dc.id DESC""",(uid,uid)).fetchall()
        active_dm = None
        dm_history = []
        if dm_id and not dm_allowed(c,uid,dm_id):
            dm_id = None
        if dm_id:
            active_dm = c.execute("""SELECT u.id,u.username,u.avatar,u.status FROM dm_members d
                                     JOIN users u ON u.id=d.user_id WHERE d.conversation_id=? AND d.user_id<>?""",(dm_id,uid)).fetchone()
            dm_history = c.execute("""SELECT m.content,m.created_at,u.username,u.avatar,m.id,m.user_id
                                      FROM dm_messages m JOIN users u ON u.id=m.user_id
                                      WHERE m.conversation_id=? ORDER BY m.id DESC LIMIT 100""",(dm_id,)).fetchall()
            dm_history = list(reversed(dm_history))
    return render_template("app.html",servers=servers,channels=channels,server_id=sid,channel=channel,
                           members=members,history=history,username=session["username"],friends=friends,
                           pending=pending,dms=dms,dm_id=dm_id,active_dm=active_dm,dm_history=dm_history,view=view)

@app.post("/servers/create")
@require_auth
def create_server():
    name=request.form.get("name","").strip()[:32]
    if name:
        with connect() as c:
            cur=c.execute("INSERT INTO servers(name,owner_id,invite_code,created_at) VALUES(?,?,?,?)",
                          (name,session["uid"],secrets.token_urlsafe(8),now()))
            sid=cur.lastrowid
            c.execute("INSERT INTO memberships(user_id,server_id,role,joined_at) VALUES(?,?,?,?)",(session["uid"],sid,"owner",now()))
            c.execute("INSERT INTO channels(server_id,name,kind) VALUES(?,?,?)",(sid,"general","text"))
            c.execute("INSERT INTO channels(server_id,name,kind) VALUES(?,?,?)",(sid,"voice","voice"))
        return redirect(url_for("app_home",server=sid))
    return redirect(url_for("app_home"))

@app.post("/servers/join")
@require_auth
def join_server():
    code=request.form.get("invite","").strip()
    with connect() as c:
        s=c.execute("SELECT id FROM servers WHERE invite_code=?",(code,)).fetchone()
        if s:
            c.execute("INSERT OR IGNORE INTO memberships(user_id,server_id,role,joined_at) VALUES(?,?,?,?)",
                      (session["uid"],s["id"],"member",now()))
            return redirect(url_for("app_home",server=s["id"]))
    flash("That invite code is not valid.")
    return redirect(url_for("app_home"))

@app.post("/servers/<int:sid>/invite")
@require_auth
def rotate_invite(sid):
    with connect() as c:
        if not can_manage(c,session["uid"],sid): abort(403)
        code=secrets.token_urlsafe(8)
        c.execute("UPDATE servers SET invite_code=? WHERE id=?",(code,sid))
    return jsonify({"invite":code})

@app.post("/channels/create")
@require_auth
def create_channel():
    sid=request.form.get("server_id",type=int)
    name=request.form.get("name","").strip().lower().replace(" ","-")[:32]
    kind=request.form.get("kind","text")
    with connect() as c:
        if not is_member(c,session["uid"],sid): abort(403)
        if name and re.fullmatch(r"[a-z0-9-]+",name) and kind in ("text","voice"):
            cur=c.execute("INSERT INTO channels(server_id,name,kind) VALUES(?,?,?)",(sid,name,kind))
            cid=cur.lastrowid
            return redirect(url_for("app_home",server=sid,channel=cid))
    return redirect(url_for("app_home",server=sid))

@app.post("/friends/request")
@require_auth
def friend_request():
    name=request.form.get("username","").strip()
    with connect() as c:
        target=c.execute("SELECT id FROM users WHERE username=?",(name,)).fetchone()
        if not target or target["id"]==session["uid"]:
            flash("User not found.")
        else:
            outgoing=c.execute("SELECT * FROM friendships WHERE requester_id=? AND addressee_id=?",
                               (session["uid"],target["id"])).fetchone()
            incoming=c.execute("SELECT * FROM friendships WHERE requester_id=? AND addressee_id=?",
                               (target["id"],session["uid"])).fetchone()
            existing=outgoing or incoming
            if existing:
                if existing["status"]=="accepted":
                    flash("You are already friends.")
                elif incoming and incoming["status"]=="pending":
                    c.execute("UPDATE friendships SET status='accepted' WHERE id=?",(incoming["id"],))
                    flash("Friend request accepted.")
                else:
                    flash("Friend request already sent.")
            else:
                c.execute("INSERT INTO friendships(requester_id,addressee_id,status,created_at) VALUES(?,?,?,?)",
                          (session["uid"],target["id"],"pending",now()))
                flash("Friend request sent.")
    return redirect(url_for("app_home"))

@app.post("/friends/accept/<int:fid>")
@require_auth
def accept_friend(fid):
    with connect() as c:
        c.execute("UPDATE friendships SET status='accepted' WHERE id=? AND addressee_id=?",(fid,session["uid"]))
    return redirect(url_for("app_home"))

@app.post("/dms/open/<int:other_id>")
@require_auth
def open_dm(other_id):
    uid=session["uid"]
    if other_id==uid: abort(400)
    with connect() as c:
        other=c.execute("SELECT id FROM users WHERE id=?",(other_id,)).fetchone()
        if not other: abort(404)
        # Open an existing one-to-one conversation if present.
        row=c.execute("""SELECT a.conversation_id FROM dm_members a JOIN dm_members b
                         ON a.conversation_id=b.conversation_id WHERE a.user_id=? AND b.user_id=? LIMIT 1""",
                      (uid,other_id)).fetchone()
        if row: did=row["conversation_id"]
        else:
            cur=c.execute("INSERT INTO dm_conversations(created_at) VALUES(?)",(now(),))
            did=cur.lastrowid
            c.execute("INSERT INTO dm_members(conversation_id,user_id) VALUES(?,?)",(did,uid))
            c.execute("INSERT INTO dm_members(conversation_id,user_id) VALUES(?,?)",(did,other_id))
    return redirect(url_for("app_home",dm=did))

@app.post("/profile")
@require_auth
def profile():
    bio=request.form.get("bio","").strip()[:160]
    avatar=session.get("avatar","")
    file=request.files.get("avatar")
    if file and file.filename:
        ext=os.path.splitext(secure_filename(file.filename))[1].lower()
        if ext not in (".png",".jpg",".jpeg",".gif",".webp"): 
            flash("Avatar must be PNG, JPG, GIF, or WEBP.")
            return redirect(url_for("app_home"))
        filename=f"user_{session['uid']}_{secrets.token_hex(5)}{ext}"
        file.save(os.path.join(UPLOAD_DIR,filename))
        avatar=filename
    with connect() as c:
        c.execute("UPDATE users SET bio=?,avatar=? WHERE id=?",(bio,avatar,session["uid"]))
    flash("Profile updated.")
    return redirect(url_for("app_home"))

@app.get("/api/servers/<int:sid>/invite")
@require_auth
def get_invite(sid):
    with connect() as c:
        if not can_manage(c,session["uid"],sid): abort(403)
        row=c.execute("SELECT invite_code FROM servers WHERE id=?",(sid,)).fetchone()
        if not row: abort(404)
        return jsonify({"invite":row["invite_code"]})

@socketio.on("join_channel")
def ws_join_channel(data):
    if not logged_in(): return
    cid=int(data.get("channel_id",0))
    with connect() as c:
        row=c.execute("SELECT server_id FROM channels WHERE id=?",(cid,)).fetchone()
        if row and is_member(c,session["uid"],row["server_id"]):
            join_room(f"channel:{cid}")

@socketio.on("send_message")
def ws_send_message(data):
    if not logged_in(): return
    cid=int(data.get("channel_id",0))
    content=str(data.get("content","")).strip()
    if not content or len(content)>2000: return
    with connect() as c:
        row=c.execute("SELECT server_id FROM channels WHERE id=?",(cid,)).fetchone()
        if not row or not is_member(c,session["uid"],row["server_id"]): return
        cur=c.execute("INSERT INTO messages(channel_id,user_id,content,created_at) VALUES(?,?,?,?)",
                      (cid,session["uid"],content,now()))
        user=c.execute("SELECT username,avatar FROM users WHERE id=?",(session["uid"],)).fetchone()
        msg={"id":cur.lastrowid,"username":user["username"],"avatar":user["avatar"] or "",
             "user_id":session["uid"],"content":content,"created_at":datetime.utcnow().strftime("%I:%M %p")}
    emit("new_message",msg,room=f"channel:{cid}")

@socketio.on("join_dm")
def ws_join_dm(data):
    if not logged_in(): return
    did=int(data.get("dm_id",0))
    with connect() as c:
        if dm_allowed(c,session["uid"],did): join_room(f"dm:{did}")

@socketio.on("send_dm")
def ws_send_dm(data):
    if not logged_in(): return
    did=int(data.get("dm_id",0))
    content=str(data.get("content","")).strip()
    if not content or len(content)>2000: return
    with connect() as c:
        if not dm_allowed(c,session["uid"],did): return
        cur=c.execute("INSERT INTO dm_messages(conversation_id,user_id,content,created_at) VALUES(?,?,?,?)",
                      (did,session["uid"],content,now()))
        user=c.execute("SELECT username,avatar FROM users WHERE id=?",(session["uid"],)).fetchone()
        msg={"id":cur.lastrowid,"username":user["username"],"avatar":user["avatar"] or "",
             "user_id":session["uid"],"content":content,"created_at":datetime.utcnow().strftime("%I:%M %p")}
    emit("new_dm",msg,room=f"dm:{did}")

@socketio.on("voice_join")
def voice_join(data):
    if not logged_in() or not isinstance(data, dict):
        return
    try:
        cid = int(data.get("channel_id", 0))
    except (TypeError, ValueError):
        return
    with connect() as c:
        row = c.execute("SELECT server_id,kind,name FROM channels WHERE id=?", (cid,)).fetchone()
        if not row or row["kind"] != "voice" or not is_member(c, session["uid"], row["server_id"]):
            return
        user = c.execute("SELECT username FROM users WHERE id=?", (session["uid"],)).fetchone()
    room = f"voice:{cid}"
    previous = active_voice_sessions.get(request.sid)
    if previous and previous != room:
        leave_room(previous)
        emit("voice_peer_left", {"sid": request.sid}, room=previous)
    active_voice_sessions[request.sid] = room
    join_room(room)
    emit("voice_peer", {"sid": request.sid, "username": user["username"]}, room=room, include_self=False)
    emit("voice_joined", {"room": room, "name": row["name"], "kind": "channel"})

@socketio.on("dm_call_invite")
def dm_call_invite(data):
    if not logged_in() or not isinstance(data, dict):
        return
    try:
        did = int(data.get("dm_id", 0))
    except (TypeError, ValueError):
        return
    with connect() as c:
        if not dm_allowed(c, session["uid"], did):
            return
        user = c.execute("SELECT username FROM users WHERE id=?", (session["uid"],)).fetchone()
    emit("dm_call_incoming", {"dm_id": did, "username": user["username"]}, room=f"dm:{did}", include_self=False)

@socketio.on("dm_voice_join")
def dm_voice_join(data):
    if not logged_in() or not isinstance(data, dict):
        return
    try:
        did = int(data.get("dm_id", 0))
    except (TypeError, ValueError):
        return
    with connect() as c:
        if not dm_allowed(c, session["uid"], did):
            return
        user = c.execute("SELECT username FROM users WHERE id=?", (session["uid"],)).fetchone()
    room = f"dmvoice:{did}"
    previous = active_voice_sessions.get(request.sid)
    if previous and previous != room:
        leave_room(previous)
        emit("voice_peer_left", {"sid": request.sid}, room=previous)
    active_voice_sessions[request.sid] = room
    join_room(room)
    emit("voice_peer", {"sid": request.sid, "username": user["username"]}, room=room, include_self=False)
    emit("voice_joined", {"room": room, "name": "Direct message call", "kind": "dm"})

@socketio.on("voice_leave")
def voice_leave(data=None):
    room = active_voice_sessions.pop(request.sid, None)
    if not room:
        return
    leave_room(room)
    emit("voice_peer_left", {"sid": request.sid}, room=room)

@socketio.on("voice_signal")
def voice_signal(data):
    if not logged_in() or not isinstance(data, dict):
        return
    target = data.get("target")
    signal = data.get("signal")
    sender_room = active_voice_sessions.get(request.sid)
    if not target or not isinstance(signal, dict) or not sender_room:
        return
    # Relay only between people in the same authorized voice room.
    if active_voice_sessions.get(target) != sender_room:
        return
    socketio.emit("voice_signal", {"from": request.sid, "signal": signal}, to=target)

@socketio.on("disconnect")
def ws_disconnect():
    cid = active_voice_sessions.pop(request.sid, None)
    if cid is not None:
        emit("voice_peer_left", {"sid": request.sid}, room=cid)
    if logged_in():
        with connect() as c:
            c.execute("UPDATE users SET status='offline' WHERE id=?", (session["uid"],))
    # Socket.IO removes the socket from rooms automatically.

@app.errorhandler(403)
def forbidden(_): return "You do not have permission to do that.",403

init_db()  # Also runs when imported by a production server such as Gunicorn.\n\nif __name__ == "__main__":\n    socketio.run(app, host="127.0.0.1", port=5000, debug=True, allow_unsafe_werkzeug=True)
