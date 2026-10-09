import time
import os
import ssl
import json
import uuid
import base64
import hashlib
import secrets
import sqlite3
from aiohttp import web
from dotenv import load_dotenv

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
DB_FILE = os.getenv("DB_FILE", "backend_db.db")
CERT_FILE = os.getenv("CERT_FILE", "server.crt")
CERT_KEY_FILE = os.getenv("CERT_KEY_FILE", "server.key")

TOKEN_EXPIRY_PERIOD = 60*60*24*7

# ----------------- DATABASE HELPERS -----------------

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                token TEXT,
                last_login INTEGER
            )
        """)
        conn.commit()

init_db()

def hash_password(password: str, salt: str|None = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000
    ).hex()
    return hashed, salt

def authenticate_token(token: str):
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute("SELECT id, username, last_login FROM users WHERE token = ?", (token,)).fetchone()
        if row:
            if abs(int(time.time()) - row["last_login"]) >= TOKEN_EXPIRY_PERIOD:
                return None
            conn.execute("UPDATE users SET last_login = ? WHERE token = ?", (int(time.time()), token))
            return dict(row)
        return None

# ----------------- WEBSOCKET PEER REGISTRY -----------------
# Stores active connections: user_id -> { "ws": WebSocketResponse, "username": str }
active_peers = {}

# ----------------- ROUTE HANDLERS -----------------

routes = web.RouteTableDef()

@routes.get("/")
async def main_page(request):
    token = request.cookies.get("auth_token")
    user = authenticate_token(token)
    if not user:
        raise web.HTTPFound('/login')
    return web.FileResponse('public/index.html')

@routes.get("/login")
async def login_page(_):
    return web.FileResponse('public/login.html')

@routes.get("/admin")
async def admin_page(request):
    # Basic Auth Verification for Admin
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="Admin"'})
    
    encoded_creds = auth_header.split(" ")[1]
    decoded = base64.b64decode(encoded_creds).decode("utf-8")
    user, pwd = decoded.split(":", 1)
    
    if user != ADMIN_USERNAME or pwd != ADMIN_PASSWORD:
        return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="Admin"'})

    return web.FileResponse('public/admin.html')

# ----------------- API ENDPOINTS -----------------

@routes.post("/api/login")
async def api_login(request):
    data = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return web.json_response({"error": "Invalid username or password"}, status=401)
        
        expected_hash, _ = hash_password(password, row["salt"])
        if expected_hash != row["password_hash"]:
            return web.json_response({"error": "Invalid username or password"}, status=401)

        # Generate a new access token
        new_token = secrets.token_urlsafe(32)
        conn.execute("UPDATE users SET (token, last_login) = (?, ?) WHERE id = ?", (new_token, int(time.time()), row["id"]))
        conn.commit()

    resp = web.json_response({"success": True, "token": new_token, "userId": row["id"], "username": row["username"]})
    # Set the authentication cookie
    resp.set_cookie("auth_token", new_token, max_age=60*60*24*7, path="/", samesite="Lax")
    return resp

# Admin basic auth check
def admin_check(request) -> None|web.Response:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return web.json_response({"error": "Unauthorized"}, status=401)
        
    encoded = auth_header.split(" ")[1]
    user, pwd = base64.b64decode(encoded).decode("utf-8").split(":", 1)
    if user != ADMIN_USERNAME or pwd != ADMIN_PASSWORD:
        return web.json_response({"error": "Unauthorized"}, status=401)

@routes.post("/api/admin/users")
async def api_admin_create_user(request):
    res = admin_check(request)
    if res: return res

    data = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return web.json_response({"error": "Username and password required"}, status=400)

    user_id = str(uuid.uuid4())[:8]
    p_hash, salt = hash_password(password)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, salt) VALUES (?, ?, ?, ?)",
                (user_id, username, p_hash, salt)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return web.json_response({"error": "Username already exists"}, status=400)

    return web.json_response({"success": True, "userId": user_id, "username": username})

@routes.patch("/api/admin/users")
async def api_admin_edit_user(request):
    res = admin_check(request)
    if res: return res

    data = await request.json()
    user_id = data.get("user_id", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not user_id or not (username or password):
        print(data)
        return web.json_response({"error": "Invalid request form"}, status=400)

    try:
        with get_db() as conn:
            if username:
                conn.execute(
                    "UPDATE users SET username = ? WHERE id = ?",
                    (username, user_id)
                )
            if password:
                p_hash, salt = hash_password(password)
                conn.execute(
                    "UPDATE users SET (password_hash, salt) = (?, ?) WHERE id = ?",
                    (p_hash, salt, user_id)
                )
            conn.execute("UPDATE users SET (token, last_login) = (NULL, NULL)")
            conn.commit()
    except sqlite3.IntegrityError:
        return web.json_response({"error": "User ID does not exist or invalid operation"}, status=400)

    return web.json_response({"success": True, "userId": user_id})

@routes.delete("/api/admin/users")
async def api_admin_delete_user(request):
    res = admin_check(request)
    if res: return res

    data = await request.json()
    user_id = data.get("user_id", "").strip()

    if not user_id:
        return web.json_response({"error": "User ID required"}, status=400)

    try:
        with get_db() as conn:
            conn.execute(
                "DELETE FROM users WHERE id = ?",
                (user_id,)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return web.json_response({"error": "User ID does not exist"}, status=400)

    return web.json_response({"success": True, "userId": user_id})

@routes.get("/api/admin/users")
async def api_admin_list_users(request):
    res = admin_check(request)
    if res: return res
    with get_db() as conn:
        rows = conn.execute("SELECT id, username, last_login FROM users").fetchall()
        return web.json_response([dict(r) for r in rows])

@routes.get("/api/users")
async def api_get_users(request):
    """Returns all registered users with their IDs for client display."""
    token = request.cookies.get("auth_token")
    if not authenticate_token(token):
        return web.json_response({"error": "Unauthorized"}, status=401)

    with get_db() as conn:
        rows = conn.execute("SELECT id, username FROM users").fetchall()
        return web.json_response([dict(r) for r in rows])

# ----------------- WEBSOCKET SIGNALING -----------------
@routes.get("/ws")
async def websocket_handler(request):
    token = request.cookies.get("auth_token")
    user = authenticate_token(token)
    if not user:
        return web.Response(status=403, text="Unauthorized WebSocket connection")

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    user_id = user["id"]
    username = user["username"]

    # 1. Inform newly connected peer about its ID and currently online peers
    existing_online = [{"id": pid, "username": pdata["username"]} for pid, pdata in active_peers.items()]
    await ws.send_json({
        "type": "welcome",
        "id": user_id,
        "username": username,
        "existingPeers": existing_online
    })

    # 2. Inform existing peers that a new peer joined
    for _, pdata in active_peers.items():
        if not pdata["ws"].closed:
            await pdata["ws"].send_json({
                "type": "peer-joined",
                "id": user_id,
                "username": username
            })

    active_peers[user_id] = {"ws": ws, "username": username}

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                payload = json.loads(msg.data)
                target_id = payload.get("targetId")

                # Targeted WebRTC signaling exchange
                if target_id and target_id in active_peers and not active_peers[target_id]["ws"].closed:
                    payload["senderId"] = user_id
                    payload["senderUsername"] = username
                    await active_peers[target_id]["ws"].send_json(payload)
    finally:
        active_peers.pop(user_id, None)
        # Broadcast departure
        for pid, pdata in active_peers.items():
            if not pdata["ws"].closed:
                await pdata["ws"].send_json({"type": "peer-left", "id": user_id})

    return ws

# ----------------- APP INITIALIZATION -----------------

app = web.Application()
app.add_routes(routes)

if __name__ == '__main__':
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(CERT_FILE, CERT_KEY_FILE)

    port = int(os.getenv("PORT", 8080))
    host = os.getenv("HOST", "0.0.0.0")
    web.run_app(app, host=host, port=port, ssl_context=ssl_context)