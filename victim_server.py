from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime, timezone
import uvicorn

app = FastAPI(title="Victim Target Server")

# Application Request Logs
request_logs = []

def log_request(req: Request):
    """Saves details of every incoming request to a local array."""
    client_ip = req.client.host if req.client else "Unknown"
    log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": req.method,
        "path": req.url.path,
        "src_ip": client_ip,
        "user_agent": req.headers.get("user-agent", "Unknown")
    }
    request_logs.append(log)
    print(f"[VICTIM] {log['method']} {log['path']} from {log['src_ip']}")

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    log_request(request)
    response = await call_next(request)
    return response

# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    return "<html><body><h1>Welcome to Corporate Portal</h1><p>Internal network only.</p></body></html>"

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return '''
    <html>
      <body style="font-family: Arial;">
        <h2>Admin Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" /><br/><br/>
            <input type="password" name="password" placeholder="Password" /><br/><br/>
            <input type="submit" value="Login" />
        </form>
      </body>
    </html>
    '''

@app.post("/login")
def login_post():
    return JSONResponse(content={"error": "Invalid credentials", "success": False}, status_code=401)

@app.get("/admin")
def admin_panel():
    return JSONResponse(content={"error": "Forbidden: Requires Administrator privileges"}, status_code=403)

@app.get("/api/users")
def get_users():
    return JSONResponse(content={"data": [{"id": 1, "name": "Admin"}, {"id": 2, "name": "TestUser"}]})

@app.get("/api/data")
def get_data():
    return JSONResponse(content={"system_status": "Healthy", "database": "Connected", "version": "1.0.4"})

@app.get("/logs")
def fetch_logs():
    # Return the 100 most recent logs
    return request_logs[-100:][::-1]

if __name__ == "__main__":
    print("[*] Starting Victim Server on port 8080...")
    uvicorn.run("victim_server:app", host="0.0.0.0", port=8080, log_level="error", reload=False)
