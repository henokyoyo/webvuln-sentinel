"""
DDoS SENTINEL - Enterprise Edition
Real-Time Attack & Defense Simulation Platform
FastAPI Backend with WebSocket Support
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import time
import os
from datetime import datetime
from typing import Dict, List
import threading

# ========== APP INIT ==========
app = FastAPI(
    title="DDoS SENTINEL",
    description="Real-Time Attack & Defense Simulation Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== GLOBAL STATE ==========
class BattleState:
    def __init__(self):
        self.total_requests = 0
        self.current_rps = 0
        self.blocked_ips: set = set()
        self.connected_ips: Dict[str, dict] = {}
        self.alerts: List[dict] = []
        self.traffic_log: List[dict] = []
        self.attack_active = False
        self.request_times: List[float] = []
        self.lock = threading.Lock()
        self.active_websockets: List[WebSocket] = []

state = BattleState()

# ========== THREAT DETECTION ==========
def calculate_threat_level(rps: int) -> str:
    if rps > 100: return "CRITICAL"
    elif rps > 50: return "SUSPICIOUS"
    return "NORMAL"

def add_alert(message: str):
    state.alerts.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "message": message
    })
    if len(state.alerts) > 200:
        state.alerts.pop(0)

# ========== WEBSOCKET MANAGER ==========
async def broadcast_state():
    """Broadcast current state to all connected WebSocket clients"""
    disconnected = []
    for ws in state.active_websockets:
        try:
            with state.lock:
                ip_list = []
                for ip, data in state.connected_ips.items():
                    ip_list.append({
                        "ip": ip,
                        "rps": data["rps"],
                        "last_seen": data["last_seen"],
                        "blocked": ip in state.blocked_ips,
                        "is_attacker": data["rps"] > 30
                    })
                
                payload = {
                    "type": "state_update",
                    "data": {
                        "total_requests": state.total_requests,
                        "current_rps": state.current_rps,
                        "blocked_count": len(state.blocked_ips),
                        "blocked_ips": list(state.blocked_ips),
                        "connected_ips": ip_list,
                        "alerts": state.alerts[-30:],
                        "attack_active": state.attack_active,
                        "threat_level": calculate_threat_level(state.current_rps)
                    }
                }
            await ws.send_json(payload)
        except:
            disconnected.append(ws)
    
    for ws in disconnected:
        if ws in state.active_websockets:
            state.active_websockets.remove(ws)

# ========== ATTACK ENGINE ==========
def simulate_continuous_attack(threads: int):
    """Simulate continuous attack traffic"""
    import requests
    from concurrent.futures import ThreadPoolExecutor
    
    target = "http://127.0.0.1:8000"
    
    def send_request():
        while state.attack_active:
            try:
                requests.get(f"{target}/api/ping", timeout=0.3)
            except:
                pass
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(send_request) for _ in range(threads)]

# ========== API ROUTES ==========

@app.get("/api/ping")
async def ping(request: Request):
    """Endpoint that gets attacked - simulates target server"""
    client_ip = request.client.host
    
    with state.lock:
        state.total_requests += 1
        state.request_times.append(time.time())
        
        # Clean old entries
        cutoff = time.time() - 60
        state.request_times = [t for t in state.request_times if t > cutoff]
        state.current_rps = len(state.request_times)
        
        # Track IP
        if client_ip not in state.connected_ips:
            state.connected_ips[client_ip] = {"rps": 0, "last_seen": ""}
        state.connected_ips[client_ip]["rps"] = state.current_rps
        state.connected_ips[client_ip]["last_seen"] = datetime.now().strftime("%H:%M:%S")
        
        # Check if blocked
        if client_ip in state.blocked_ips:
            return JSONResponse(
                status_code=403,
                content={"status": "BLOCKED", "message": "Access Denied"}
            )
    
    return {"status": "OK", "timestamp": datetime.now().isoformat()}

@app.get("/api/stats")
async def get_stats():
    """Get current battle statistics"""
    with state.lock:
        return {
            "total_requests": state.total_requests,
            "current_rps": state.current_rps,
            "blocked_count": len(state.blocked_ips),
            "blocked_ips": list(state.blocked_ips),
            "attack_active": state.attack_active,
            "threat_level": calculate_threat_level(state.current_rps)
        }

@app.post("/api/attack/start")
async def start_attack(data: dict):
    """Start continuous attack"""
    global attack_thread
    
    mode = data.get("mode", "http_flood")
    threads = min(data.get("threads", 50), 500)
    
    state.attack_active = True
    add_alert(f"💥 ATTACK LAUNCHED: {mode} | {threads} threads | CONTINUOUS")
    
    attack_thread = threading.Thread(target=simulate_continuous_attack, args=(threads,))
    attack_thread.daemon = True
    attack_thread.start()
    
    await broadcast_state()
    return {"status": "ATTACK_LAUNCHED", "mode": mode, "threads": threads}

@app.post("/api/attack/stop")
async def stop_attack():
    """Stop attack"""
    state.attack_active = False
    add_alert("🛑 Attack stopped by attacker")
    await broadcast_state()
    return {"status": "ATTACK_STOPPED"}

@app.post("/api/defense/block")
async def block_ip(data: dict):
    """Block an IP address"""
    ip = data.get("ip")
    if ip:
        state.blocked_ips.add(ip)
        add_alert(f"🚫 BLOCKED: {ip}")
        await broadcast_state()
    return {"status": "BLOCKED", "ip": ip}

@app.post("/api/defense/unblock")
async def unblock_ip(data: dict):
    """Unblock an IP address"""
    ip = data.get("ip")
    if ip in state.blocked_ips:
        state.blocked_ips.remove(ip)
        add_alert(f"✅ UNBLOCKED: {ip}")
        await broadcast_state()
    return {"status": "UNBLOCKED", "ip": ip}

@app.get("/api/my-ip")
async def get_my_ip(request: Request):
    """Get client IP and blocked status"""
    client_ip = request.client.host
    return {
        "ip": client_ip,
        "blocked": client_ip in state.blocked_ips
    }

# ========== WEBSOCKET ENDPOINT ==========

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates"""
    await websocket.accept()
    state.active_websockets.append(websocket)
    
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in state.active_websockets:
            state.active_websockets.remove(websocket)

# ========== STATIC PAGES ==========

@app.get("/", response_class=HTMLResponse)
async def landing_page():
    """Landing page - Battle Station"""
    path = os.path.join("frontend", "pages", "index.html")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read()
    return "<h1>Create frontend/pages/index.html</h1>"

@app.get("/attack", response_class=HTMLResponse)
async def attacker_page():
    """Attacker dashboard"""
    path = os.path.join("frontend", "pages", "attacker.html")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read()
    return "<h1>Create frontend/pages/attacker.html</h1>"

@app.get("/defend", response_class=HTMLResponse)
async def defender_page():
    """Defender dashboard"""
    path = os.path.join("frontend", "pages", "defender.html")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read()
    return "<h1>Create frontend/pages/defender.html</h1>"

# ========== BROADCAST LOOP ==========
async def broadcast_loop():
    """Send updates to WebSocket clients every second"""
    while True:
        await broadcast_state()
        await asyncio.sleep(1)

@app.on_event("startup")
async def startup():
    """Start background tasks"""
    asyncio.create_task(broadcast_loop())
    print("""
╔══════════════════════════════════════════════════════╗
║        ⚔️  DDoS SENTINEL - ENTERPRISE EDITION       ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  🎯 LANDING:   http://localhost:8000                 ║
║  💥 ATTACKER:  http://localhost:8000/attack          ║
║  🛡️ DEFENDER:  http://localhost:8000/defend          ║
║                                                      ║
║  ⚡ WebSocket: ws://localhost:8000/ws                 ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
    """)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")