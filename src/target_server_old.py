"""
DDoS Sentinel - Battle Station
Cyber Warfare Simulation Platform
"""

from flask import Flask, render_template_string, request, jsonify
import threading
import time
from datetime import datetime
import os

app = Flask(__name__)

# ========== GLOBAL DATA ==========
traffic_log = []
blocked_ips = set()
attack_alerts = []
connected_ips = {}
stats = {
    'total_requests': 0,
    'current_rps': 0,
    'blocked_count': 0
}
request_times = []
attack_active = False
attack_threads = []
lock = threading.Lock()

# ========== LANDING PAGE ==========
INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>DDoS Sentinel - Battle Station</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0f; color: #fff; font-family: 'Segoe UI', system-ui, sans-serif; height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { text-align: center; }
        h1 { font-size: 52px; font-weight: 900; margin-bottom: 5px; background: linear-gradient(135deg, #ff4444, #ff8800); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: #666; font-size: 14px; letter-spacing: 4px; text-transform: uppercase; margin-bottom: 50px; }
        .cards { display: flex; gap: 30px; justify-content: center; flex-wrap: wrap; }
        .card { border: 2px solid #222; border-radius: 16px; padding: 40px 30px; width: 280px; cursor: pointer; transition: all 0.3s; text-decoration: none; color: #fff; background: #111118; }
        .card:hover { transform: translateY(-5px); }
        .card.attack:hover { border-color: #ff4444; box-shadow: 0 0 40px rgba(255,68,68,0.3); }
        .card.defend:hover { border-color: #4488ff; box-shadow: 0 0 40px rgba(68,136,255,0.3); }
        .card-icon { font-size: 60px; margin-bottom: 20px; }
        .card h2 { font-size: 24px; margin-bottom: 10px; }
        .card p { color: #888; font-size: 13px; line-height: 1.6; }
        .card .btn { display: inline-block; margin-top: 20px; padding: 12px 30px; border-radius: 8px; font-weight: 700; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
        .btn-attack { background: #ff4444; color: #fff; }
        .btn-defend { background: #4488ff; color: #fff; }
        .footer { margin-top: 40px; color: #444; font-size: 11px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚔️ DDoS SENTINEL</h1>
        <p class="subtitle">Cyber Warfare Simulation Platform</p>
        <div class="cards">
            <a href="/attack" class="card attack">
                <div class="card-icon">💥</div>
                <h2>ATTACKER</h2>
                <p>Launch DDoS attacks against the target server. Choose your attack type and intensity.</p>
                <span class="btn btn-attack">JOIN ATTACK</span>
            </a>
            <a href="/defend" class="card defend">
                <div class="card-icon">🛡️</div>
                <h2>DEFENDER</h2>
                <p>Monitor traffic, detect attackers, and manually block malicious IPs in real-time.</p>
                <span class="btn btn-defend">JOIN DEFENSE</span>
            </a>
        </div>
        <p class="footer">Built for CRYPTEN • Cyber Defense Operations</p>
    </div>
</body>
</html>
'''

# ========== ATTACKER DASHBOARD ==========
ATTACK_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>💥 ATTACKER HQ - DDoS Sentinel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0005; color: #fff; font-family: 'Segoe UI', system-ui, sans-serif; padding: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #1a000a; }
        .header h1 { font-size: 32px; color: #ff4466; }
        .header .badge { background: #1a000a; border: 1px solid #ff4466; padding: 8px 16px; border-radius: 20px; font-size: 12px; color: #ff4466; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .panel { background: #0d0010; border: 1px solid #1a001a; border-radius: 12px; padding: 24px; }
        .panel h2 { font-size: 14px; color: #ff4466; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 20px; }
        .stat-big { font-size: 48px; font-weight: 900; color: #ff4466; }
        .stat-label { font-size: 11px; color: #661133; text-transform: uppercase; letter-spacing: 1px; }
        select, input { width: 100%; background: #0a0005; border: 1px solid #2a0a1a; color: #fff; padding: 12px; border-radius: 8px; font-size: 14px; margin-bottom: 10px; font-family: inherit; }
        select:focus, input:focus { outline: none; border-color: #ff4466; }
        button { width: 100%; padding: 14px; border: none; border-radius: 8px; font-size: 15px; font-weight: 700; cursor: pointer; text-transform: uppercase; letter-spacing: 1px; transition: all 0.3s; margin-bottom: 8px; }
        .btn-launch { background: #ff4466; color: #fff; }
        .btn-launch:hover { background: #ff2244; box-shadow: 0 0 30px rgba(255,68,102,0.5); }
        .btn-launch:disabled { background: #333; color: #666; cursor: not-allowed; box-shadow: none; }
        .btn-stop { background: transparent; border: 2px solid #ff4466; color: #ff4466; }
        .btn-stop:hover { background: #ff4466; color: #fff; }
        .progress-bar { height: 6px; background: #1a000a; border-radius: 3px; overflow: hidden; margin: 15px 0; }
        .progress-fill { height: 100%; background: #ff4466; width: 0%; transition: width 0.3s; }
        .blocked-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,0,0,0.95); z-index: 1000; align-items: center; justify-content: center; text-align: center; }
        .blocked-overlay.active { display: flex; }
        .blocked-overlay h1 { font-size: 64px; color: #000; margin-bottom: 20px; }
        .blocked-overlay p { font-size: 18px; color: #000; }
        .log-box { max-height: 300px; overflow-y: auto; font-size: 11px; color: #888; }
        .log-entry { padding: 6px 0; border-bottom: 1px solid #1a000a; font-family: 'Courier New', monospace; }
        .home-link { color: #ff4466; text-decoration: none; font-size: 12px; }
    </style>
</head>
<body>
    <div class="blocked-overlay" id="blocked-overlay">
        <div>
            <h1>🚫 BLOCKED!</h1>
            <p>Your IP has been blocked by the defender.</p>
            <p style="font-size:12px; margin-top:10px;">Attack stopped. Waiting for unblock...</p>
        </div>
    </div>

    <div class="header">
        <div>
            <h1>💥 ATTACKER HQ</h1>
            <a href="/" class="home-link">← Back to Battle Station</a>
        </div>
        <div class="badge" id="ip-badge">IP: Loading...</div>
    </div>

    <div class="grid">
        <div class="panel">
            <h2>⚡ ATTACK CONFIGURATION</h2>
            <label style="font-size:12px; color:#888;">Attack Mode</label>
            <select id="attack-mode">
                <option value="http_flood">HTTP Flood</option>
                <option value="slowloris">Slowloris Style</option>
                <option value="multi_page">Multi-Page Assault</option>
            </select>
            <label style="font-size:12px; color:#888;">Threads (Intensity)</label>
            <input type="number" id="threads" value="100" min="10" max="500">
            <button class="btn-launch" id="btn-launch" onclick="launchAttack()">💥 LAUNCH ATTACK</button>
            <button class="btn-stop" onclick="stopAttack()">🛑 STOP ATTACK</button>
        </div>
        <div class="panel">
            <h2>📊 ATTACK STATISTICS</h2>
            <div class="stat-big" id="attack-rps">0</div>
            <div class="stat-label">Requests Per Second</div>
            <br><br>
            <div class="stat-big" id="attack-total" style="font-size:32px;">0</div>
            <div class="stat-label">Total Requests Sent</div>
            <br><br>
            <div id="attack-status" style="font-size:14px; color:#00ff88;">● READY</div>
        </div>
    </div>

    <div class="panel">
        <h2>📈 ATTACK PROGRESS</h2>
        <div class="progress-bar">
            <div class="progress-fill" id="progress-fill"></div>
        </div>
        <div id="progress-text" style="text-align:center; font-size:12px; color:#888;">Waiting for launch command...</div>
    </div>

    <div class="panel">
        <h2>📋 MISSION LOG</h2>
        <div class="log-box" id="mission-log"></div>
    </div>

    <script>
        let attackRunning = false;
        let attackInterval = null;

        fetch('/api/my-ip').then(r => r.json()).then(d => {
            document.getElementById('ip-badge').textContent = 'IP: ' + d.ip;
        });

        function checkBlocked() {
            fetch('/api/blocked-status').then(r => r.json()).then(d => {
                let overlay = document.getElementById('blocked-overlay');
                if (d.blocked) {
                    overlay.classList.add('active');
                    if (attackRunning) stopAttack();
                } else {
                    overlay.classList.remove('active');
                }
            });
        }

        function launchAttack() {
            if (attackRunning) return;

            let mode = document.getElementById('attack-mode').value;
            let threads = parseInt(document.getElementById('threads').value);

            fetch('/api/attack', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({mode, threads, duration: 9999})
            }).then(r => r.json()).then(d => {
                attackRunning = true;
                document.getElementById('btn-launch').disabled = true;
                document.getElementById('attack-status').innerHTML = '🔴 ATTACKING';
                document.getElementById('attack-status').style.color = '#ff4466';
                addLog('💥 Attack launched: ' + mode + ' | ' + threads + ' threads');
                addLog('⚠️ Attack will continue until DEFENDER blocks you!');

                let startTime = Date.now();
                attackInterval = setInterval(() => {
                    let elapsed = Math.floor((Date.now() - startTime) / 1000);
                    document.getElementById('progress-text').textContent = 'Attacking for ' + elapsed + 's... (Continuous)';
                }, 1000);
            });
        }

        function stopAttack() {
            fetch('/api/stop-attack', {method: 'POST'}).then(r => r.json()).then(d => {
                attackRunning = false;
                document.getElementById('btn-launch').disabled = false;
                document.getElementById('attack-status').innerHTML = '● STOPPED';
                document.getElementById('attack-status').style.color = '#ffaa00';
                if (attackInterval) clearInterval(attackInterval);
                addLog('🛑 Attack stopped');
            });
        }

        function addLog(msg) {
            let log = document.getElementById('mission-log');
            let time = new Date().toLocaleTimeString();
            log.innerHTML = '<div class="log-entry">[' + time + '] ' + msg + '</div>' + log.innerHTML;
        }

        function updateStats() {
            fetch('/api/stats').then(r => r.json()).then(d => {
                document.getElementById('attack-rps').textContent = d.current_rps;
                document.getElementById('attack-total').textContent = d.total_requests;
            });
        }

        setInterval(checkBlocked, 1000);
        setInterval(updateStats, 1000);
    </script>
</body>
</html>
'''

# ========== DEFENDER DASHBOARD ==========
DEFEND_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ DEFENDER HQ - DDoS Sentinel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #000510; color: #fff; font-family: 'Segoe UI', system-ui, sans-serif; padding: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #0a1a2a; }
        .header h1 { font-size: 32px; color: #4488ff; }
        .header .badge { background: #0a1a2a; border: 1px solid #4488ff; padding: 8px 16px; border-radius: 20px; font-size: 12px; color: #4488ff; }
        .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: #0a1020; border: 1px solid #0a1a2a; border-radius: 12px; padding: 20px; text-align: center; }
        .stat-card h3 { font-size: 10px; color: #3366aa; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
        .stat-card .value { font-size: 40px; font-weight: 900; }
        .value-safe { color: #00ff88; }
        .value-warn { color: #ffaa00; }
        .value-danger { color: #ff4466; }
        .panel { background: #0a1020; border: 1px solid #0a1a2a; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
        .panel h2 { font-size: 14px; color: #4488ff; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 20px; }
        .ip-row { display: flex; justify-content: space-between; align-items: center; padding: 15px; border: 1px solid #0a1a2a; border-radius: 8px; margin-bottom: 10px; background: #080c18; }
        .ip-row.attacker { border-color: #ff4466; background: #0a0005; animation: pulse 2s infinite; }
        @keyframes pulse { 50% { border-color: #ff6688; } }
        .ip-row.blocked { opacity: 0.5; border-color: #333; }
        .ip-info .ip-addr { font-size: 16px; font-weight: 700; }
        .ip-info .ip-meta { font-size: 11px; color: #666; margin-top: 4px; }
        .btn-block { background: #ff4466; color: #fff; border: none; padding: 10px 24px; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }
        .btn-block:hover { background: #ff2244; box-shadow: 0 0 20px rgba(255,68,102,0.5); }
        .btn-unblock { background: #00cc66; color: #fff; border: none; padding: 10px 24px; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }
        .btn-unblock:hover { box-shadow: 0 0 20px rgba(0,204,102,0.5); }
        .alert-item { padding: 10px; margin: 5px 0; border-left: 3px solid #4488ff; background: #0a1020; font-size: 12px; }
        .alert-item.danger { border-left-color: #ff4466; background: #0a0005; }
        .alert-item.success { border-left-color: #00ff88; }
        .home-link { color: #4488ff; text-decoration: none; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ DEFENDER HQ</h1>
            <a href="/" class="home-link">← Back to Battle Station</a>
        </div>
        <div class="badge">THREAT MONITORING ACTIVE</div>
    </div>

    <div class="grid">
        <div class="stat-card">
            <h3>Total Requests</h3>
            <div class="value value-safe" id="total-requests">0</div>
        </div>
        <div class="stat-card">
            <h3>Current RPS</h3>
            <div class="value value-safe" id="current-rps">0</div>
        </div>
        <div class="stat-card">
            <h3>Blocked IPs</h3>
            <div class="value value-danger" id="blocked-count">0</div>
        </div>
    </div>

    <div class="panel">
        <h2>🌐 CONNECTED IPs — THREAT MONITOR</h2>
        <div id="ip-list">No connections detected</div>
    </div>

    <div class="panel">
        <h2>🚫 BLOCKED IPs</h2>
        <div id="blocked-list">No IPs currently blocked</div>
    </div>

    <div class="panel">
        <h2>⚠️ SECURITY ALERTS</h2>
        <div id="alert-feed" style="max-height:300px; overflow-y:auto;"></div>
    </div>

    <script>
        function updateDashboard() {
            fetch('/api/stats').then(r => r.json()).then(d => {
                document.getElementById('total-requests').textContent = d.total_requests;

                let rpsEl = document.getElementById('current-rps');
                rpsEl.textContent = d.current_rps;
                rpsEl.className = 'value ' + (d.current_rps > 100 ? 'value-danger' : d.current_rps > 30 ? 'value-warn' : 'value-safe');

                document.getElementById('blocked-count').textContent = d.blocked_count;

                if (d.connected_ips && d.connected_ips.length > 0) {
                    let html = '';
                    d.connected_ips.forEach(ip => {
                        let rowClass = ip.blocked ? 'ip-row blocked' : ip.is_attacker ? 'ip-row attacker' : 'ip-row';
                        let action = ip.blocked
                            ? '<button class="btn-unblock" onclick="unblockIP(\'' + ip.ip + '\')">UNBLOCK</button>'
                            : '<button class="btn-block" onclick="blockIP(\'' + ip.ip + '\')">BLOCK</button>';
                        html += '<div class="' + rowClass + '">'
                            + '<div class="ip-info">'
                            + '<div class="ip-addr">' + (ip.blocked ? '🚫 ' : ip.is_attacker ? '⚠️ ' : '✅ ') + ip.ip + '</div>'
                            + '<div class="ip-meta">RPS: ' + ip.rps + ' | Last seen: ' + ip.last_seen + (ip.is_attacker ? ' | THREAT DETECTED' : '') + '</div>'
                            + '</div>' + action + '</div>';
                    });
                    document.getElementById('ip-list').innerHTML = html;
                } else {
                    document.getElementById('ip-list').innerHTML = '<p style="color:#666;">No connections detected</p>';
                }

                if (d.blocked_ips && d.blocked_ips.length > 0) {
                    let html = '';
                    d.blocked_ips.forEach(ip => {
                        html += '<div class="ip-row blocked"><div class="ip-info"><div class="ip-addr">🚫 ' + ip + '</div><div class="ip-meta">BLOCKED</div></div><button class="btn-unblock" onclick="unblockIP(\'' + ip + '\')">UNBLOCK</button></div>';
                    });
                    document.getElementById('blocked-list').innerHTML = html;
                } else {
                    document.getElementById('blocked-list').innerHTML = '<p style="color:#666;">No IPs currently blocked</p>';
                }

                if (d.alerts && d.alerts.length > 0) {
                    let html = '';
                    d.alerts.slice(-20).reverse().forEach(a => {
                        let cls = a.message.includes('BLOCKED') ? 'danger' : a.message.includes('UNBLOCKED') ? 'success' : '';
                        html += '<div class="alert-item ' + cls + '">[' + a.time + '] ' + a.message + '</div>';
                    });
                    document.getElementById('alert-feed').innerHTML = html;
                }
            });
        }

        function blockIP(ip) {
            fetch('/api/block', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip})
            }).then(r => r.json()).then(() => updateDashboard());
        }

        function unblockIP(ip) {
            fetch('/api/unblock', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip})
            }).then(r => r.json()).then(() => updateDashboard());
        }

        setInterval(updateDashboard, 1000);
        updateDashboard();
    </script>
</body>
</html>
'''

# ========== ROUTES ==========

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/attack')
def attack():
    return render_template_string(ATTACK_HTML)

@app.route('/defend')
def defend():
    return render_template_string(DEFEND_HTML)

@app.route('/api/stats')
def api_stats():
    with lock:
        ip_list = []
        for ip, data in connected_ips.items():
            ip_list.append({
                'ip': ip,
                'rps': data['rps'],
                'last_seen': data['last_seen'],
                'blocked': ip in blocked_ips,
                'is_attacker': data['rps'] > 20
            })
        return jsonify({
            'total_requests': stats['total_requests'],
            'current_rps': stats['current_rps'],
            'blocked_count': len(blocked_ips),
            'blocked_ips': list(blocked_ips),
            'connected_ips': ip_list,
            'alerts': attack_alerts[-30:]
        })

@app.route('/api/my-ip')
def my_ip():
    return jsonify({'ip': request.remote_addr})

@app.route('/api/blocked-status')
def blocked_status():
    return jsonify({'blocked': request.remote_addr in blocked_ips, 'ip': request.remote_addr})

@app.route('/api/attack', methods=['POST'])
def api_attack():
    global attack_active
    data = request.json
    mode = data.get('mode', 'http_flood')
    threads = min(data.get('threads', 50), 500)
    
    attack_active = True
    t = threading.Thread(target=continuous_attack, args=(mode, threads))
    t.daemon = True
    t.start()
    attack_threads.append(t)
    
    add_alert(f'💥 Attack launched: {mode} | {threads} threads | CONTINUOUS')
    return jsonify({'status': 'ATTACK_LAUNCHED'})

@app.route('/api/stop-attack', methods=['POST'])
def api_stop_attack():
    global attack_active
    attack_active = False
    add_alert('🛑 Attack stopped by attacker')
    return jsonify({'status': 'STOPPED'})

@app.route('/api/block', methods=['POST'])
def api_block():
    ip = request.json.get('ip')
    if ip:
        blocked_ips.add(ip)
        add_alert(f'🚫 BLOCKED: {ip}')
        stats['blocked_count'] = len(blocked_ips)
    return jsonify({'status': 'BLOCKED'})

@app.route('/api/unblock', methods=['POST'])
def api_unblock():
    ip = request.json.get('ip')
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        add_alert(f'✅ UNBLOCKED: {ip}')
        stats['blocked_count'] = len(blocked_ips)
    return jsonify({'status': 'UNBLOCKED'})

# ========== CONTINUOUS ATTACK ENGINE ==========

def continuous_attack(mode, threads):
    global attack_active
    import requests
    from concurrent.futures import ThreadPoolExecutor
    
    target = 'http://127.0.0.1:5000'
    
    def send_request():
        while attack_active:
            if request.remote_addr in blocked_ips:
                break
            try:
                if mode == 'http_flood':
                    requests.get(f'{target}/', timeout=0.3)
                elif mode == 'slowloris':
                    requests.get(f'{target}/login', timeout=1)
                elif mode == 'multi_page':
                    import random
                    requests.get(f'{target}/{random.choice(["","about","login","admin"])}', timeout=0.3)
            except:
                pass
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(send_request) for _ in range(threads)]

# ========== DEFENSE ==========

def add_alert(message):
    attack_alerts.append({'time': datetime.now().strftime('%H:%M:%S'), 'message': message})
    if len(attack_alerts) > 200:
        attack_alerts.pop(0)

@app.before_request
def defense_monitor():
    if request.path.startswith('/api/') or request.path.startswith('/static/'):
        return
    
    client_ip = request.remote_addr
    
    with lock:
        stats['total_requests'] += 1
        request_times.append(time.time())
        
        cutoff = time.time() - 60
        while request_times and request_times[0] < cutoff:
            request_times.pop(0)
        
        stats['current_rps'] = len(request_times)
        
        if client_ip not in connected_ips:
            connected_ips[client_ip] = {'rps': 0, 'last_seen': ''}
        connected_ips[client_ip]['rps'] = stats['current_rps']
        connected_ips[client_ip]['last_seen'] = datetime.now().strftime('%H:%M:%S')
        
        if client_ip in blocked_ips:
            return '🚫 ACCESS DENIED', 403

# ========== START ==========

if __name__ == '__main__':
    print('''
╔══════════════════════════════════════════════════════╗
║        ⚔️  DDoS SENTINEL - BATTLE STATION           ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  🎯 LANDING:   http://localhost:5000                 ║
║                                                      ║
║  💥 ATTACKER:  http://localhost:5000/attack          ║
║     → Launch continuous DDoS attacks                 ║
║                                                      ║
║  🛡️ DEFENDER:  http://localhost:5000/defend          ║
║     → Monitor traffic & manually block IPs           ║
║                                                      ║
║  ⚡ Open BOTH in separate tabs and BATTLE!           ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
    ''')
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)