import subprocess
from datetime import datetime
import random
import psutil  # For system metrics
import time
import json
import logging
import requests
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_caching import Cache
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = "scW0b0LsjpWLfY43mBIUGfWjmElCAbX3yt1EgNGpAIB3BzehXxM3a/TIC85a8dwDcWShGuqm4zraAm0N1hY31t4AQY8bopOdHZo26zXfZcVR7UohVNnzL66d3tRNDlOf"  # Change this for production

# Flask Cache (prevents excessive API calls)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# AbuseIPDB API Key
ABUSEIPDB_API_KEY = "597a45ad837b3b01f18c40f2a04d1b895115b43675985fdecef05790afe8e39ec81701bdef810775"  # Replace with a valid API key

GEOLOCATION_API_URL = 'https://ipinfo.io/{ip}/json?token=b452ba3173f1a5'

# log_parser path
LOG_PARSER_SCRIPT = "/home/cowrie/scripts/log_parser.py"

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Database setup
DB_PATH = "database.db"

def init_db():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

class User(UserMixin):
    """User model for authentication."""
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

def run_log_parser():
    """Runs log_parser.py and retrieves parsed attack data."""
    try:
        result = subprocess.run(["python3", LOG_PARSER_SCRIPT], capture_output=True, text=True, check=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            logging.error(f"Log parser script failed: {result.stderr}")
            return []
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logging.error(f"Error running log_parser.py: {e}")
        return []

@cache.memoize(timeout=3600)  # Cache results for 1 hours
def check_abuseipdb(ip):
    """Checks if an IP is malicious using AbuseIPDB."""
    if not ip:
        return {}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    retries = 3
    for _ in range(retries):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                return response.json().get('data', {})
            elif response.status_code == 429:  # Rate limit exceeded
                time.sleep(2)  # Wait before retrying
                continue
            else:
                logging.error(f"AbuseIPDB API error: {response.status_code} - {response.text}")
                return {}
        except requests.RequestException as e:
            logging.error(f"AbuseIPDB API request failed: {e}")
            return {}
    return {}

@cache.memoize(timeout=300)  # Cache geolocation for 5 minutes
def get_geolocation(ip):
    """Fetches geolocation details based on an IP address."""
    if not ip:
        return {}

    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token=b452ba3173f1a5", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "Country": data.get("country", "Unknown"),
                "City": data.get("city", "Unknown"),
                "Latitude": data.get("lat", "N/A"),
                "Longitude": data.get("lon", "N/A"),
                "ISP": data.get("isp", "Unknown")
            }
        else:
            logging.error(f"GeoLocation API error: {response.status_code} - {response.text}")
            return {}
    except requests.RequestException as e:
        logging.error(f"GeoLocation API request failed: {e}")
        return {}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def index():
    return render_template('index.html')

reports = [
    {"id": 1, "type": "Daily", "date": "2023-10-10", "content": "Summary of daily attacks."},
    {"id": 2, "type": "Weekly", "date": "2023-10-09", "content": "Summary of weekly attacks."},
]

@app.route('/reports')
@login_required
def view_reports():
    return render_template('reports.html', reports=reports)

@app.route('/real-time-monitoring')
@login_required
def real_time_monitoring():
    return render_template('monitor.html')

@app.route('/system')
@login_required
def system_configuration():
    return render_template('system.html')

threat_data = [
    {"IP": "192.168.1.1", "Abuse Confidence": 85, "Total Reports": 10, "Threat Level": "⚠️ High"},
    {"IP": "10.0.0.1", "Abuse Confidence": 72, "Total Reports": 5, "Threat Level": "⚠️ High"},
    {"IP": "172.16.0.1", "Abuse Confidence": 60, "Total Reports": 8, "Threat Level": "✅ Low"},
    {"IP": "203.0.113.1", "Abuse Confidence": 45, "Total Reports": 3, "Threat Level": "✅ Low"},
]

@app.route('/threat-intel')
def threat_report():
    return render_template('threat_intel.html', threat_data=threat_data)

@app.route('/api/system-status')
@login_required
def system_status():
    # Simulate real system status data
    status = {
        "server":"Online",
        "security": "Secure",
        "network": random.choice(["Stable", "Unstable"])
    }
    status.update(get_system_metrics())
    return jsonify(status)

def get_system_metrics():
    """Fetch system metrics like CPU, memory, disk, and uptime."""
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')
    uptime_seconds = time.time() - psutil.boot_time()
    network_io = psutil.net_io_counters()
    active_processes = len(psutil.pids())
    return {
        "cpu_usage": cpu_usage,
        "memory_usage": memory_info.percent,
        "disk_usage": disk_usage.percent,
        "uptime": uptime_seconds,
	"network_traffic": {
            "sent": network_io.bytes_sent,
            "received": network_io.bytes_recv,
        },
        "active_processes": active_processes,
    }

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            login_user(User(user[0],user[1]))
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Renders the attack dashboard."""
    app.logger.debug("...Dashboard accessed...")
    attackers = run_log_parser()
    enriched_attackers = []
    for attacker in attackers:
        ip = attacker['IP']
        if not ip:
            app.logger.warning(f"Missing IP for attacker: {attacker}")
            continue

        app.logger.debug(f"Processing IP: {ip}")

        ip_info = check_abuseipdb(ip)  # Fetch AbuseIPDB data
        geo_info = get_geolocation(ip)  # Fetch geolocation data

        app.logger.debug(f"AbuseIPDB data: {ip_info}")
        app.logger.debug(f"Geolocation data: {geo_info}")

        # Enrich attacker data with AbuseIPDB and geolocation info
        attacker["Abuse Confidence"] = ip_info.get("abuseConfidenceScore", "N/A")
        attacker["ISP"] = ip_info.get("isp", "Unknown")
        attacker["Last Reported"] = ip_info.get("lastReportedAt", "N/A")
        attacker["Usage Type"] = ip_info.get("usageType", "Unknown")
        attacker["Total Reports"] = ip_info.get("totalReports", 0)
        attacker["Tor User"] = ip_info.get("isTor", "N/A")
        attacker["Domain"] = ip_info.get("domain", "N/A")
        # Add geolocation data
        attacker["City"] = geo_info.get("City", "Unknown")
        attacker["Country"] = geo_info.get("Country", "Unknown")
        enriched_attackers.append(attacker)

    return render_template('dashboard.html', attackers=enriched_attackers)

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
