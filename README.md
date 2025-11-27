# 🕵️‍♂️ Hacker Reconnaissance System

### A Cloud-Deployed Cowrie Honeypot Threat Intelligence Dashboard

The **Hacker Reconnaissance System** is a full-stack cyber-threat monitoring platform built using the **Cowrie SSH/Telnet Honeypot**, **Flask**, and **Google Cloud Platform (GCP)**.
It captures attacker activity in real time, enriches IPs with external threat-intel APIs, and visualizes attack patterns through an interactive dashboard.

This project is designed for cybersecurity learning, SOC automation, and offensive security research.

---

## 🚀 Features

### 🧪 Honeypot-Based Reconnaissance

* Deployed **Cowrie Honeypot** on GCP to capture brute-force attacks and malicious commands.
* Logs attacker IPs, credentials, payload uploads, and executed commands.

### 🔎 Threat Intelligence Enrichment

* Integrates with **AbuseIPDB** to retrieve:

  * Abuse confidence scores
  * Total reports
  * Tor/Proxy status
  * ISP and domain reputation

* Integrates with **IPInfo** to fetch:

  * Geolocation
  * Country & city
  * Organization / ASN

### 📊 Web Dashboard (Flask)

* Real-time attack dashboard
* Attacker profiles and enriched intel
* Live system metrics (CPU, RAM, Disk, Network I/O)
* Reports page (Daily/Weekly summaries)
* System monitoring view

### 🔐 Authentication & Security

* Secure login using **Flask-Login**
* Password hashing (Werkzeug)
* Role-based dashboard access
* Local SQLite database for user management

### ⚙️ System-Level Insights

* CPU, memory, disk, uptime, network traffic, processes
  *(via `psutil`)*

### ⚡ Performance Enhancements

* API result caching using **Flask-Caching**
* Retry logic on external threat APIs
* Logging (debug, error, warning)

---

## 🏗 Project Architecture

```
+----------------------------+
|   Google Cloud VM (GCE)    |
+----------------------------+
             |
             v
+----------------------------+
|       Cowrie Honeypot     |
+----------------------------+
      |           |
      | Log Files | 
      v           |
+----------------------------+
|  log_parser.py (Custom)    |
+----------------------------+
             |
             v
+----------------------------+
|      Flask Backend         |
|  - API Integration         |
|  - Threat Enrichment       |
|  - System Metrics          |
+----------------------------+
             |
             v
+----------------------------+
|   Web Dashboard (HTML/JS)  |
+----------------------------+
```

---

## 📁 Project Structure

```
/project-root
│
├── app.py                   # Main Flask application
├── /database/database.db    # SQLite authentication DB
├── /templates/              # HTML UI templates
├── /src/                    # static assets
├── /scripts/log_parser.py   # Custom Cowrie log processor
├── README.md                # Project documentation
└── requirements.txt         # Python dependencies
```

---

## 🔧 Tech Stack

**Backend:** Flask, Python
**Database:** SQLite
**Security:** Cowrie Honeypot, AbuseIPDB, IPInfo
**Frontend:** HTML, Bootstrap
**System Tools:** psutil, subprocess
**Cloud:** Google Cloud Platform (GCE)
**Caching:** Flask-Caching

---

## 🛠 Installation & Setup

### 1️⃣ Clone the repo

```bash
git clone https://github.com/LAVAN-N/Hacker-Reconnaissance-System.git
cd Hacker-Reconnaissance-System
```

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Setup SQLite Database

```bash
python3 -c "from app import init_db; init_db()"
```

### 4️⃣ Configure API Keys

Edit `app.py`:

```python
ABUSEIPDB_API_KEY = "YOUR_KEY"
IPINFO_TOKEN = "YOUR_KEY"
```

### 5️⃣ Run Flask App

```bash
python3 app.py
```

Your dashboard will be available at:
👉 `http://localhost:5000`

---

## 🧪 Deploying Cowrie on GCP (Quick Guide)

1. Create a GCP Compute Engine VM (Ubuntu 22.04)
2. Open inbound ports (22, 2222, 2223)
3. Install dependencies
4. Clone Cowrie
5. Configure `cowrie.cfg`
6. Start the honeypot

Full deployment steps can be added on request.

---

## 📊 Dashboard Screenshots

```
src\Home.png
src\Settings.png
src\Dashboard.png
```

---

## 🔌 API Endpoints (Internal Use)

### System Status

```
GET /api/system-status
```

### Dashboard

```
GET /dashboard
```

### Authentication

```
POST /login  
GET  /logout
```

---

## 🧠 log_parser.py – Role in the System

This script reads Cowrie logs such as:

```
cowrie.json  
cowrie.log  
tty logs  
```

It extracts:

* IP addresses
* Username/password attempts
* Executed commands
* Session timestamps
* Payload uploads

Then converts raw logs → structured JSON → dashboard.

---

## 🛡 Security Notes

⚠️ Running a honeypot exposes your server to attackers.
It must be isolated from production systems.

Key protections:

* GCP firewall rules
* Limited access ports
* Read-only filesystem areas
* Non-root execution
* Network segmentation

---

## 👨‍💻 Author

**Lavanyan**
Cybersecurity & AI Developer
Feel free to connect or open issues in the repository.

---

## ⭐ Show Your Support

If this repo helped you, please ⭐ star it!
This boosts visibility and supports future development.

---

## 📜 License

MIT License – free for modification and commercial use.

---

## 🏁 Future Enhancements

* Machine learning risk scoring
* Live attack map (GeoJSON + Mapbox)
* Email/SMS alerting
* Graph-based intrusion correlation
* Elasticsearch + Kibana dashboards

---

**This project demonstrates real-world cybersecurity engineering, log forensics, API integration, and cloud deployment.**
