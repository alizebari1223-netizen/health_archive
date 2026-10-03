# Health Directorate Employee Archive System - v3
## Setup & Network Guide

---

## Quick Start (Windows)

1. Double-click **run.bat**
2. Wait for "Starting server..." message
3. Open browser → go to **http://localhost:8000**
4. Login: **admin** / **admin1234**
5. **Change the password immediately** using the button in the sidebar

---

## Allow Other Computers on the Network to Connect

1. Run the server (step above)
2. The terminal will show your PC's IP address, e.g.:
   ```
   http://192.168.1.105:8000
   ```
3. On other computers, open a browser and go to that address
4. They will see the login screen

### Windows Firewall (one-time setup)
The first time you run the server, Windows may ask to allow network access.
Click **Allow** (or Allow on Private networks).

If it doesn't ask automatically:
- Open Windows Defender Firewall
- Click "Allow an app through firewall"
- Add Python and allow it on Private networks

---

## What's New in v3

| Feature | v2 | v3 |
|---|---|---|
| Server engine | Basic http.server | Flask + Waitress |
| Concurrent users | 1 at a time | 8 threads (expandable) |
| Brute-force protection | Rate limit only | 5 failed = 15 min lockout |
| Access logs | None | Saved to data/access.log |
| Network access | Localhost only | Full LAN support |
| DB writes | Atomic | Atomic + file locking |
| Security headers | Basic | Full (XSS, MIME, frame) |

---

## File Structure

```
health_archive_secure/
├── server.py          ← Main server (run this)
├── run.bat            ← Windows launcher
├── run.sh             ← Linux/Mac launcher
├── requirements.txt   ← Python packages needed
├── index.html         ← Web interface
├── css/
│   └── style.css
├── js/
│   ├── app.js
│   └── db.js
└── data/              ← Created automatically on first run
    ├── database.json  ← All employee records
    ├── auth.json      ← Login credentials (hashed)
    └── access.log     ← Who logged in, when
```

---

## Security Notes

- Data **never leaves your building** — everything is stored locally
- Passwords are hashed with SHA-256 (never stored in plain text)
- After 5 wrong password attempts, the IP is blocked for 15 minutes
- All access is logged to `data/access.log`
- Sessions expire automatically after 8 hours of inactivity

---

## Backup

Use the **Export Backup** button in the Settings tab regularly.
Store the backup file on a USB drive or external location.
