# 🛡️ CyberShield AI: Multi-Device Privacy & Security System
**Real-Life Laptop SOC & Live Mobile Privacy Guardian**
*Designed for Real-World Deployment across Laptop and Mobile Devices*

---

## 📌 Architecture Overview

This project provides a **real-life dual-system deployment**:
1. **Laptop SOC Desktop Application (`laptop_desktop_app/`):**
   - Monitors the mobile device in real-time over the local network (Wi-Fi / Hotspot).
   - Features **Dual Perspectives**:
     - **Normal Mode:** Live overview of paired mobile device(s), battery status, synced privacy score, incoming threat stream, and tracker radar.
     - **Student Mode (Laptop Exclusive):** Deep forensic inspection, MITRE ATT&CK mapping, Virtual Threat Sandbox (for safe payload detonation), CVE vulnerability auditor, and printable validation certificate.
   - **Native Desktop Launching:** Double-click [`CyberShield_Laptop.exe`](file:///C:/Users/gadup/Desktop/2.1%20ADD/AI%20GEN/laptop_desktop_app/CyberShield_Laptop.exe) or the desktop shortcut on your Windows desktop — zero black command prompt windows!

2. **Mobile Privacy Guardian (`mobile_app/`):**
   - Operates in **Normal Mode ONLY** (clean, personal, user-friendly privacy protection).
   - Features 4 on-device defense channels:
     - 💬 **WhatsApp & Message Phishing Guard:** Intercepts fraudulent URLs, electricity bill scams, and festive lottery traps.
     - 💳 **UPI QR Payment Scam Detector:** Identifies deceptive reverse-debit collect traps masquerading as refunds or cashbacks.
     - 📦 **APK & Permission Inspector:** Detects banking trojans (Anatsa/Cerberus) requesting excessive SMS & overlay permissions.
     - 📋 **Live Clipboard PII Shield:** Scrubs sensitive credit card numbers, Aadhaar numbers, and passwords from volatile buffers.
   - **Real-Time Telemetry Link:** As soon as an attack or suspicious input is evaluated on the phone, a real-time event packet is streamed to the Laptop SOC!

---

## 🚀 How to Run in Real Life

### Step 1: Open the Laptop SOC Dashboard
- Simply double-click **`CyberShield AI - Laptop SOC.lnk`** on your Desktop or run:
  [`CyberShield_Laptop.exe`](file:///C:/Users/gadup/Desktop/2.1%20ADD/AI%20GEN/CyberShield_Laptop.exe)
- The standalone application window will open immediately on your screen.

### Step 2: Connect Your Real Mobile Phone
1. Connect your smartphone to the **same Wi-Fi network** or **Laptop Mobile Hotspot**.
2. Click **"📲 Connect Real Phone (QR Code)"** in the top bar of the Laptop Dashboard (or open [`📱_INSTALL_MOBILE_APP.html`](file:///C:/Users/gadup/Desktop/2.1%20ADD/AI%20GEN/📱_INSTALL_MOBILE_APP.html)).
3. Scan the QR code using your phone camera, or type the URL:
   ```
   http://<YOUR-LAPTOP-IP>:8000/mobile
   ```
   *(e.g., `http://10.247.156.117:8000/mobile`)*

### Step 3: Install the Mobile App on Your Phone
- On your phone browser (Chrome/Safari), tap **"Install"** or open the browser menu (⋮) -> **"Add to Home Screen"** / **"Install App"**.
- An icon named **"CyberShield AI"** will be added to your mobile home screen.

### Step 4: Perform Real-Life Threat Scans
- On your phone, tap any test scenario in **WhatsApp Guard**, **UPI Guard**, **APK Scanner**, or **Clipboard Shield**.
- Notice the **instant red alert and audio feedback** that flashes in real time across the **Laptop SOC Dashboard**!
- Switch to **Student Mode** on your laptop to analyze the threat vector in the **Threat Sandbox**, inspect MITRE techniques, and test defense rules.

---

## 📂 Directory Structure

```
C:\Users\gadup\Desktop\2.1 ADD\AI GEN\
│
├── CyberShield_Laptop.exe          <-- Direct 64-bit Windows GUI Executable
├── 📱_INSTALL_MOBILE_APP.html      <-- Double-click to view Pairing QR Code & Guide
├── README.md                       <-- This Documentation
│
├── laptop_desktop_app\             <-- Laptop SOC System
│   ├── backend\                    <-- FastAPI, SQLite, AI Agent, Network Discovery
│   │   ├── app.py                  <-- Dual-route server binding on 0.0.0.0:8000
│   │   ├── database.py             <-- Persistence with device tracking
│   │   ├── ai_agent.py             <-- Dual-perspective heuristic & MITRE engine
│   │   ├── network_info.py         <-- Dynamic LAN Wi-Fi IP resolver
│   │   └── schema.sql              <-- Multi-device SQLite database schema
│   ├── desktop_ui\                 <-- Cyber SOC Dashboard (Normal & Student Modes)
│   ├── CyberShield_Laptop.exe      <-- Compiled standalone GUI launcher
│   └── run_backend.py              <-- Windowless background server runner
│
└── mobile_app\                     <-- Mobile Device System
    ├── web_pwa\                    <-- Standalone Progressive Web App (Normal Mode ONLY)
    │   ├── index.html              <-- Mobile-first UI
    │   ├── manifest.json           <-- 1-tap Home Screen Install Manifest
    │   ├── service-worker.js       <-- Offline & caching worker
    │   ├── css\mobile.css          <-- Touch-optimized cyber design
    │   └── js\mobile_agent.js      <-- Real-time telemetry sync & heuristic engine
    ├── android_project\            <-- Native Android / Capacitor packaging files
    └── INSTALL_MOBILE_APP.html     <-- Installation & pairing helper
```
