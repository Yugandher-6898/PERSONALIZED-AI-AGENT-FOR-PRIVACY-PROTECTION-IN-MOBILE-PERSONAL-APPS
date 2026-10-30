"""
Seed Data Script for Personalized AI Agent for Privacy Protection.
Pre-populates baseline devices, initial intercepted threat events,
student forensics, known CVE vulnerabilities, and blocked tracker telemetry.
"""

import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

import database
from ai_agent import PersonalizedPrivacyAIAgent

def populate_sample_data():
    database.init_db()
    conn = database.get_db_connection()
    cursor = conn.cursor()

    # 1. Register Devices
    devices = [
        ("dev-mobile-001", "Android (iQOO Z9x)", "ANDROID", "Android 14 (Funtouch OS)", "192.168.1.104", "SHIELDED"),
        ("dev-desktop-002", "Windows 11 Workstation", "WINDOWS", "Windows 11 23H2 (x64)", "192.168.1.108", "SHIELDED")
    ]
    for d in devices:
        cursor.execute("""
            INSERT OR REPLACE INTO devices (device_id, device_name, device_type, os_version, ip_address, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, d)
    conn.commit()
    conn.close()

    # 2. Pre-populate Baseline Threat Events & Forensics using AI Engine
    agent = PersonalizedPrivacyAIAgent()

    # Sample 1: WhatsApp Phishing
    sample1 = agent.analyze_content(
        channel="WHATSAPP",
        content="🎁 Festive Reward! You won ₹50,000 cash! Click link to claim: http://festival-reward-claim.online/claim.php"
    )
    sample1["event_data"]["id"] = "evt-wa-001"
    sample1["event_data"]["device_id"] = "dev-mobile-001"
    sample1["forensics_data"]["event_id"] = "evt-wa-001"
    database.insert_threat_event(sample1["event_data"], sample1["forensics_data"])

    # Sample 2: Deceptive UPI QR
    sample2 = agent.analyze_content(
        channel="UPI_QR",
        content="upi://pay?pa=fastpayouts.claim@fakeupi&pn=RefundAgent&am=25000.00&cu=INR&mode=02"
    )
    sample2["event_data"]["id"] = "evt-qr-002"
    sample2["event_data"]["device_id"] = "dev-mobile-001"
    sample2["forensics_data"]["event_id"] = "evt-qr-002"
    database.insert_threat_event(sample2["event_data"], sample2["forensics_data"])

    # Sample 3: Insecure APK Download
    sample3 = agent.analyze_content(
        channel="APK_DOWNLOAD",
        content="Download initiated for unverified APK: Express_Loan_Approved_v4.2.apk from third-party server.",
        artifact_name="Express_Loan_Approved_v4.2.apk"
    )
    sample3["event_data"]["id"] = "evt-apk-003"
    sample3["event_data"]["device_id"] = "dev-mobile-001"
    sample3["forensics_data"]["event_id"] = "evt-apk-003"
    database.insert_threat_event(sample3["event_data"], sample3["forensics_data"])

    # 3. Pre-populate CVE Vulnerabilities
    vulns = [
        {
            "id": "vuln-cve-001",
            "device_id": "dev-desktop-002",
            "software_name": "Google Chrome (Windows)",
            "installed_version": "v124.0.6367.60 (Outdated)",
            "patched_version": "v124.0.6367.201+",
            "cve_id": "CVE-2024-4671",
            "cvss_score": 8.8,
            "severity": "HIGH",
            "summary": "Use-after-free in Visuals rendering component allows a remote attacker to execute arbitrary code via a crafted HTML page.",
            "remediation_action": "Update Google Chrome to version 124.0.6367.201 or newer via Settings > About Google Chrome.",
            "status": "ACTIVE"
        },
        {
            "id": "vuln-cve-002",
            "device_id": "dev-desktop-002",
            "software_name": "WhatsApp Desktop (Windows)",
            "installed_version": "v2.2410.5 (Outdated)",
            "patched_version": "v2.2412.3+",
            "cve_id": "CVE-2024-31497",
            "cvss_score": 8.1,
            "severity": "HIGH",
            "summary": "Improper input validation in multimedia packet parser allows remote attackers to trigger memory corruption via malformed attachment.",
            "remediation_action": "Apply WhatsApp Desktop hotfix via Microsoft Store or auto-updater.",
            "status": "ACTIVE"
        },
        {
            "id": "vuln-cve-003",
            "device_id": "dev-mobile-001",
            "software_name": "Android System WebView (Android)",
            "installed_version": "v122.0.6261.64 (Outdated)",
            "patched_version": "v125.0.6422.52+",
            "cve_id": "CVE-2024-4947",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "summary": "Type confusion in V8 JavaScript engine allows remote attacker to escape webview sandbox and execute arbitrary native code.",
            "remediation_action": "Update Android System WebView via Google Play Store to eliminate zero-day exploit risk.",
            "status": "ACTIVE"
        }
    ]
    for v in vulns:
        database.record_vulnerability(v)

    # 4. Pre-populate Blocked Mobile App Trackers
    trackers = [
        {
            "id": "trk-001",
            "app_name": "Truecaller",
            "package_name": "com.truecaller",
            "telemetry_domain": "analytics.truecaller.com",
            "tracker_category": "Device Fingerprinting",
            "destination_ip": "104.18.22.45",
            "status": "BLOCKED"
        },
        {
            "id": "trk-002",
            "app_name": "PhonePe",
            "package_name": "com.phonepe.app",
            "telemetry_domain": "device-metrics.appsflyer.com",
            "tracker_category": "Advertising & Attribution",
            "destination_ip": "54.192.18.112",
            "status": "BLOCKED"
        },
        {
            "id": "trk-003",
            "app_name": "InShot Video Editor",
            "package_name": "com.camerasideas.instashot",
            "telemetry_domain": "log.umeng.com",
            "tracker_category": "Analytics & Diagnostics",
            "destination_ip": "140.205.140.204",
            "status": "BLOCKED"
        },
        {
            "id": "trk-004",
            "app_name": "Instagram",
            "package_name": "com.instagram.android",
            "telemetry_domain": "graph.facebook.com/telemetry",
            "tracker_category": "Location & Behavior Profiling",
            "destination_ip": "157.240.22.35",
            "status": "BLOCKED"
        },
        {
            "id": "trk-005",
            "app_name": "UC Browser",
            "package_name": "com.UCMobile.intl",
            "telemetry_domain": "track.ucweb.com",
            "tracker_category": "Background Data Harvesting",
            "destination_ip": "106.11.144.18",
            "status": "BLOCKED"
        }
    ]
    for t in trackers:
        database.insert_tracker_log(t)

    # 5. Initialize Profile
    database.get_or_create_profile("usr-yugandhar-01")

    print("[+] Seed data initialized successfully with realistic cybersecurity baselines.")

if __name__ == "__main__":
    populate_sample_data()
