"""
Database layer for Personalized AI Agent for Privacy Protection in Mobile Personal Apps.
Provides SQLite persistence, queries, privacy score computation, and forensics tracking.
"""

import sqlite3
import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

DB_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DB_DIR / "privacy_agent.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

def get_db_connection():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    cursor.executescript(schema_sql)
    conn.commit()
    conn.close()

def get_privacy_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    # Active Threats
    cursor.execute("SELECT COUNT(*) FROM threat_events WHERE status != 'RESOLVED'")
    active_threats = cursor.fetchone()[0]

    # Trackers Blocked
    cursor.execute("SELECT COUNT(*) FROM trackers WHERE status = 'BLOCKED'")
    trackers_blocked = cursor.fetchone()[0]

    # Active Vulnerabilities
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'ACTIVE'")
    active_vulns = cursor.fetchone()[0]

    # Dynamic Privacy Score Calculation (100 Base)
    # Deductions:
    # - 5 points per active threat
    # - 4 points per unpatched CVE
    # - 1 point per tracker pressure (up to max 10 points)
    # Minimum score 20, Maximum 100
    deduction = (active_threats * 5) + (active_vulns * 4) + min(trackers_blocked, 10)
    score = max(20, min(100, 100 - deduction))

    if score >= 80:
        score_label = f"{score}/100 🟢"
        health_status = "Optimal Protection"
    elif score >= 60:
        score_label = f"{score}/100 🟡"
        health_status = "Moderate Attention Needed"
    else:
        score_label = f"{score}/100 🔴"
        health_status = "Critical Risk - Immediate Action Required"

    conn.close()
    return {
        "privacy_score": score,
        "score_display": score_label,
        "health_status": health_status,
        "active_threats_count": active_threats,
        "trackers_blocked_count": trackers_blocked,
        "unpatched_vulns_count": active_vulns,
        "agent_engine_status": "Active & Shielding"
    }

def get_all_devices() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_threat_events(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.*, 
               f.mitre_tactic, f.mitre_technique_id, f.mitre_technique_name,
               f.ioc_indicators, f.disassembly_payload, f.defensive_code, f.cwe_mapping
        FROM threat_events t
        LEFT JOIN student_forensics f ON t.id = f.event_id
        ORDER BY t.timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("ioc_indicators"):
            try:
                d["ioc_parsed"] = json.loads(d["ioc_indicators"])
            except Exception:
                d["ioc_parsed"] = d["ioc_indicators"]
        result.append(d)
    return result

def get_threat_student_forensics(event_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM student_forensics WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("ioc_indicators"):
        try:
            d["ioc_parsed"] = json.loads(d["ioc_indicators"])
        except Exception:
            d["ioc_parsed"] = d["ioc_indicators"]
    return d

def insert_threat_event(event_data: Any = None, forensics_data: Optional[Dict[str, Any]] = None, **kwargs):
    if isinstance(event_data, dict) and "threat_title" in event_data:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = dict(event_data)
        data.setdefault("timestamp", None)
        data.setdefault("content_snippet", "")
        cursor.execute("""
            INSERT OR REPLACE INTO threat_events (
                id, device_id, channel, threat_title, threat_category,
                risk_level, content_snippet, explanation_normal_what,
                explanation_normal_leak, explanation_normal_action,
                status, timestamp
            ) VALUES (
                :id, :device_id, :channel, :threat_title, :threat_category,
                :risk_level, :content_snippet, :explanation_normal_what,
                :explanation_normal_leak, :explanation_normal_action,
                :status, COALESCE(:timestamp, CURRENT_TIMESTAMP)
            )
        """, data)

        if forensics_data:
            f_data = dict(forensics_data)
            f_data["event_id"] = data["id"]
            f_data.setdefault("ioc_indicators", "")
            f_data.setdefault("disassembly_payload", "")
            f_data.setdefault("defensive_code", "")
            f_data.setdefault("cwe_mapping", "")
            cursor.execute("""
                INSERT OR REPLACE INTO student_forensics (
                    event_id, mitre_tactic, mitre_technique_id, mitre_technique_name,
                    ioc_indicators, disassembly_payload, defensive_code, cwe_mapping
                ) VALUES (
                    :event_id, :mitre_tactic, :mitre_technique_id, :mitre_technique_name,
                    :ioc_indicators, :disassembly_payload, :defensive_code, :cwe_mapping
                )
            """, f_data)

        conn.commit()
        conn.close()
        return data
    else:
        dev_id = kwargs.get("device_id") or (event_data if isinstance(event_data, str) else "dev-mobile-live")
        dev_name = kwargs.get("device_name", "Connected Device")
        chan = kwargs.get("channel", "WHATSAPP")
        sev = kwargs.get("severity", "HIGH")
        ttype = kwargs.get("threat_type", "Security Threat")
        snippet = kwargs.get("content_snippet", "")
        evid = kwargs.get("evidence")
        recom = kwargs.get("recommendation", "Neutralized by CyberShield")
        stat = kwargs.get("status", "INTERCEPTED")
        return insert_mobile_threat_report(
            device_id=dev_id,
            device_name=dev_name,
            channel=chan,
            severity=sev,
            threat_type=ttype,
            content_snippet=snippet,
            evidence=evid,
            recommendation=recom,
            status=stat
        )

def get_vulnerabilities() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilities ORDER BY status ASC, cvss_score DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def record_vulnerability(vuln_data: Dict[str, Any]):
    conn = get_db_connection()
    cursor = conn.cursor()
    data = dict(vuln_data)
    data.setdefault("detected_at", None)
    cursor.execute("""
        INSERT OR REPLACE INTO vulnerabilities (
            id, device_id, software_name, installed_version,
            patched_version, cve_id, cvss_score, severity,
            summary, remediation_action, status, detected_at
        ) VALUES (
            :id, :device_id, :software_name, :installed_version,
            :patched_version, :cve_id, :cvss_score, :severity,
            :summary, :remediation_action, :status, COALESCE(:detected_at, CURRENT_TIMESTAMP)
        )
    """, data)
    conn.commit()
    conn.close()

def resolve_vulnerability(vuln_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE vulnerabilities SET status = 'PATCHED' WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()

def get_tracker_logs(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM trackers ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def insert_tracker_log(tracker_data: Dict[str, Any]):
    conn = get_db_connection()
    cursor = conn.cursor()
    data = dict(tracker_data)
    data.setdefault("timestamp", None)
    data.setdefault("destination_ip", "")
    cursor.execute("""
        INSERT OR REPLACE INTO trackers (
            id, app_name, package_name, telemetry_domain,
            tracker_category, destination_ip, status, timestamp
        ) VALUES (
            :id, :app_name, :package_name, :telemetry_domain,
            :tracker_category, :destination_ip, :status, COALESCE(:timestamp, CURRENT_TIMESTAMP)
        )
    """, data)
    conn.commit()
    conn.close()

def get_or_create_profile(user_id: str = "usr-yugandhar-01") -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_profile WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        cursor.execute("""
            INSERT INTO user_profile (user_id, user_name, sensitivity_level, student_mode_enabled, last_defense_score)
            VALUES (?, 'Gadupudi Yugandhar', 'BALANCED', 0, 84)
        """, (user_id,))
        conn.commit()
        cursor.execute("SELECT * FROM user_profile WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
    conn.close()
    return dict(row)

def update_profile(user_id: str, sensitivity_level: str, student_mode_enabled: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE user_profile 
        SET sensitivity_level = ?, student_mode_enabled = ?
        WHERE user_id = ?
    """, (sensitivity_level, student_mode_enabled, user_id))
    conn.commit()
    conn.close()

def record_sandbox_run(scenario_id: str, rule_selected: str, score: int, verdict: str, terminal_log: str):
    import uuid
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sandbox_lab_runs (id, scenario_id, rule_selected, score, defense_verdict, terminal_log)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (run_id, scenario_id, rule_selected, score, verdict, terminal_log))
    conn.commit()
    conn.close()
    return run_id

def register_or_update_device(device_id: str, device_name: str, device_type: str = "ANDROID",
                              os_version: str = "Android 14", ip_address: str = "", status: str = "ONLINE",
                              battery_level: int = 85, privacy_score: int = 85, **kwargs):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO devices (device_id, device_name, device_type, os_version, ip_address, battery_level, privacy_score, status, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(device_id) DO UPDATE SET
            device_name=excluded.device_name,
            device_type=excluded.device_type,
            os_version=excluded.os_version,
            ip_address=excluded.ip_address,
            battery_level=excluded.battery_level,
            privacy_score=excluded.privacy_score,
            status='ONLINE',
            last_seen=CURRENT_TIMESTAMP
    """, (device_id, device_name, device_type, os_version, ip_address, battery_level, privacy_score, status))
    conn.commit()
    conn.close()
    return {"status": "SUCCESS", "device_id": device_id}

def insert_mobile_threat_report(device_id: str, device_name: str, channel: str,
                                severity: str, threat_type: str, content_snippet: str = "",
                                evidence: Any = None, recommendation: str = "", status: str = "INTERCEPTED", **kwargs):
    import uuid
    evt_id = f"evt-mob-{uuid.uuid4().hex[:6]}"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threat_events (
            id, device_id, channel, threat_title, threat_category,
            risk_level, content_snippet, explanation_normal_what,
            explanation_normal_leak, explanation_normal_action, status, timestamp
        ) VALUES (
            ?, ?, ?, ?, 'Mobile Real-Time Alert',
            ?, ?, ?,
            'Personal identifiers and session tokens targeted.',
            ?, ?, CURRENT_TIMESTAMP
        )
    """, (evt_id, device_id, channel, threat_type, severity, content_snippet,
          f"Real-time event intercepted on {device_name}.", recommendation or "Neutralized by CyberShield.", status))

    mitre_map = {
        "WHATSAPP": ("Initial Access", "T1566.002", "Spearphishing Link"),
        "UPI": ("Credential Access", "T1417", "Input Capture (Reverse Payment Trap)"),
        "APK": ("Execution", "T1407", "Download New Code at Runtime (Sideload Dropper)"),
        "CLIPBOARD": ("Collection", "T1414", "Clipboard Data Siphon")
    }
    tactic, tech_id, tech_name = mitre_map.get(channel, ("Defense Evasion", "T1036", "Masquerading"))
    cursor.execute("""
        INSERT INTO student_forensics (
            event_id, mitre_tactic, mitre_technique_id, mitre_technique_name,
            ioc_indicators, disassembly_payload, defensive_code, cwe_mapping
        ) VALUES (
            ?, ?, ?, ?,
            ?, ?, 'CyberShield.sanitizeBuffer() // Active Defensive Gate', 'CWE-200 / CWE-352'
        )
    """, (evt_id, tactic, tech_id, tech_name, json.dumps(evidence) if evidence else "{}", content_snippet))

    conn.commit()
    conn.close()
    return {
        "id": evt_id,
        "device_id": device_id,
        "device_name": device_name,
        "channel": channel,
        "severity": severity,
        "threat_type": threat_type,
        "content_snippet": content_snippet,
        "recommendation": recommendation,
        "status": status
    }

def insert_tracker(app_name: str, package_name: str, telemetry_domain: str,
                   tracker_category: str, destination_ip: str = "104.18.22.45",
                   status: str = "BLOCKED", device_id: str = ""):
    import uuid
    tid = f"trk-{uuid.uuid4().hex[:6]}"
    insert_tracker_log({
        "id": tid,
        "app_name": app_name,
        "package_name": package_name,
        "telemetry_domain": telemetry_domain,
        "tracker_category": tracker_category,
        "destination_ip": destination_ip,
        "status": status
    })
    return tid

# Convenience Aliases
get_devices = get_all_devices
get_recent_threats = get_threat_events
get_trackers = get_tracker_logs
get_profile = get_or_create_profile
