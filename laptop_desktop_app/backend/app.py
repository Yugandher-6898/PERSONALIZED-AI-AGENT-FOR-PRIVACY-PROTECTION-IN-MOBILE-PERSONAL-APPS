"""
CyberShield AI • Multi-Device Security & Privacy Monitoring Server
Serves:
1. Laptop SOC Virtual Defense & Forensic Console (Normal Mode + Student Mode)
2. Real-Time Mobile Device Privacy Guardian App (Normal Mode Only)
3. Bi-Directional WebSocket & REST Telemetry Synchronization
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
AI_GEN_ROOT = PROJECT_ROOT.parent

sys.path.insert(0, str(BACKEND_DIR))

import database
import seed_data
import network_info
from ai_agent import PersonalizedPrivacyAIAgent
from cve_scanner import scan_software_inventory

app = FastAPI(
    title="CyberShield AI • Multi-Device Privacy & Security Engine",
    version="3.0.0",
    description="Real-life mobile device monitoring & student forensic sandbox system."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ai_agent = PersonalizedPrivacyAIAgent()

# Paths
LAPTOP_STATIC_DIR = PROJECT_ROOT / "desktop_ui" / "static"
LAPTOP_TEMPLATES_DIR = PROJECT_ROOT / "desktop_ui" / "templates"
MOBILE_PWA_DIR = AI_GEN_ROOT / "mobile_app" / "web_pwa"

# Mount Static Directories
if LAPTOP_STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(LAPTOP_STATIC_DIR)), name="laptop_static")
if MOBILE_PWA_DIR.exists():
    app.mount("/mobile_static", StaticFiles(directory=str(MOBILE_PWA_DIR)), name="mobile_static")

# WebSocket Connection Manager for Laptop & Mobile fleets
class MultiDeviceConnectionManager:
    def __init__(self):
        self.laptop_connections: List[WebSocket] = []
        self.mobile_connections: List[WebSocket] = []

    async def connect_laptop(self, ws: WebSocket):
        await ws.accept()
        self.laptop_connections.append(ws)

    def disconnect_laptop(self, ws: WebSocket):
        if ws in self.laptop_connections:
            self.laptop_connections.remove(ws)

    async def connect_mobile(self, ws: WebSocket):
        await ws.accept()
        self.mobile_connections.append(ws)

    def disconnect_mobile(self, ws: WebSocket):
        if ws in self.mobile_connections:
            self.mobile_connections.remove(ws)

    async def broadcast_to_laptop(self, data: Dict[str, Any]):
        for ws in list(self.laptop_connections):
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect_laptop(ws)

    async def broadcast_to_mobile(self, data: Dict[str, Any]):
        for ws in list(self.mobile_connections):
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect_mobile(ws)

    async def broadcast_all(self, data: Dict[str, Any]):
        await self.broadcast_to_laptop(data)
        await self.broadcast_to_mobile(data)

manager = MultiDeviceConnectionManager()

# Pydantic Schemas
class DeviceRegisterRequest(BaseModel):
    device_id: str
    device_name: str
    device_type: str = "MOBILE"
    ip_address: Optional[str] = ""
    os_version: Optional[str] = "Android 14"
    battery_level: Optional[int] = 85
    privacy_score: Optional[int] = 85

class ThreatReportRequest(BaseModel):
    device_id: str = "dev-mobile-001"
    device_name: str = "Personal Mobile"
    channel: str = "WHATSAPP"
    severity: str = "CRITICAL"
    threat_type: str = "Phishing Link"
    content_snippet: str = ""
    artifact_name: Optional[str] = None
    evidence: Optional[Any] = None
    recommendation: str = ""
    status: str = "BLOCKED"

class AnalyzeRequest(BaseModel):
    channel: str = "WHATSAPP"
    content: str = ""
    artifact_name: Optional[str] = None
    device_id: str = "dev-mobile-001"

class SandboxEvalRequest(BaseModel):
    scenario_id: str = "WA_PHISH"
    rule_selected: str = "CSP_FORM_ACTION_RESTRICTION"

class TrackerRequest(BaseModel):
    app_name: str
    package_name: str
    telemetry_domain: str
    tracker_category: str
    destination_ip: Optional[str] = "104.18.22.45"
    status: str = "BLOCKED"
    device_id: str = "dev-mobile-001"

# Startup Event
@app.on_event("startup")
def startup_event():
    database.init_db()
    seed_data.populate_sample_data()
    # Register host laptop device
    database.register_or_update_device(
        device_id="dev-laptop-host",
        device_name="CyberShield SOC Workstation (Host Laptop)",
        device_type="LAPTOP",
        ip_address=network_info.get_local_ip(),
        os_version="Windows 11 Enterprise",
        battery_level=100,
        privacy_score=92
    )

# ==============================================================================
# UI Routes
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_laptop_dashboard():
    index_file = LAPTOP_TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Laptop UI not found")
    return FileResponse(str(index_file))

@app.get("/laptop", response_class=HTMLResponse)
async def serve_laptop_alias():
    return await serve_laptop_dashboard()

@app.get("/mobile", response_class=HTMLResponse)
async def serve_mobile_app():
    mobile_file = MOBILE_PWA_DIR / "index.html"
    if not mobile_file.exists():
        raise HTTPException(status_code=404, detail="Mobile App UI not found")
    return FileResponse(str(mobile_file))

# ==============================================================================
# Network & Pairing APIs
# ==============================================================================

@app.get("/api/v1/network/info")
def get_network_info():
    local_ip = network_info.get_local_ip()
    port = 8000
    mobile_url = f"http://{local_ip}:{port}/mobile"
    return {
        "local_ip": local_ip,
        "port": port,
        "mobile_url": mobile_url,
        "laptop_url": f"http://127.0.0.1:{port}",
        "pairing_instructions": f"Connect your phone to the same Wi-Fi / Hotspot and navigate to: {mobile_url}"
    }

@app.get("/api/v1/devices")
def list_devices():
    return database.get_devices()

@app.post("/api/v1/devices/register")
async def register_device(payload: DeviceRegisterRequest, request: Request):
    client_ip = payload.ip_address or (request.client.host if request.client else "")
    res = database.register_or_update_device(
        device_id=payload.device_id,
        device_name=payload.device_name,
        device_type=payload.device_type,
        ip_address=client_ip,
        os_version=payload.os_version,
        battery_level=payload.battery_level,
        privacy_score=payload.privacy_score
    )
    # Broadcast device registration event to Laptop SOC
    await manager.broadcast_to_laptop({
        "type": "DEVICE_CONNECTED",
        "device": {
            "device_id": payload.device_id,
            "device_name": payload.device_name,
            "device_type": payload.device_type,
            "ip_address": client_ip,
            "os_version": payload.os_version,
            "battery_level": payload.battery_level,
            "privacy_score": payload.privacy_score,
            "status": "ONLINE"
        }
    })
    return res

# ==============================================================================
# Threat Intelligence & AI Analysis APIs
# ==============================================================================

@app.get("/api/v1/stats")
def get_stats():
    return database.get_privacy_stats()

@app.get("/api/v1/threats")
def get_threats(limit: int = 30):
    return database.get_recent_threats(limit)

@app.post("/api/v1/threats/report")
async def report_threat(payload: ThreatReportRequest):
    # Save to SQLite
    event = database.insert_threat_event(
        device_id=payload.device_id,
        device_name=payload.device_name,
        channel=payload.channel,
        severity=payload.severity,
        threat_type=payload.threat_type,
        content_snippet=payload.content_snippet,
        artifact_name=payload.artifact_name or "",
        evidence=payload.evidence,
        recommendation=payload.recommendation,
        status=payload.status
    )
    # Recompute dynamic stats
    stats = database.get_privacy_stats()

    # Stream real-time threat alert to Laptop SOC
    await manager.broadcast_to_laptop({
        "type": "NEW_THREAT_EVENT",
        "threat": event,
        "stats": stats
    })
    return {"status": "RECORDED", "event": event, "stats": stats}

@app.post("/api/v1/analyze")
async def analyze_threat(payload: AnalyzeRequest):
    result = ai_agent.analyze_content(
        channel=payload.channel,
        content=payload.content,
        artifact_name=payload.artifact_name
    )
    # If a threat is detected, record and broadcast automatically
    if result.get("risk_level") in ("CRITICAL", "HIGH", "MEDIUM"):
        database.insert_threat_event(
            device_id=payload.device_id,
            device_name="Connected Mobile Device",
            channel=result["channel"],
            severity=result["risk_level"],
            threat_type=result["threat_title"],
            content_snippet=payload.content[:150],
            artifact_name=payload.artifact_name or "",
            evidence=result.get("student_mode_forensics", {}),
            recommendation=result.get("normal_mode_action", {}).get("recommended_step", "Block and delete immediately"),
            status="BLOCKED"
        )
        stats = database.get_privacy_stats()
        await manager.broadcast_to_laptop({
            "type": "NEW_THREAT_EVENT",
            "threat": result,
            "stats": stats
        })

    return result

@app.get("/api/v1/trackers")
def list_trackers(limit: int = 50):
    return database.get_trackers(limit)

@app.post("/api/v1/trackers/log")
async def log_tracker(payload: TrackerRequest):
    tid = database.insert_tracker(
        app_name=payload.app_name,
        package_name=payload.package_name,
        telemetry_domain=payload.telemetry_domain,
        tracker_category=payload.tracker_category,
        destination_ip=payload.destination_ip or "104.18.22.45",
        status=payload.status,
        device_id=payload.device_id
    )
    stats = database.get_privacy_stats()
    tracker_item = {
        "id": tid,
        "app_name": payload.app_name,
        "package_name": payload.package_name,
        "telemetry_domain": payload.telemetry_domain,
        "tracker_category": payload.tracker_category,
        "destination_ip": payload.destination_ip,
        "status": payload.status,
        "device_id": payload.device_id
    }
    await manager.broadcast_to_laptop({
        "type": "TRACKER_BLOCKED",
        "tracker": tracker_item,
        "stats": stats
    })
    return {"status": "RECORDED", "tracker_id": tid}

# ==============================================================================
# Student Sandbox & CVE APIs (Laptop Exclusive)
# ==============================================================================

@app.get("/api/v1/cve")
def list_cve():
    return database.get_vulnerabilities()

@app.post("/api/v1/cve/scan")
def scan_cve(request: Dict[str, Any]):
    device_id = request.get("device_id", "dev-mobile-001")
    return scan_software_inventory(device_id=device_id)

@app.post("/api/v1/sandbox/evaluate")
def evaluate_sandbox(payload: SandboxEvalRequest):
    rule = payload.rule_selected
    scenario = payload.scenario_id

    # Defensive evaluation matrix
    scenario_rules = {
        "WA_PHISH": {
            "effective": ["CSP_FORM_ACTION_RESTRICTION", "DNS_OVER_HTTPS_PHISH_SINK"],
            "title": "WhatsApp Phishing Credential Extractor Attack"
        },
        "UPI_DECEPTIVE_QR": {
            "effective": ["UPI_VPA_WHITELIST_VALIDATOR", "PAYMENT_INTENT_CONFIRMATION_SHIELD"],
            "title": "Deceptive UPI Collect Request QR Injection"
        },
        "APK_TROJAN": {
            "effective": ["STATIC_DEX_HEURISTIC_PARSER", "PERMISSION_OVERPRIVILEGE_GATE"],
            "title": "Banking Trojan Overprivileged Dropper (Anatsa/Cerberus)"
        },
        "CLIPBOARD_PII": {
            "effective": ["AUTOMATIC_CLIPBOARD_EPHEMERAL_SCRUB", "REGEX_PII_DATA_MASKING"],
            "title": "PII Clipboard Siphon Exploit (Aadhaar & Card Scraping)"
        }
    }

    sc_info = scenario_rules.get(scenario, {
        "effective": ["CSP_FORM_ACTION_RESTRICTION"],
        "title": "Simulated Cyber Attack"
    })

    if rule in sc_info["effective"]:
        score = 95
        verdict = "DEFENSE_SUCCESSFUL"
        log = (
            f"[+] Countermeasure '{rule}' activated successfully.\n"
            f"[+] Threat vector neutralized before payload execution.\n"
            f"[+] Zero sensitive tokens leaked. Exploit mitigated at gateway boundary."
        )
    else:
        score = 25
        verdict = "DEFENSE_BYPASSED"
        log = (
            f"[-] Countermeasure '{rule}' proved ineffective against {sc_info['title']}.\n"
            f"[!] Rule failed to restrict the targeted exploit mechanism.\n"
            f"[!] Recommended rule: {sc_info['effective'][0]}"
        )

    run_id = database.record_sandbox_run(scenario, rule, score, verdict, log)
    return {
        "run_id": run_id,
        "scenario_id": scenario,
        "rule_selected": rule,
        "score": score,
        "verdict": verdict,
        "terminal_log": log
    }

@app.get("/api/v1/profile")
def get_user_profile():
    return database.get_profile()

@app.post("/api/v1/profile")
def update_user_profile(data: Dict[str, Any]):
    database.update_profile(
        user_id=data.get("user_id", "usr-yugandhar-01"),
        sensitivity_level=data.get("sensitivity_level", "BALANCED"),
        student_mode_enabled=data.get("student_mode_enabled", 1)
    )
    return {"status": "SUCCESS"}

# ==============================================================================
# WebSockets: Real-Time Laptop SOC & Mobile Sync
# ==============================================================================

@app.websocket("/ws/laptop")
async def websocket_laptop_endpoint(websocket: WebSocket):
    await manager.connect_laptop(websocket)
    try:
        # Send initial status snapshot
        await websocket.send_json({
            "type": "INITIAL_SNAPSHOT",
            "stats": database.get_privacy_stats(),
            "devices": database.get_devices(),
            "recent_threats": database.get_recent_threats(15),
            "trackers": database.get_trackers(15)
        })
        while True:
            data = await websocket.receive_text()
            # Handle commands from Laptop SOC
            try:
                msg = json.loads(data)
                if msg.get("action") == "PING":
                    await websocket.send_json({"type": "PONG"})
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect_laptop(websocket)

@app.websocket("/ws/mobile")
async def websocket_mobile_endpoint(websocket: WebSocket):
    await manager.connect_mobile(websocket)
    try:
        await websocket.send_json({
            "type": "MOBILE_INIT",
            "status": "CONNECTED_TO_SOC",
            "stats": database.get_privacy_stats()
        })
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                mtype = msg.get("type")

                # Mobile Heartbeat
                if mtype == "HEARTBEAT":
                    database.register_or_update_device(
                        device_id=msg.get("device_id", "dev-mobile-live"),
                        device_name=msg.get("device_name", "Real Mobile Client"),
                        device_type="MOBILE",
                        ip_address=msg.get("ip_address", ""),
                        os_version=msg.get("os_version", "Android 14"),
                        battery_level=msg.get("battery_level", 85),
                        privacy_score=msg.get("privacy_score", 85)
                    )
                    await manager.broadcast_to_laptop({
                        "type": "MOBILE_HEARTBEAT",
                        "device_id": msg.get("device_id"),
                        "battery_level": msg.get("battery_level"),
                        "privacy_score": msg.get("privacy_score")
                    })

                # Mobile Live Threat Triggered
                elif mtype == "MOBILE_THREAT_DETECTED":
                    threat = msg.get("threat", {})
                    evt = database.insert_threat_event(
                        device_id=msg.get("device_id", "dev-mobile-live"),
                        device_name=msg.get("device_name", "Real Mobile Client"),
                        channel=threat.get("channel", "WHATSAPP"),
                        severity=threat.get("severity", "CRITICAL"),
                        threat_type=threat.get("threat_type", "Mobile Malicious Intent"),
                        content_snippet=threat.get("content_snippet", "")[:150],
                        artifact_name=threat.get("artifact_name", ""),
                        evidence=threat.get("evidence"),
                        recommendation=threat.get("recommendation", "Neutralized on device"),
                        status="BLOCKED"
                    )
                    stats = database.get_privacy_stats()
                    # Stream to Laptop SOC immediately
                    await manager.broadcast_to_laptop({
                        "type": "NEW_THREAT_EVENT",
                        "threat": evt,
                        "stats": stats
                    })
                    # Confirm back to mobile
                    await websocket.send_json({
                        "type": "THREAT_SYNCED",
                        "event_id": evt["id"],
                        "stats": stats
                    })

            except Exception as e:
                print(f"[!] WebSocket mobile error: {e}", file=sys.stderr)
    except WebSocketDisconnect:
        manager.disconnect_mobile(websocket)
