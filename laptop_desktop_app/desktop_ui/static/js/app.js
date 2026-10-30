/**
 * CyberShield • Personalized AI Agent for Privacy Protection
 * Enterprise Desktop Console Controller & Real-Time Sync Engine
 */

// Application State
const state = {
    currentMode: "NORMAL", // "NORMAL" or "STUDENT"
    activeScenario: "WA_PHISH",
    selectedRule: "CSP_FORM_ACTION_RESTRICTION",
    labPolicy: "CSP_POLICY",
    activeTeam: "BLUE",
    defenseScore: 84,
    threatEvents: [],
    vulnerabilities: [],
    trackers: [],
    activePhoneApp: "whatsapp",
    filterThreats: "ALL",
    soundEnabled: true,
    animStep: 1,
    animPlaying: false,
    animInterval: null,
    ws: null
};

// API Base URL
const API_BASE = window.location.origin;

// ==============================================================================
// 1. SOUND ENGINE (WEB AUDIO API)
// ==============================================================================
let audioCtx = null;

function getAudioContext() {
    if (!audioCtx) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) audioCtx = new AudioContext();
    }
    if (audioCtx && audioCtx.state === "suspended") {
        audioCtx.resume();
    }
    return audioCtx;
}

function playSound(type) {
    if (!state.soundEnabled) return;
    try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;

        if (type === "alert") {
            // Cyber Alert Sound (Two-tone high-tech warning)
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "sawtooth";
            osc.frequency.setValueAtTime(587, now); // D5
            osc.frequency.setValueAtTime(880, now + 0.12); // A5
            gain.gain.setValueAtTime(0.12, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.35);
        } else if (type === "success") {
            // Success Chime (Pleasant rising chord)
            const freqs = [523.25, 659.25, 783.99, 1046.50]; // C5, E5, G5, C6
            freqs.forEach((f, i) => {
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = "sine";
                osc.frequency.setValueAtTime(f, now + i * 0.07);
                gain.gain.setValueAtTime(0.08, now + i * 0.07);
                gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.07 + 0.3);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start(now + i * 0.07);
                osc.stop(now + i * 0.07 + 0.3);
            });
        } else if (type === "blip") {
            // Subtle Terminal Keystroke Blip
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "triangle";
            osc.frequency.setValueAtTime(1200, now);
            gain.gain.setValueAtTime(0.04, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.04);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.04);
        } else if (type === "click") {
            // Tactile Click
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = "sine";
            osc.frequency.setValueAtTime(440, now);
            gain.gain.setValueAtTime(0.05, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.05);
        }
    } catch (e) {
        // Fallback silently if audio blocked
    }
}

// ==============================================================================
// 2. INITIALIZATION
// ==============================================================================
document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initStartupModal();
    initSoundToggle();
    initModeSwitcher();
    initTabs();
    initThreatFilters();
    initPhoneAppSwitcher();
    initSimulationButtons();
    initCustomPayloadAnalyzer();
    initSandboxLab();
    initVirtualLab();
    initCertificateModal();
    initSocTerminal();
    initMobilePairingModal();

    // Load initial data
    loadAllData();

    // Connect WebSocket
    connectWebSocket();
});

// Update Clock
function initClock() {
    const clockEl = document.getElementById("phone-clock");
    const updateTime = () => {
        const now = new Date();
        const hrs = String(now.getHours()).padStart(2, "0");
        const mins = String(now.getMinutes()).padStart(2, "0");
        if (clockEl) clockEl.textContent = `${hrs}:${mins}`;
    };
    updateTime();
    setInterval(updateTime, 30000);
}

// Startup Welcome Modal
function initStartupModal() {
    const modal = document.getElementById("startup-welcome-modal");
    const btnEnter = document.getElementById("btn-enter-dashboard");

    if (btnEnter && modal) {
        btnEnter.addEventListener("click", () => {
            playSound("click");
            modal.style.display = "none";
        });
    }
}

// Sound Toggle
function initSoundToggle() {
    const btn = document.getElementById("btn-toggle-sound");
    if (!btn) return;
    btn.addEventListener("click", () => {
        state.soundEnabled = !state.soundEnabled;
        btn.textContent = state.soundEnabled ? "🔊 Sound: ON" : "🔇 Sound: OFF";
        if (state.soundEnabled) playSound("success");
    });
}

// ==============================================================================
// 3. MODE SWITCHER (NORMAL VS. STUDENT FORENSICS)
// ==============================================================================
function initModeSwitcher() {
    const btnNormal = document.getElementById("top-btn-normal");
    const btnStudent = document.getElementById("top-btn-student");
    const sandboxTabBtn = document.getElementById("tab-btn-sandbox");

    function setMode(mode) {
        state.currentMode = mode;
        playSound("click");
        if (mode === "NORMAL") {
            btnNormal.className = "mode-toggle-btn active-normal";
            btnStudent.className = "mode-toggle-btn";
            if (sandboxTabBtn) sandboxTabBtn.style.display = "none";
            if (sandboxTabBtn && sandboxTabBtn.classList.contains("active")) {
                switchTab("pane-threats");
            }
        } else {
            btnNormal.className = "mode-toggle-btn";
            btnStudent.className = "mode-toggle-btn active-student";
            if (sandboxTabBtn) sandboxTabBtn.style.display = "inline-block";
        }
        renderThreatCards();
    }

    if (btnNormal) btnNormal.addEventListener("click", () => setMode("NORMAL"));
    if (btnStudent) btnStudent.addEventListener("click", () => setMode("STUDENT"));

    // Default: Normal Mode
    setMode("NORMAL");
}

// ==============================================================================
// 4. TAB CONTROLLER
// ==============================================================================
function initTabs() {
    const tabButtons = document.querySelectorAll(".console-tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetPaneId = btn.getAttribute("data-tab");
            if (targetPaneId) {
                playSound("click");
                switchTab(targetPaneId);
            }
        });
    });
}

function switchTab(targetPaneId) {
    document.querySelectorAll(".console-tab-btn").forEach(btn => {
        if (btn.getAttribute("data-tab") === targetPaneId) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    document.querySelectorAll(".tab-pane").forEach(pane => {
        if (pane.id === targetPaneId) {
            pane.classList.add("active");
        } else {
            pane.classList.remove("active");
        }
    });
}

// Threat Filter Strip
function initThreatFilters() {
    document.querySelectorAll(".btn-filter").forEach(btn => {
        btn.addEventListener("click", () => {
            playSound("click");
            document.querySelectorAll(".btn-filter").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            state.filterThreats = btn.getAttribute("data-filter");
            renderThreatCards();
        });
    });
}

// ==============================================================================
// 5. PHONE APP SWITCHER (WHATSAPP, UPI, APK, CLIPBOARD)
// ==============================================================================
function initPhoneAppSwitcher() {
    document.querySelectorAll(".app-switch-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            playSound("click");
            document.querySelectorAll(".app-switch-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const app = btn.getAttribute("data-app");
            state.activePhoneApp = app;
            renderPhoneAppView(app);
        });
    });
}

function renderPhoneAppView(app) {
    const viewport = document.getElementById("phone-app-viewport");
    if (!viewport) return;

    if (app === "whatsapp") {
        viewport.innerHTML = `
            <div class="chat-app-header">
                <div class="chat-avatar">💬</div>
                <div class="chat-info">
                    <h5 id="phone-chat-sender">+91 98480 22319</h5>
                    <span>WhatsApp &bull; Encrypted Channel</span>
                </div>
            </div>
            <div class="phone-screen-body" id="phone-chat-screen">
                <div class="chat-bubble incoming">
                    🎁 Festive Reward! You won ₹50,000 cash! Click link to claim:
                    <br><a class="fake-link" href="#" onclick="return false;">http://festival-reward-claim.online/claim.php</a>
                </div>
                <div class="agent-intercept-badge">
                    <strong>🛡️ CYBERSHIELD AGENT ACTIVE</strong><br>
                    🚨 Suspicious Phishing Link Blocked before Webview launch.
                </div>
            </div>
        `;
    } else if (app === "upi") {
        viewport.innerHTML = `
            <div class="chat-app-header" style="background: #1e3a8a;">
                <div class="chat-avatar" style="background: #2563eb;">💳</div>
                <div class="chat-info">
                    <h5>GPay / PhonePe Scanner</h5>
                    <span>Instant Payment Channel</span>
                </div>
            </div>
            <div class="phone-screen-body">
                <div style="background: #1e293b; border-radius: 12px; padding: 14px; border: 1px solid #334155;">
                    <div style="font-size: 0.72rem; color: #94a3b8;">SCANNED MERCHANT QR CODE:</div>
                    <div style="font-size: 1.05rem; font-weight: 700; color: #fff; margin-top: 4px;">FastPayouts Express (Mule VPA)</div>
                    <div style="font-size: 0.82rem; color: #f59e0b; margin-top: 2px;">Requested Debit Amount: ₹25,000.00</div>
                </div>
                <div class="agent-intercept-badge">
                    <strong>🚨 REVERSE DEBIT TRAP DETECTED</strong><br>
                    You were promised money, but this QR code will DEBIT ₹25,000 from your account! Remember: You NEVER enter UPI PIN to receive money.
                </div>
            </div>
        `;
    } else if (app === "apk") {
        viewport.innerHTML = `
            <div class="chat-app-header" style="background: #0f172a;">
                <div class="chat-avatar" style="background: #334155;">📦</div>
                <div class="chat-info">
                    <h5>Package Installer</h5>
                    <span>System Sideload Audit</span>
                </div>
            </div>
            <div class="phone-screen-body">
                <div style="background: #1e293b; border-radius: 12px; padding: 14px; border: 1px solid #334155;">
                    <strong style="color: #fff; font-size: 0.95rem;">Express_Loan_Approved_v4.2.apk</strong>
                    <div style="font-size: 0.75rem; color: #ef4444; margin-top: 4px;">Source: Unverified Third-Party Server (185.220.101.5)</div>
                    <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 6px;">Requested Permissions:
                        <ul style="margin-left: 16px; margin-top: 4px; color: #fca5a5;">
                            <li>android.permission.RECEIVE_SMS</li>
                            <li>android.permission.RECORD_AUDIO</li>
                        </ul>
                    </div>
                </div>
                <div class="agent-intercept-badge">
                    <strong>🚨 SIDELOAD BLOCKED BY CYBERSHIELD</strong><br>
                    Identified as Banking Trojan SMS Stealer (MITRE T1406). Installation aborted safely.
                </div>
            </div>
        `;
    } else if (app === "clipboard") {
        viewport.innerHTML = `
            <div class="chat-app-header" style="background: #1e293b;">
                <div class="chat-avatar" style="background: #475569;">📋</div>
                <div class="chat-info">
                    <h5>System Clipboard Monitor</h5>
                    <span>Background PII Shield</span>
                </div>
            </div>
            <div class="phone-screen-body">
                <div style="background: #1e293b; border-radius: 12px; padding: 14px; border: 1px solid #334155;">
                    <span style="font-size: 0.72rem; color: #94a3b8;">DETECTED CLIPBOARD BUFFER:</span>
                    <div style="font-family: var(--font-code); font-size: 0.8rem; color: #38bdf8; margin-top: 4px;">
                        5421 9801 4329 (Aadhaar)<br>OTP Token: 894120
                    </div>
                </div>
                <div class="agent-intercept-badge" style="border-color: #10b981; color: #6ee7b7; background: rgba(16, 185, 129, 0.15);">
                    <strong>🛡️ CLIPBOARD AUTO-SANITIZED</strong><br>
                    Volatile buffer cleared before background third-party applications could read your authentication secret.
                </div>
            </div>
        `;
    }
}

// ==============================================================================
// 6. DATA FETCHING & WEBSOCKET
// ==============================================================================
async function loadAllData() {
    await Promise.all([
        fetchStats(),
        fetchThreats(),
        fetchVulnerabilities(),
        fetchTrackers()
    ]);
}

async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/stats`);
        if (!res.ok) return;
        const data = await res.json();
        updateStatsUI(data);
    } catch (err) {
        console.error("Error fetching stats:", err);
    }
}

function updateStatsUI(stats) {
    const scoreNumEl = document.getElementById("stat-score-num");
    const scoreEl = document.getElementById("stat-score");
    const threatsEl = document.getElementById("stat-threats-count");
    const trackersEl = document.getElementById("stat-trackers-count");
    const vulnsEl = document.getElementById("stat-vulns-count");
    const engineEl = document.getElementById("stat-engine-status");

    if (scoreNumEl && stats.privacy_score !== undefined) scoreNumEl.textContent = stats.privacy_score;
    if (scoreEl && stats.score_display) scoreEl.textContent = stats.score_display;
    if (threatsEl && stats.active_threats_count !== undefined) threatsEl.textContent = stats.active_threats_count;
    if (trackersEl && stats.trackers_blocked_count !== undefined) trackersEl.textContent = stats.trackers_blocked_count;
    if (vulnsEl && stats.unpatched_vulns_count !== undefined) vulnsEl.textContent = stats.unpatched_vulns_count;
    if (engineEl && stats.agent_engine_status) engineEl.textContent = stats.agent_engine_status;
}

async function fetchThreats() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/threats`);
        if (!res.ok) return;
        state.threatEvents = await res.json();
        renderThreatCards();
    } catch (err) {
        console.error("Error fetching threats:", err);
    }
}

async function fetchVulnerabilities() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/vulnerabilities`);
        if (!res.ok) return;
        state.vulnerabilities = await res.json();
        renderVulnTable();
    } catch (err) {
        console.error("Error fetching vulnerabilities:", err);
    }
}

async function fetchTrackers() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/trackers`);
        if (!res.ok) return;
        state.trackers = await res.json();
        renderTrackerTable();
    } catch (err) {
        console.error("Error fetching trackers:", err);
    }
}

}

function initMobilePairingModal() {
    const btnOpen = document.getElementById("btn-open-pairing-modal");
    const modal = document.getElementById("mobile-pairing-modal");
    const btnClose = document.getElementById("btn-close-pairing-modal");

    if (btnOpen && modal) {
        btnOpen.addEventListener("click", () => {
            playSound("click");
            modal.style.display = "flex";
            fetchNetworkInfo();
        });
    }
    if (btnClose && modal) {
        btnClose.addEventListener("click", () => {
            playSound("click");
            modal.style.display = "none";
        });
    }
    fetchNetworkInfo();
}

async function fetchNetworkInfo() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/network/info`);
        if (res.ok) {
            const data = await res.json();
            const urlEl = document.getElementById("pairing-url-text");
            const qrEl = document.getElementById("pairing-qr-img");
            const openTabBtn = document.getElementById("btn-open-mobile-tab");
            if (urlEl) urlEl.textContent = data.mobile_url;
            if (openTabBtn) openTabBtn.href = data.mobile_url;
            if (qrEl) qrEl.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(data.mobile_url)}`;
        }
    } catch (e) {}
}

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/laptop`;

    try {
        const ws = new WebSocket(wsUrl);
        state.ws = ws;

        ws.onopen = () => {
            console.log("[WS] Connected to CyberShield Laptop SOC sync stream.");
            const pillText = document.getElementById("mobile-status-text");
            if (pillText) pillText.textContent = "Listening for Mobile...";
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.stats) updateStatsUI(msg.stats);

                if (msg.type === "DEVICE_CONNECTED") {
                    playSound("success");
                    const pillText = document.getElementById("mobile-status-text");
                    if (pillText) {
                        pillText.textContent = `${msg.device.device_name} (Online - ${msg.device.ip_address})`;
                        pillText.style.color = "var(--accent-green)";
                    }
                    appendSocTerminal(`[DEVICE-CONNECTED] Real mobile client '${msg.device.device_name}' paired via IP: ${msg.device.ip_address}`, "success");
                } else if (msg.type === "MOBILE_HEARTBEAT") {
                    const pillText = document.getElementById("mobile-status-text");
                    if (pillText) {
                        pillText.textContent = `Online (${msg.battery_level}% Bat, ${msg.privacy_score}% Privacy)`;
                    }
                } else if (msg.type === "NEW_THREAT_EVENT" || msg.type === "NEW_THREAT_INTERCEPTED") {
                    playSound("alert");
                    appendSocTerminal(`[MOBILE-ALERT] Threat intercepted on mobile device! Vector: ${msg.threat ? msg.threat.threat_type : 'Unknown'}`, "warning");
                    fetchThreats();
                    fetchStats();
                } else if (msg.type === "VULNERABILITY_SCAN_COMPLETED" || msg.type === "VULNERABILITY_RESOLVED") {
                    playSound("success");
                    fetchVulnerabilities();
                } else if (msg.type === "TRACKER_BLOCKED") {
                    fetchTrackers();
                }
            } catch (e) {
                console.error("WebSocket message parsing error:", e);
            }
        };

        ws.onclose = () => {
            setTimeout(connectWebSocket, 3000);
        };
    } catch (e) {
        setInterval(fetchStats, 6000);
    }
}

// ==============================================================================
// 7. RENDERING THREAT CARDS (NORMAL VS. STUDENT)
// ==============================================================================
function renderThreatCards() {
    const container = document.getElementById("threat-cards-container");
    if (!container) return;

    let events = state.threatEvents || [];

    // Filter
    if (state.filterThreats === "CRITICAL") {
        events = events.filter(e => e.risk_level === "CRITICAL");
    } else if (state.filterThreats === "HIGH") {
        events = events.filter(e => e.risk_level === "HIGH");
    } else if (state.filterThreats === "WHATSAPP") {
        events = events.filter(e => e.channel === "WHATSAPP");
    } else if (state.filterThreats === "UPI_QR") {
        events = events.filter(e => e.channel === "UPI_QR");
    }

    if (events.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-secondary); padding: 40px; background: var(--bg-secondary); border-radius: 12px; border: 1px dashed var(--border-color);">No active threat interceptions found matching filter. System shielded.</div>`;
        return;
    }

    container.innerHTML = events.map(evt => {
        const riskClass = (evt.risk_level || "HIGH").toLowerCase();
        const icon = getChannelIcon(evt.channel);

        // NORMAL MODE VIEW
        if (state.currentMode === "NORMAL") {
            return `
                <div class="threat-card">
                    <div class="threat-card-header">
                        <div class="threat-title-group">
                            <span class="threat-icon">${icon}</span>
                            <div>
                                <div class="threat-title">${escapeHtml(evt.threat_title)}</div>
                                <span style="font-size: 0.74rem; color: var(--text-secondary);">${escapeHtml(evt.channel)} &bull; ${escapeHtml(evt.timestamp || "Just now")}</span>
                            </div>
                        </div>
                        <span class="badge-risk ${riskClass}">${escapeHtml(evt.risk_level)} RISK</span>
                    </div>

                    <div class="guidance-box">
                        <div class="guidance-row">
                            <span class="guidance-label">1. What is this threat?</span><br>
                            ${escapeHtml(evt.explanation_normal_what || "Suspicious external payload intercepted.")}
                        </div>
                        <div class="guidance-row" style="margin-top: 6px;">
                            <span class="guidance-label" style="color: #f97316;">2. What personal data could it compromise?</span><br>
                            ${escapeHtml(evt.explanation_normal_leak || "Personal account credentials or banking tokens.")}
                        </div>
                        <div class="guidance-row" style="margin-top: 6px;">
                            <span class="guidance-label guidance-action">3. What should you do?</span><br>
                            ${escapeHtml(evt.explanation_normal_action || "Ignore or delete the message.")}
                        </div>
                    </div>
                </div>
            `;
        }

        // STUDENT MODE VIEW (FORENSICS + MITRE + DISASSEMBLY)
        const mitreTactic = evt.mitre_tactic || "Initial Access";
        const mitreTechId = evt.mitre_technique_id || "T1566.002";
        const mitreTechName = evt.mitre_technique_name || "Spearphishing Link";
        const cwe = evt.cwe_mapping || "CWE-79 / CWE-352";
        const payload = evt.disassembly_payload || "Raw payload payload parsing...";
        const defenseCode = evt.defensive_code || "// Remediation filter";

        return `
            <div class="threat-card">
                <div class="threat-card-header">
                    <div class="threat-title-group">
                        <span class="threat-icon">${icon}</span>
                        <div>
                            <div class="threat-title">${escapeHtml(evt.threat_title)}</div>
                            <span style="font-size: 0.74rem; color: var(--text-secondary);">${escapeHtml(evt.channel)} &bull; Forensic Case: #${evt.id}</span>
                        </div>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="badge-risk ${riskClass}">${escapeHtml(evt.risk_level)}</span>
                        <button class="btn-open-lab" onclick="openDefenseLab('${evt.id}')">
                            🔬 Open in Defense Lab →
                        </button>
                    </div>
                </div>

                <div class="student-forensics-box">
                    <div class="mitre-badge-row">
                        <span class="mitre-pill">MITRE ATT&CK: ${mitreTechId} (${escapeHtml(mitreTechName)})</span>
                        <span class="mitre-pill" style="color: #38bdf8; border-color: #38bdf8; background: rgba(56, 189, 248, 0.15);">${mitreTactic}</span>
                        <span class="ioc-pill">${escapeHtml(cwe)}</span>
                    </div>

                    <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">
                        <strong>Payload / Bytecode Heuristic Extract:</strong>
                    </div>
                    <pre class="code-snippet">${escapeHtml(payload)}</pre>

                    <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">
                        <strong>Defensive Remediation Snippet:</strong>
                    </div>
                    <pre class="code-snippet" style="border-color: #10b981; color: #86efac;">${escapeHtml(defenseCode)}</pre>
                </div>
            </div>
        `;
    }).join("");
}

function getChannelIcon(channel) {
    switch (channel) {
        case "WHATSAPP": return "💬";
        case "UPI_QR": return "💳";
        case "APK_DOWNLOAD": return "📦";
        case "CLIPBOARD_PII": return "📋";
        default: return "🚨";
    }
}

// ==============================================================================
// 8. VULNERABILITIES TABLE
// ==============================================================================
function renderVulnTable() {
    const tbody = document.getElementById("vuln-table-body");
    if (!tbody) return;

    if (!state.vulnerabilities || state.vulnerabilities.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 30px;">All endpoints up to date. No unpatched CVEs found.</td></tr>`;
        return;
    }

    tbody.innerHTML = state.vulnerabilities.map(v => {
        const isPatched = v.status === "PATCHED";
        const riskColor = v.cvss_score >= 9.0 ? "#ef4444" : v.cvss_score >= 7.0 ? "#f59e0b" : "#38bdf8";

        return `
            <tr>
                <td style="font-weight: 600;">${escapeHtml(v.software_name)}</td>
                <td style="color: ${isPatched ? '#10b981' : '#f87171'}; font-family: var(--font-code); font-size: 0.8rem;">
                    ${escapeHtml(v.installed_version)}
                </td>
                <td style="font-family: var(--font-code); font-size: 0.8rem; color: #34d399;">
                    ${escapeHtml(v.patched_version)}
                </td>
                <td><span class="badge-cve">${escapeHtml(v.cve_id)}</span></td>
                <td><strong style="color: ${riskColor};">${v.cvss_score}</strong> (${escapeHtml(v.severity)})</td>
                <td style="max-width: 320px; font-size: 0.8rem; color: #cbd5e1;">${escapeHtml(v.summary)}</td>
                <td>
                    ${isPatched 
                        ? `<span class="badge-blocked" style="background: rgba(16, 185, 129, 0.2);">PATCHED ✓</span>`
                        : `<button class="btn-patch" onclick="resolveVulnerability('${v.id}')">Apply Patch</button>`
                    }
                </td>
            </tr>
        `;
    }).join("");
}

async function resolveVulnerability(vulnId) {
    playSound("click");
    try {
        const res = await fetch(`${API_BASE}/api/v1/vulnerabilities/${vulnId}/resolve`, {
            method: "POST"
        });
        if (res.ok) {
            playSound("success");
            await fetchVulnerabilities();
            await fetchStats();
        }
    } catch (err) {
        console.error("Error resolving vulnerability:", err);
    }
}

// Rescan CVE button
const btnRescan = document.getElementById("btn-rescan-cve");
if (btnRescan) {
    btnRescan.addEventListener("click", async () => {
        playSound("click");
        btnRescan.textContent = "Auditing...";
        try {
            await fetch(`${API_BASE}/api/v1/vulnerabilities/scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ device_id: "dev-desktop-002" })
            });
            playSound("success");
            await fetchVulnerabilities();
            await fetchStats();
        } catch (err) {
            console.error(err);
        } finally {
            btnRescan.textContent = "🔄 Re-Scan Endpoints";
        }
    });
}

// ==============================================================================
// 9. TRACKER RADAR TABLE
// ==============================================================================
function renderTrackerTable() {
    const tbody = document.getElementById("tracker-table-body");
    if (!tbody) return;

    if (!state.trackers || state.trackers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 30px;">No telemetry leaks detected.</td></tr>`;
        return;
    }

    tbody.innerHTML = state.trackers.map(t => `
        <tr>
            <td>
                <strong>${escapeHtml(t.app_name)}</strong><br>
                <span style="font-family: var(--font-code); font-size: 0.72rem; color: var(--text-secondary);">${escapeHtml(t.package_name)}</span>
            </td>
            <td style="font-family: var(--font-code); font-size: 0.8rem; color: #38bdf8;">
                ${escapeHtml(t.telemetry_domain)}
            </td>
            <td>
                <span style="background: rgba(139, 92, 246, 0.15); border: 1px solid rgba(139, 92, 246, 0.4); color: #c084fc; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem;">
                    ${escapeHtml(t.tracker_category)}
                </span>
            </td>
            <td>
                <span class="badge-blocked">🛡️ BLOCKED by VpnService</span>
            </td>
        </tr>
    `).join("");
}

// ==============================================================================
// 10. SMARTPHONE SIMULATOR TRIGGERS & CUSTOM ANALYZER
// ==============================================================================
function initSimulationButtons() {
    const btnWa = document.getElementById("sim-wa-phish");
    const btnQr = document.getElementById("sim-qr-scam");
    const btnApk = document.getElementById("sim-apk-download");
    const btnClip = document.getElementById("sim-clipboard-pii");

    if (btnWa) {
        btnWa.addEventListener("click", () => {
            playSound("alert");
            renderPhoneAppView("whatsapp");
            triggerPhoneSimulation(
                "WHATSAPP",
                "🎁 Festive Reward! You won ₹50,000 cash! Click link to claim: http://festival-reward-claim.online/claim.php"
            );
        });
    }

    if (btnQr) {
        btnQr.addEventListener("click", () => {
            playSound("alert");
            renderPhoneAppView("upi");
            triggerPhoneSimulation(
                "UPI_QR",
                "upi://pay?pa=fastpayouts.claim@fakeupi&pn=RefundAgent&am=25000.00&cu=INR&mode=02"
            );
        });
    }

    if (btnApk) {
        btnApk.addEventListener("click", () => {
            playSound("alert");
            renderPhoneAppView("apk");
            triggerPhoneSimulation(
                "APK_DOWNLOAD",
                "Download initiated for unverified APK: Express_Loan_Approved_v4.2.apk from 185.220.101.5",
                "Express_Loan_Approved_v4.2.apk"
            );
        });
    }

    if (btnClip) {
        btnClip.addEventListener("click", () => {
            playSound("alert");
            renderPhoneAppView("clipboard");
            triggerPhoneSimulation(
                "CLIPBOARD_PII",
                "User clipboard: 5421 9801 4329 (Aadhaar) and One-time OTP 894120"
            );
        });
    }
}

function initCustomPayloadAnalyzer() {
    const btn = document.getElementById("btn-analyze-custom");
    const input = document.getElementById("custom-payload-input");

    if (btn && input) {
        const handleAnalyze = () => {
            const val = input.value.trim();
            if (!val) return;
            playSound("click");
            let channel = "WHATSAPP";
            if (val.startsWith("upi://")) channel = "UPI_QR";
            else if (val.endsWith(".apk")) channel = "APK_DOWNLOAD";

            triggerPhoneSimulation(channel, val, val.endsWith(".apk") ? val : null);
            input.value = "";
        };

        btn.addEventListener("click", handleAnalyze);
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") handleAnalyze();
        });
    }
}

async function triggerPhoneSimulation(channel, content, artifact = null) {
    try {
        const res = await fetch(`${API_BASE}/api/v1/threats/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                channel: channel,
                content: content,
                artifact_name: artifact,
                device_id: "dev-mobile-001"
            })
        });

        if (res.ok) {
            await fetchThreats();
            await fetchStats();
        }
    } catch (err) {
        console.error("Simulation error:", err);
    }
}

// ==============================================================================
// 11. INTERACTIVE DEFENSE SANDBOX LAB TAB
// ==============================================================================
function initSandboxLab() {
    const options = document.querySelectorAll(".defense-option");
    const btnTest = document.getElementById("btn-test-defense");
    const resultBox = document.getElementById("sandbox-result");
    const scenarioSelect = document.getElementById("sandbox-scenario-select");

    if (scenarioSelect) {
        scenarioSelect.addEventListener("change", () => {
            playSound("click");
            state.activeScenario = scenarioSelect.value;
            const scenarioContexts = {
                "WA_PHISH": "Social Engineering Phishing Link (WhatsApp Interception): Rogue server disguised as cashback.",
                "UPI_QR": "Deceptive UPI Reverse Debit Intent: Merchant QR requesting ₹25,000 debit during refund claim.",
                "APK_DOWNLOAD": "Trojanized APK Sideload: Malicious package requesting SMS and audio surveillance.",
                "CLIPBOARD_PII": "Background Clipboard Snooping: Aadhaar and banking OTP exfiltration."
            };
            const activeScenarioEl = document.getElementById("sandbox-active-scenario");
            if (activeScenarioEl) {
                activeScenarioEl.innerHTML = `<strong>Scenario Context:</strong> ${scenarioContexts[state.activeScenario] || state.activeScenario}`;
            }
        });
    }

    options.forEach(opt => {
        opt.addEventListener("click", () => {
            playSound("click");
            options.forEach(o => o.classList.remove("active-option"));
            opt.classList.add("active-option");
            state.selectedRule = opt.getAttribute("data-rule");
        });
    });

    if (btnTest) {
        btnTest.addEventListener("click", async () => {
            playSound("click");
            btnTest.textContent = "⚡ Deploying & Testing Countermeasure...";
            btnTest.disabled = true;

            try {
                const res = await fetch(`${API_BASE}/api/v1/sandbox/evaluate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        scenario_id: state.activeScenario,
                        rule_selected: state.selectedRule
                    })
                });

                if (res.ok) {
                    const data = await res.json();
                    if (resultBox) {
                        resultBox.style.display = "block";
                        const isSuccess = data.score >= 80;
                        if (isSuccess) playSound("success");
                        else playSound("alert");

                        resultBox.innerHTML = `
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                <strong style="color: ${isSuccess ? '#10b981' : '#f59e0b'}; font-size: 1.05rem;">
                                    ${escapeHtml(data.verdict)}
                                </strong>
                                <span style="background: ${isSuccess ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)'}; color: ${isSuccess ? '#34d399' : '#fbbf24'}; padding: 4px 12px; border-radius: 8px; font-weight: 700;">
                                    Score: ${data.score} / 100
                                </span>
                            </div>
                            <p style="color: #cbd5e1; font-size: 0.85rem; margin-bottom: 12px;">
                                ${escapeHtml(data.technical_analysis)}
                            </p>
                            <pre class="code-snippet" style="margin-top: 8px;">${escapeHtml(data.terminal_log)}</pre>
                            <div style="margin-top: 14px; display: flex; gap: 10px;">
                                <button class="btn-player" onclick="openDefenseLab()" style="background: #7c3aed; color: #fff;">
                                    🚀 Launch Full SOC Virtual Lab Workspace →
                                </button>
                            </div>
                        `;
                    }
                }
            } catch (err) {
                console.error("Sandbox test error:", err);
            } finally {
                btnTest.textContent = "⚡ Deploy Defensive Rule in Sandbox";
                btnTest.disabled = false;
            }
        });
    }
}

// ==============================================================================
// 12. VIRTUAL CYBER DEFENSE LAB WORKSPACE
// ==============================================================================
function initVirtualLab() {
    const modal = document.getElementById("virtual-lab-modal");
    const btnClose = document.getElementById("btn-close-lab");
    const btnBlue = document.getElementById("btn-blue-team");
    const btnRed = document.getElementById("btn-red-team");
    const policySelect = document.getElementById("lab-policy-select");
    const policyPreview = document.getElementById("lab-policy-preview");
    const btnDetonate = document.getElementById("btn-fire-detonation");

    // Exit Lab
    if (btnClose && modal) {
        btnClose.addEventListener("click", () => {
            playSound("click");
            modal.classList.add("hidden");
            pauseAttackAnimation();
        });
    }

    // Perspective Toggles
    if (btnBlue && btnRed) {
        btnBlue.addEventListener("click", () => {
            playSound("click");
            btnBlue.className = "btn-team-toggle active-blue";
            btnRed.className = "btn-team-toggle";
            state.activeTeam = "BLUE";
            appendSocTerminal("[MODE] Switched perspective to BLUE TEAM (Defender). Hardening filters active.", "info");
        });
        btnRed.addEventListener("click", () => {
            playSound("click");
            btnBlue.className = "btn-team-toggle";
            btnRed.className = "btn-team-toggle active-red";
            state.activeTeam = "RED";
            appendSocTerminal("[MODE] Switched perspective to RED TEAM (Attacker). Inspecting exfiltration routes.", "warning");
        });
    }

    // Tool Tab Switching
    document.querySelectorAll(".btn-tool-tab").forEach(tab => {
        tab.addEventListener("click", () => {
            playSound("click");
            const toolId = tab.getAttribute("data-tool");
            document.querySelectorAll(".btn-tool-tab").forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            document.querySelectorAll(".tool-pane").forEach(p => {
                if (p.id === toolId) p.classList.add("active");
                else p.classList.remove("active");
            });
        });
    });

    // Policy Select Change
    if (policySelect && policyPreview) {
        policySelect.addEventListener("change", () => {
            playSound("click");
            state.labPolicy = policySelect.value;
            if (policySelect.value === "CSP_POLICY") {
                policyPreview.textContent = "Content-Security-Policy: default-src 'self'; form-action 'self' https://trusted-bank.com;\n// Enforces browser sandbox refusal of form post to external IPs.";
                appendSocTerminal("[POLICY] Active policy updated: Content Security Policy (form-action 'self').", "success");
            } else if (policySelect.value === "DNS_SINKHOLE") {
                policyPreview.textContent = "// Local DNS-over-HTTPS Sinkhole Rule:\nif (domain.endsWith('.online') && riskScore > 90) {\n    return InetAddress.getByName('0.0.0.0');\n}";
                appendSocTerminal("[POLICY] Active policy updated: DNS Sinkhole (Drop rogue domains).", "success");
            } else {
                policyPreview.textContent = "// NONE: All outbound traffic permitted without restriction.\n// WARNING: System is currently vulnerable to data exfiltration!";
                appendSocTerminal("[POLICY-WARN] Warning: Active defense policy stripped. Node is vulnerable.", "warning");
            }
        });
    }

    // Animation Controls
    const btnPlay = document.getElementById("btn-play-anim");
    const btnPause = document.getElementById("btn-pause-anim");
    const btnRestart = document.getElementById("btn-restart-anim");

    if (btnPlay) btnPlay.addEventListener("click", () => { playSound("click"); startAttackAnimation(); });
    if (btnPause) btnPause.addEventListener("click", () => { playSound("click"); pauseAttackAnimation(); });
    if (btnRestart) btnRestart.addEventListener("click", () => {
        playSound("click");
        state.animStep = 1;
        updateAttackAnimStep(1);
        startAttackAnimation();
    });

    document.querySelectorAll(".step-marker-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            playSound("click");
            const step = parseInt(btn.getAttribute("data-step"));
            pauseAttackAnimation();
            updateAttackAnimStep(step);
        });
    });

    // Attack Detonation Button
    if (btnDetonate) {
        btnDetonate.addEventListener("click", fireDetonation);
    }
}

function openDefenseLab(threatId) {
    playSound("click");
    const modal = document.getElementById("virtual-lab-modal");
    if (!modal) return;
    modal.classList.remove("hidden");

    if (threatId) {
        const caseTitle = document.getElementById("lab-case-file-title");
        if (caseTitle) caseTitle.textContent = `CASE FILE #${threatId.toUpperCase()} // TARGET: MOBILE MESSAGING VECTOR`;
    }

    startAttackAnimation();
}

// Attack Animation Player
function startAttackAnimation() {
    if (state.animPlaying) return;
    state.animPlaying = true;
    state.animInterval = setInterval(() => {
        let nextStep = state.animStep + 1;
        if (nextStep > 5) nextStep = 1;
        updateAttackAnimStep(nextStep);
    }, 2800);
}

function pauseAttackAnimation() {
    state.animPlaying = false;
    if (state.animInterval) {
        clearInterval(state.animInterval);
        state.animInterval = null;
    }
}

function updateAttackAnimStep(step) {
    state.animStep = step;
    playSound("blip");
    const badge = document.getElementById("player-step-badge");
    const caption = document.getElementById("player-caption");
    const progressBar = document.getElementById("anim-progress-bar");
    const packet = document.getElementById("anim-packet");

    if (badge) badge.textContent = `STAGE ${step} OF 5`;
    if (progressBar) progressBar.style.width = `${step * 20}%`;

    // Highlight Buttons
    document.querySelectorAll(".step-marker-btn").forEach(b => {
        if (parseInt(b.getAttribute("data-step")) === step) b.classList.add("active-step");
        else b.classList.remove("active-step");
    });

    // Highlight Node
    document.querySelectorAll(".flow-node").forEach(n => n.classList.remove("active-node"));
    const nodes = ["node-attacker", "node-whatsapp", "node-webview", "node-victim", "node-defense"];
    const targetNode = document.getElementById(nodes[step - 1]);
    if (targetNode) targetNode.classList.add("active-node");

    // Packet Position
    if (packet) {
        const pct = [5, 28, 52, 75, 95];
        packet.style.left = `${pct[step - 1]}%`;
    }

    // Captions & Terminal log
    const captions = [
        "<strong>Step 1: Threat C2 Initialization:</strong> Attacker provisions bulletproof server (198.51.100.24) and sets up credential harvester script.",
        "<strong>Step 2: WhatsApp Phishing Distribution:</strong> Social engineering link is sent to mobile victim disguised as ₹50,000 festive cashback.",
        "<strong>Step 3: Webview Navigation:</strong> Victim taps link; in-app webview begins resolving external domain 'festival-reward-claim.online'.",
        "<strong>Step 4: Form Injection & Exfiltration:</strong> Attacker form prompts for OTP / Card tokens and attempts HTTP POST exfiltration.",
        "<strong>Step 5: Policy Intercept & Neutralization:</strong> Content Security Policy or DNS Sinkhole drops the request. Threat neutralized!"
    ];

    if (caption) caption.innerHTML = captions[step - 1];
    appendSocTerminal(`[STAGE-${step}] ${captions[step - 1].replace(/<[^>]*>/g, '')}`, "info");
}

// Attack Detonation Function
function fireDetonation() {
    playSound("alert");
    appendSocTerminal("==================================================", "info");
    appendSocTerminal("[DETONATION-ENGINE] Firing simulated attack payload against Node 10.0.8.14...", "warning");
    appendSocTerminal("[PAYLOAD] POST /collect.php Host: 198.51.100.24 User: gadupudi071 OTP: 894120", "warning");

    setTimeout(() => {
        if (state.labPolicy === "CSP_POLICY") {
            playSound("success");
            appendSocTerminal("[BROWSER-SANDBOX] Content-Security-Policy header enforced!", "success");
            appendSocTerminal("[BLOCKED] Form action to '198.51.100.24' violates CSP 'form-action 'self''. Form dropped.", "success");
            appendSocTerminal("[VERDICT] 100/100 MITIGATION VERIFIED. Zero data leaked to threat actor.", "success");
            unlockCertificate();
        } else if (state.labPolicy === "DNS_SINKHOLE") {
            playSound("success");
            appendSocTerminal("[DNS-SINKHOLE] Query for 'festival-reward-claim.online' intercepted by on-device DNS.", "success");
            appendSocTerminal("[BLOCKED] Domain resolved to 0.0.0.0. Connection refused by kernel.", "success");
            appendSocTerminal("[VERDICT] 100/100 MITIGATION VERIFIED. Exploit rendered completely unreachable.", "success");
            unlockCertificate();
        } else {
            playSound("alert");
            appendSocTerminal("[EXPLOITATION-ALERT] Node has NO active policy!", "error");
            appendSocTerminal("[DATA-LEAK] 68 bytes of victim data transmitted to C2 (198.51.100.24:80).", "error");
            appendSocTerminal("[VERDICT] DEFENSE FAILED (0/100). Select 'CSP_POLICY' or 'DNS_SINKHOLE' to harden your node.", "error");
        }
    }, 600);
}

function unlockCertificate() {
    const certBtn = document.getElementById("btn-view-cert");
    if (certBtn) {
        certBtn.style.display = "block";
        certBtn.scrollIntoView({ behavior: "smooth" });
    }
    state.defenseScore = 100;
}

// ==============================================================================
// 13. INTERACTIVE SOC TERMINAL CLI
// ==============================================================================
function initSocTerminal() {
    const form = document.getElementById("terminal-cli-form");
    const input = document.getElementById("terminal-cli-input");

    if (form && input) {
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            const cmd = input.value.trim();
            if (cmd) {
                executeCliCommand(cmd);
                input.value = "";
            }
        });
    }
}

function executeCliCommand(cmd) {
    playSound("blip");
    appendSocTerminal(`root@cybershield-soc:~# ${cmd}`, "info");

    const parts = cmd.toLowerCase().split(" ");
    const command = parts[0];

    switch (command) {
        case "help":
            appendSocTerminal("Available SOC Commands:\n" +
                "  • help                 - Show this manual\n" +
                "  • nmap <target>        - Scan open ports on target host\n" +
                "  • inspect-packet       - View intercepted HTTP POST request stream\n" +
                "  • whois                - Query threat intelligence domain registry\n" +
                "  • policy csp           - Enable Content Security Policy defense\n" +
                "  • policy sinkhole      - Enable DNS sinkholing filter\n" +
                "  • policy none          - Disable all protections (Vulnerable baseline)\n" +
                "  • detonate             - Launch safe attack payload against current node\n" +
                "  • clear                - Clear terminal display", "info");
            break;

        case "nmap":
            const target = parts[1] || "10.0.8.14";
            appendSocTerminal(`Starting Nmap scan on ${target}...`, "info");
            appendSocTerminal(`Host is up (0.00042s latency).\n` +
                `PORT    STATE SERVICE\n` +
                `80/tcp  OPEN  http [Simulated Webview Node]\n` +
                `443/tcp OPEN  https [TLS Terminated]\n` +
                `53/udp  OPEN  domain [Local DNS Proxy]`, "success");
            break;

        case "inspect-packet":
            appendSocTerminal("[PACKET-INSPECTOR]\n" +
                "POST /collect.php HTTP/1.1\n" +
                "Host: 198.51.100.24\n" +
                "Content-Type: application/x-www-form-urlencoded\n" +
                "Payload: victim_user=gadupudi071&otp_token=894120", "warning");
            break;

        case "whois":
            appendSocTerminal("[WHOIS RECORD]\n" +
                "Domain: festival-reward-claim.online\n" +
                "IP: 198.51.100.24 (AS45102 Bulletproof Fast-Flux)\n" +
                "Risk Score: 98/100 (CRITICAL PHISHING HOST)", "warning");
            break;

        case "policy":
            const sub = parts[1];
            const selectEl = document.getElementById("lab-policy-select");
            if (sub === "csp") {
                if (selectEl) { selectEl.value = "CSP_POLICY"; selectEl.dispatchEvent(new Event('change')); }
            } else if (sub === "sinkhole") {
                if (selectEl) { selectEl.value = "DNS_SINKHOLE"; selectEl.dispatchEvent(new Event('change')); }
            } else if (sub === "none") {
                if (selectEl) { selectEl.value = "NO_POLICY"; selectEl.dispatchEvent(new Event('change')); }
            } else {
                appendSocTerminal("Usage: policy [csp | sinkhole | none]", "error");
            }
            break;

        case "detonate":
            fireDetonation();
            break;

        case "clear":
            const term = document.getElementById("soc-terminal");
            if (term) term.innerHTML = "";
            break;

        default:
            appendSocTerminal(`Command not found: '${command}'. Type 'help' for valid options.`, "error");
            break;
    }
}

function appendSocTerminal(text, type = "normal") {
    const term = document.getElementById("soc-terminal");
    if (!term) return;

    const line = document.createElement("div");
    line.className = `terminal-line ${type}`;
    line.textContent = text;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

// ==============================================================================
// 14. DEFENSE CERTIFICATE MODAL
// ==============================================================================
function initCertificateModal() {
    const btnViewCert = document.getElementById("btn-view-cert");
    const certModal = document.getElementById("defense-cert-modal");
    const btnCloseCert = document.getElementById("btn-close-cert");

    if (btnViewCert && certModal) {
        btnViewCert.addEventListener("click", () => {
            playSound("success");
            const dateStr = new Date().toLocaleDateString("en-US", { month: "long", year: "numeric", day: "numeric" });
            const dateEl = document.getElementById("cert-date-string");
            if (dateEl) dateEl.textContent = `Date: ${dateStr}`;
            certModal.classList.remove("hidden");
        });
    }

    if (btnCloseCert && certModal) {
        btnCloseCert.addEventListener("click", () => {
            playSound("click");
            certModal.classList.add("hidden");
        });
    }
}

// Utility: HTML Sanitizer
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
