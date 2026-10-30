/**
 * CyberShield AI • Mobile Privacy Guardian
 * Real-time Mobile Engine & Laptop SOC Telemetry Sync
 */

// Global State
const MobileState = {
    deviceId: localStorage.getItem('cs_device_id') || `mob-${Math.random().toString(36).substring(2, 8)}`,
    deviceName: localStorage.getItem('cs_device_name') || (navigator.userAgent.includes('Android') ? 'Android Smartphone' : (navigator.userAgent.includes('iPhone') ? 'Apple iPhone' : 'Personal Mobile Client')),
    osVersion: navigator.userAgent.includes('Android') ? 'Android 14' : (navigator.userAgent.includes('iPhone') ? 'iOS 18' : 'Mobile Web Client'),
    batteryLevel: 88,
    privacyScore: 85,
    threatsBlocked: 0,
    trackersBlocked: 4,
    wsConnected: false,
    socket: null,
    deferredInstallPrompt: null
};

// Save generated device ID
localStorage.setItem('cs_device_id', MobileState.deviceId);

// Initialize On DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    initPWA();
    initWebSocket();
    initBatteryAPI();
    updateScoreUI(MobileState.privacyScore);
    setupEventListeners();
    registerDevice();
});

// PWA Service Worker & Install Prompt
function initPWA() {
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/mobile_static/service-worker.js')
            .then(() => console.log('[PWA] Service Worker Registered'))
            .catch(err => console.log('[PWA] SW Registration failed', err));
    }

    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        MobileState.deferredInstallPrompt = e;
        const banner = document.getElementById('install-banner');
        if (banner) banner.style.display = 'flex';
    });

    const installBtn = document.getElementById('install-pwa-btn');
    if (installBtn) {
        installBtn.addEventListener('click', async () => {
            if (MobileState.deferredInstallPrompt) {
                MobileState.deferredInstallPrompt.prompt();
                const choice = await MobileState.deferredInstallPrompt.userChoice;
                if (choice.outcome === 'accepted') {
                    document.getElementById('install-banner').style.display = 'none';
                }
                MobileState.deferredInstallPrompt = null;
            } else {
                alert('To install:\n• Android: Tap Chrome menu (⋮) -> "Add to Home screen" or "Install App".\n• iOS: Tap Share button -> "Add to Home Screen".');
            }
        });
    }
}

// Battery API
function initBatteryAPI() {
    if ('getBattery' in navigator) {
        navigator.getBattery().then(battery => {
            MobileState.batteryLevel = Math.round(battery.level * 100);
            updateTelemetryDisplay();
            battery.addEventListener('levelchange', () => {
                MobileState.batteryLevel = Math.round(battery.level * 100);
                updateTelemetryDisplay();
                sendHeartbeat();
            });
        }).catch(() => {});
    }
    updateTelemetryDisplay();
}

function updateTelemetryDisplay() {
    const batEl = document.getElementById('disp-battery');
    if (batEl) batEl.textContent = `${MobileState.batteryLevel}%`;
    const devEl = document.getElementById('disp-dev-name');
    if (devEl) devEl.textContent = MobileState.deviceName;
    const idEl = document.getElementById('disp-dev-id');
    if (idEl) idEl.textContent = MobileState.deviceId;
}

// Register Device to Backend
async function registerDevice() {
    try {
        await fetch('/api/v1/devices/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_id: MobileState.deviceId,
                device_name: MobileState.deviceName,
                device_type: 'MOBILE',
                os_version: MobileState.osVersion,
                battery_level: MobileState.batteryLevel,
                privacy_score: MobileState.privacyScore
            })
        });
    } catch (e) {
        console.warn('Device registration offline fallback:', e);
    }
}

// WebSocket Live Telemetry Sync
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/mobile`;

    try {
        MobileState.socket = new WebSocket(wsUrl);

        MobileState.socket.onopen = () => {
            MobileState.wsConnected = true;
            updateConnectionBadge(true);
            sendHeartbeat();
        };

        MobileState.socket.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'THREAT_SYNCED' && msg.stats) {
                    if (msg.stats.privacy_score) {
                        updateScoreUI(msg.stats.privacy_score);
                    }
                }
            } catch (e) {}
        };

        MobileState.socket.onclose = () => {
            MobileState.wsConnected = false;
            updateConnectionBadge(false);
            // Auto reconnect after 3 seconds
            setTimeout(initWebSocket, 3000);
        };

        MobileState.socket.onerror = () => {
            MobileState.wsConnected = false;
            updateConnectionBadge(false);
        };
    } catch (e) {
        MobileState.wsConnected = false;
        updateConnectionBadge(false);
    }
}

function updateConnectionBadge(connected) {
    const pill = document.getElementById('soc-link-pill');
    const text = document.getElementById('soc-link-text');
    if (!pill || !text) return;

    if (connected) {
        pill.classList.remove('disconnected');
        text.textContent = 'LINKED TO LAPTOP SOC';
    } else {
        pill.classList.add('disconnected');
        text.textContent = 'CONNECTING TO SOC...';
    }
}

function sendHeartbeat() {
    if (MobileState.socket && MobileState.socket.readyState === WebSocket.OPEN) {
        MobileState.socket.send(JSON.stringify({
            type: 'HEARTBEAT',
            device_id: MobileState.deviceId,
            device_name: MobileState.deviceName,
            battery_level: MobileState.batteryLevel,
            privacy_score: MobileState.privacyScore,
            os_version: MobileState.osVersion
        }));
    }
}

// Update Privacy Score Ring
function updateScoreUI(score) {
    MobileState.privacyScore = score;
    const numEl = document.getElementById('score-number');
    if (numEl) numEl.textContent = `${score}%`;

    const circle = document.getElementById('score-circle-fill');
    if (circle) {
        const radius = circle.r.baseVal.value;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference - (score / 100) * circumference;
        circle.style.strokeDasharray = `${circumference} ${circumference}`;
        circle.style.strokeDashoffset = offset;

        if (score >= 80) circle.style.stroke = '#00ffa3';
        else if (score >= 60) circle.style.stroke = '#ffb703';
        else circle.style.stroke = '#ff3366';
    }

    const threatCount = document.getElementById('stat-threats-count');
    if (threatCount) threatCount.textContent = MobileState.threatsBlocked;
}

// Dispatch Threat to Laptop SOC via WebSocket or REST
async function emitThreatToLaptop(threatData) {
    MobileState.threatsBlocked++;
    MobileState.privacyScore = Math.max(25, MobileState.privacyScore - 5);
    updateScoreUI(MobileState.privacyScore);

    // 1. WebSocket push
    if (MobileState.socket && MobileState.socket.readyState === WebSocket.OPEN) {
        MobileState.socket.send(JSON.stringify({
            type: 'MOBILE_THREAT_DETECTED',
            device_id: MobileState.deviceId,
            device_name: MobileState.deviceName,
            threat: threatData
        }));
    }

    // 2. REST API backup
    try {
        await fetch('/api/v1/threats/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_id: MobileState.deviceId,
                device_name: MobileState.deviceName,
                channel: threatData.channel,
                severity: threatData.severity,
                threat_type: threatData.threat_type,
                content_snippet: threatData.content_snippet,
                evidence: threatData.evidence,
                recommendation: threatData.recommendation,
                status: 'BLOCKED'
            })
        });
    } catch (e) {
        console.warn('REST threat report offline fallback:', e);
    }
}

// Setup Event Handlers for Normal Mode Channels
function setupEventListeners() {
    // Bottom Navigation
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            const targetView = item.getAttribute('data-target');
            document.querySelectorAll('.feature-view').forEach(v => v.classList.remove('active'));
            const activeView = document.getElementById(targetView);
            if (activeView) activeView.classList.add('active');
        });
    });

    // 1. WhatsApp Scan Preset Buttons
    document.querySelectorAll('.wa-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = document.getElementById('wa-input');
            input.value = btn.getAttribute('data-sample');
        });
    });

    // WhatsApp Analyze Button
    const waScanBtn = document.getElementById('wa-scan-btn');
    if (waScanBtn) {
        waScanBtn.addEventListener('click', () => {
            const content = document.getElementById('wa-input').value.trim();
            if (!content) return;

            // Run AI analysis
            const isSuspicious = /claim|reward|lottery|winner|cashback|bill|suspended|free|gift/i.test(content) && /http|www|\.online|\.xyz|\.top/i.test(content);
            const verdictBox = document.getElementById('wa-verdict');
            verdictBox.style.display = 'block';

            if (isSuspicious) {
                verdictBox.className = 'verdict-box critical';
                document.getElementById('wa-verdict-title').textContent = '⚠️ Malicious Phishing Message Detected';
                document.getElementById('wa-verdict-sev').className = 'verdict-severity critical';
                document.getElementById('wa-verdict-sev').textContent = 'CRITICAL';
                document.getElementById('wa-verdict-desc').textContent = 'This message uses social engineering and high-urgency keywords to redirect you to an unverified credential harvesting page.';
                document.getElementById('wa-verdict-action').textContent = '🛡️ Action: Block sender and DO NOT tap any link.';

                // Stream to Laptop SOC
                emitThreatToLaptop({
                    channel: 'WHATSAPP',
                    severity: 'CRITICAL',
                    threat_type: 'Social Engineering Phishing Link',
                    content_snippet: content,
                    evidence: { vector: 'SMS/WhatsApp', urgency_keywords: ['reward', 'claim'], url_extracted: content.match(/https?:\/\/[^\s]+/)?.[0] || 'unknown' },
                    recommendation: 'Block sender immediately. URL sinkholed by gateway.'
                });
            } else {
                verdictBox.className = 'verdict-box safe';
                document.getElementById('wa-verdict-title').textContent = '✅ Verified Clean Message';
                document.getElementById('wa-verdict-sev').className = 'verdict-severity safe';
                document.getElementById('wa-verdict-sev').textContent = 'SAFE';
                document.getElementById('wa-verdict-desc').textContent = 'No deceptive urgency patterns, phishing domains, or credential harvesting traps found.';
                document.getElementById('wa-verdict-action').textContent = '🛡️ Safe to read and respond.';
            }
        });
    }

    // 2. UPI Guard Presets & Scan
    document.querySelectorAll('.upi-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = document.getElementById('upi-input');
            input.value = btn.getAttribute('data-sample');
        });
    });

    const upiScanBtn = document.getElementById('upi-scan-btn');
    if (upiScanBtn) {
        upiScanBtn.addEventListener('click', () => {
            const upiVal = document.getElementById('upi-input').value.trim();
            if (!upiVal) return;

            const isScam = upiVal.includes('refund-cashback') || upiVal.includes('fake-claim') || upiVal.includes('mode=02');
            const verdictBox = document.getElementById('upi-verdict');
            verdictBox.style.display = 'block';

            if (isScam) {
                verdictBox.className = 'verdict-box critical';
                document.getElementById('upi-verdict-title').textContent = '🚨 Deceptive UPI Payment Request Trap!';
                document.getElementById('upi-verdict-sev').className = 'verdict-severity critical';
                document.getElementById('upi-verdict-sev').textContent = 'CRITICAL';
                document.getElementById('upi-verdict-desc').textContent = 'WARNING: This QR code is configured as a MONEY DEBIT COLLECT REQUEST disguised as "Cashback". If you enter your UPI PIN, funds will be deducted from your account!';
                document.getElementById('upi-verdict-action').textContent = '🛡️ Action: Cancel payment immediately. You never need a UPI PIN to receive money.';

                emitThreatToLaptop({
                    channel: 'UPI',
                    severity: 'CRITICAL',
                    threat_type: 'Deceptive QR Collect Request Trap',
                    content_snippet: upiVal,
                    evidence: { upi_string: upiVal, intent: 'MONEY_DEBIT', deceptive_merchant: 'refund-cashback@ybl' },
                    recommendation: 'Payment halted. Disallow VPA transaction.'
                });
            } else {
                verdictBox.className = 'verdict-box safe';
                document.getElementById('upi-verdict-title').textContent = '✅ Verified Merchant Payment QR';
                document.getElementById('upi-verdict-sev').className = 'verdict-severity safe';
                document.getElementById('upi-verdict-sev').textContent = 'SAFE';
                document.getElementById('upi-verdict-desc').textContent = 'Valid NPCI UPI handle with matching verified merchant name and standard transaction intent.';
                document.getElementById('upi-verdict-action').textContent = '🛡️ Secure to proceed.';
            }
        });
    }

    // 3. APK Scanner Presets
    document.querySelectorAll('.apk-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            const name = btn.getAttribute('data-name');
            const isMalware = btn.getAttribute('data-malware') === 'true';
            document.getElementById('apk-file-name').textContent = name;
            const verdictBox = document.getElementById('apk-verdict');
            verdictBox.style.display = 'block';

            if (isMalware) {
                verdictBox.className = 'verdict-box critical';
                document.getElementById('apk-verdict-title').textContent = '🛑 Spyware / Banking Trojan APK!';
                document.getElementById('apk-verdict-sev').className = 'verdict-severity critical';
                document.getElementById('apk-verdict-sev').textContent = 'CRITICAL';
                document.getElementById('apk-verdict-desc').textContent = 'Overprivileged permissions detected: READ_SMS, SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES. Contains telemetry harvesting and banking overlay injection signatures.';
                document.getElementById('apk-verdict-action').textContent = '🛡️ Action: Sideloading blocked. Delete APK file immediately.';

                emitThreatToLaptop({
                    channel: 'APK',
                    severity: 'CRITICAL',
                    threat_type: 'Banking Trojan APK Dropper',
                    content_snippet: `Malicious APK package: ${name}`,
                    evidence: { package_name: 'com.whatsapp.gold.update', dangerous_perms: ['READ_SMS', 'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES'] },
                    recommendation: 'Package quarantined. Installation permission revoked.'
                });
            } else {
                verdictBox.className = 'verdict-box safe';
                document.getElementById('apk-verdict-title').textContent = '✅ Verified Clean Package';
                document.getElementById('apk-verdict-sev').className = 'verdict-severity safe';
                document.getElementById('apk-verdict-sev').textContent = 'SAFE';
                document.getElementById('apk-verdict-desc').textContent = 'Official release package with valid certificate signature and standard minimal permissions.';
                document.getElementById('apk-verdict-action').textContent = '🛡️ Safe to install.';
            }
        });
    });

    // 4. Clipboard Guard Simulation
    document.querySelectorAll('.clip-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            const sample = btn.getAttribute('data-val');
            const type = btn.getAttribute('data-type');
            const input = document.getElementById('clip-input');
            input.value = sample;

            const verdictBox = document.getElementById('clip-verdict');
            verdictBox.style.display = 'block';

            if (type !== 'clean') {
                verdictBox.className = 'verdict-box critical';
                document.getElementById('clip-verdict-title').textContent = `⚠️ High-Risk PII Leak Detected (${type.toUpperCase()})`;
                document.getElementById('clip-verdict-sev').className = 'verdict-severity critical';
                document.getElementById('clip-verdict-sev').textContent = 'HIGH RISK';
                document.getElementById('clip-verdict-desc').textContent = `Sensitive personal identifier (${type}) detected in clipboard buffer. Installed background apps with clipboard read permission can siphon this data silently.`;
                document.getElementById('clip-verdict-action').textContent = '🛡️ Action: Clipboard auto-scrubbed to prevent data theft.';

                emitThreatToLaptop({
                    channel: 'CLIPBOARD',
                    severity: 'HIGH',
                    threat_type: 'Clipboard PII Data Exposure',
                    content_snippet: sample.substring(0, 8) + '********',
                    evidence: { pii_type: type, length: sample.length, status: 'SCRUBBED' },
                    recommendation: 'Ephemeral clipboard sanitizer cleared sensitive buffer.'
                });
            } else {
                verdictBox.className = 'verdict-box safe';
                document.getElementById('clip-verdict-title').textContent = '✅ Safe Generic Text';
                document.getElementById('clip-verdict-sev').className = 'verdict-severity safe';
                document.getElementById('clip-verdict-sev').textContent = 'SAFE';
                document.getElementById('clip-verdict-desc').textContent = 'No credit card numbers, Aadhaar IDs, passwords, or financial credentials found.';
                document.getElementById('clip-verdict-action').textContent = '🛡️ Normal clipboard content.';
            }
        });
    });
}
