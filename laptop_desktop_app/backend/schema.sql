-- Schema for Personalized AI Agent for Privacy Protection in Mobile Personal Apps
-- Supports cross-platform monitoring (Android & Windows), Normal Mode & Student Mode

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL, -- ANDROID, WINDOWS, MOBILE, LAPTOP
    os_version TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    battery_level INTEGER DEFAULT 85,
    privacy_score INTEGER DEFAULT 85,
    status TEXT NOT NULL DEFAULT 'ONLINE',
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_events (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    channel TEXT NOT NULL, -- WHATSAPP, UPI_QR, APK_DOWNLOAD, CLIPBOARD_PII
    threat_title TEXT NOT NULL,
    threat_category TEXT NOT NULL,
    risk_level TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    content_snippet TEXT,
    explanation_normal_what TEXT,
    explanation_normal_leak TEXT,
    explanation_normal_action TEXT,
    status TEXT NOT NULL DEFAULT 'INTERCEPTED', -- INTERCEPTED, BLOCKED, INVESTIGATING, RESOLVED
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS student_forensics (
    event_id TEXT PRIMARY KEY,
    mitre_tactic TEXT NOT NULL,
    mitre_technique_id TEXT NOT NULL,
    mitre_technique_name TEXT NOT NULL,
    ioc_indicators TEXT, -- JSON or formatted string
    disassembly_payload TEXT,
    defensive_code TEXT,
    cwe_mapping TEXT,
    FOREIGN KEY(event_id) REFERENCES threat_events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    software_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    patched_version TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    severity TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    summary TEXT NOT NULL,
    remediation_action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, PATCHED
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS trackers (
    id TEXT PRIMARY KEY,
    app_name TEXT NOT NULL,
    package_name TEXT NOT NULL,
    telemetry_domain TEXT NOT NULL,
    tracker_category TEXT NOT NULL, -- Advertising, Analytics, Device Fingerprinting, Location Profiling
    destination_ip TEXT,
    status TEXT NOT NULL DEFAULT 'BLOCKED', -- BLOCKED, FILTERED, ALLOWED
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_profile (
    user_id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    sensitivity_level TEXT NOT NULL DEFAULT 'BALANCED', -- BALANCED, MAX_PRIVACY, PERMISSIVE
    student_mode_enabled INTEGER NOT NULL DEFAULT 0, -- 0 = Normal Mode, 1 = Student Mode
    last_defense_score INTEGER DEFAULT 84,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sandbox_lab_runs (
    id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    rule_selected TEXT NOT NULL,
    score INTEGER NOT NULL,
    defense_verdict TEXT NOT NULL,
    terminal_log TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
