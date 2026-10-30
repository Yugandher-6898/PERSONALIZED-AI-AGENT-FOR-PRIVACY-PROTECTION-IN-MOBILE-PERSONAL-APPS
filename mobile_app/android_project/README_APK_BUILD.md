# CyberShield AI • Native Android APK Build Guide

This directory contains the configuration files to compile the **CyberShield AI Mobile Guardian** into a native standalone Android `.apk` package.

## Quick Option 1: Instant PWA Install (Recommended)
You can install the app on your phone **instantly** without compiling Android Studio:
1. Make sure your phone is connected to the same Wi-Fi as your laptop.
2. Open `INSTALL_MOBILE_APP.html` in the parent folder, or scan the QR code displayed on your Laptop Dashboard.
3. In Chrome on your phone, tap **"Add to Home Screen"** or **"Install App"**.
4. The CyberShield icon will appear on your phone home screen and launch fullscreen with hardware acceleration.

---

## Option 2: Native APK Packaging via Capacitor / Node.js
If you want to generate a signed or debug `.apk` file:

### Prerequisites:
- Node.js (v18+)
- Android Studio / Android SDK (API 34)

### Build Steps:
```bash
# 1. Install Capacitor CLI
npm install -g @capacitor/cli @capacitor/core @capacitor/android

# 2. Add Android Platform
npx cap add android

# 3. Copy web assets
npx cap copy

# 4. Open in Android Studio & Generate APK
npx cap open android
# Inside Android Studio: Click Build -> Build Bundle(s) / APK(s) -> Build APK(s)
```

The compiled APK will be output to:
`android/app/build/outputs/apk/debug/app-debug.apk`
