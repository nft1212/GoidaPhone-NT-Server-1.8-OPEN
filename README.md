# GoidaPhone v1.8 (NT Server Edition)

A performance-oriented LAN/VPN messenger built with Python and PyQt6. Designed with a focus on security, low-latency communication, and a distinctive legacy corporate aesthetic.

> !!! IN DEVELOPMENT !!!

---

## 📖 Project Overview
GoidaPhone is a cross-platform communication suite designed for local networks and VPN environments. It aims to provide a robust alternative to modern Electron-based messengers by utilizing a native-feeling UI and an optimized Python backend.

The project currently consists of over 17,000 lines of code, covering everything from custom networking protocols to encrypted data storage.

## 🏗 Key Features (Current State)
* **Hybrid Networking:** Optimized TCP for messaging and UDP-based streams for voice data.
* **Security:** End-to-end encryption using AES-256-CBC (standard library implementation for maximum portability).
* **Integrated Media:** Features the "Mewa 1-2-3" built-in media engine for handling assets within the app.
* **Legacy UI:** A highly customized interface designed to integrate seamlessly with KDE Plasma 6 while maintaining a classic NT-inspired look.
* **Resilience:** Built-in crash handling via the "GoidaDeathScreen" system for detailed debugging.

## 🛠 Tech Stack
- **Language:** Python 3.10+
- **GUI:** PyQt6 (Qt 6.x)
- **Audio:** WebRTC VAD (Voice Activity Detection)
- **Platforms:** Primarily developed on **Gentoo Linux**, compatible with modern Linux distros and Windows.


