# 📞 GoidaPhone v1.8 `NT Server Edition`

![Status](https://img.shields.io/badge/Status-In_Development-orange?style=for-the-badge&logo=git)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![UI](https://img.shields.io/badge/Interface-PyQt6-green?style=for-the-badge&logo=qt)
![Platform](https://img.shields.io/badge/Platform-Linux_|_Windows-lightgrey?style=for-the-badge&logo=gentoo)

---

### 🚀 Project Overview
**GoidaPhone** is a high-performance communication suite specifically engineered for operation within local networks (LAN) and VPN tunnels. The project aims to provide a lightweight, secure alternative to modern Electron-based messengers by utilizing a native-feeling UI and a highly optimized Python backend.

> [!IMPORTANT]
> This project is currently under active development. Some features may be experimental or in the testing phase.

---

## 🏗 Key Features

| Feature | Description |
| :--- | :--- |
| **Hybrid Networking** | Optimized stack: TCP for reliable messaging and UDP streams for low-latency VoIP. |
| **Advanced Security** | End-to-End Encryption (E2EE) using **AES-256-CBC** with PBKDF2 key derivation. |
| **Media Engine** | Integrated **Mewa 1-2-3** stack for seamless media processing and playback. |
| **Legacy UI/UX** | Deep integration with **KDE Plasma 6** featuring a visual style inspired by classic NT Server systems. |
| **System Resilience** | Custom **GoidaDeathScreen** handler for detailed diagnostics during system crashes. |

---

## 🛠 Technical Stack

* **Core Engine:** Python 3.10+ (over 19,000 lines of code)
* **Frontend UI:** PyQt6 (Qt 6.x) with custom corporate-retro styling.
* **Audio Processing:** WebRTC VAD (Voice Activity Detection) for silence suppression.
* **Cryptography:** Implemented using standard libraries to ensure maximum portability.

---

## 🗺 System Architecture (Class Diagram)
The following diagram illustrates the internal structure, class inheritance, and module relationships of the GoidaPhone engine, automatically generated from the source code.

<p align="center">
  <a href="classes_GoidaPhone.png">
    <img src="classes_GoidaPhone.png" alt="GoidaPhone Visual Structure" width="100%">
  </a>
</p>

*Click the image to view it in full resolution.*

---



## 💻 Plug & Play

 **dependencies and startup (Windows/Linux(GNU)**
   ```bash
   #WINDOWS
   # 1. Clone the repository
    git clone https://github.com/nft1212/GoidaPhone-NT-Server-1.8-OPEN.git

    # 2. Navigate to project folder
    cd GoidaPhone-NT-Server-1.8-OPEN

    # 3. Create virtual environment (to keep system clean)
    python -m venv venv

    #  4. Activate virtual environment
    venv\Scripts\activate

    # 5. Install dependencies (Windows-specific)
    pip install -r requirements-windows.txt

    # 6. Launch GoidaPhone!
    python gdf.py

  #!!!-------------------!!!
  #!!!---------END-------!!!
  #!!!-------------------!!!
  
  #LINUX(GNU)
  # 1. Clone the repository
git clone https://github.com/nft1212/GoidaPhone-NT-Server-1.8-OPEN.git

# 2. Navigate to project folder
cd GoidaPhone-NT-Server-1.8-OPEN

# 3. Create virtual environment (to keep system clean)
python3 -m venv venv

# 4. Activate virtual environment
source venv/bin/activate

# 5. Install system dependencies (choose your distribution)

#!!!!CHOOSE WHAT DO YOU NEED!!!! #(Gentoo/Ubuntu/Debian/Fedora/Arch)
# For Gentoo Linux:
#sudo emerge --ask dev-python/pip dev-vcs/git media-libs/portaudio

# For Ubuntu/Debian:
# sudo apt update && sudo apt install portaudio19-dev python3-pip git -y

# For Fedora:
# sudo dnf install portaudio-devel python3-pip git

# For Arch Linux:
# sudo pacman -S portaudio python-pip git

# 6. Install Python dependencies (Linux-specific)
pip install -r requirements-linux.txt

# 7. Launch GoidaPhone!
python gdf.py

#!!!-------------------!!!
#!!!---------END-------!!!
#!!!-------------------!!!
