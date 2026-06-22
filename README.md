# YUNA Firewall

![YUNA Firewall](https://img.shields.io/badge/Status-Active-brightgreen)
![C++17](https://img.shields.io/badge/C++-17-blue.svg)
![Qt](https://img.shields.io/badge/Qt-5%20%7C%206-41cd52.svg)

YUNA Firewall is an advanced, multi-threaded Network Security and Management platform. Built using modern **C++17** and the **Qt Framework**, it features real-time network topology visualization, advanced threat intelligence, deep packet inspection, an intrusion prevention system, and a robust Web Application Firewall (WAF).

---

## 🌟 Core Features

### 1. Dynamic Network Topology Graphic Mapper
Visualizes your network in real-time. Nodes (IPs) and edges (connections) are dynamically mapped onto a smooth Qt Graphics Scene with active traffic flow animations. 

### 2. Deep Packet Inspection (DPI)
Breaks down packets beyond the traditional OSI layer 3/4 headers. It analyzes application-layer data to identify specific protocols including **HTTP, HTTPS (TLS), DNS, and SSH**.

### 3. Intrusion Prevention System (IPS)
Employs the ultra-fast **Boyer-Moore string search algorithm** to rapidly scan packet payloads against a database of known malicious signatures. It actively drops malicious packets.

### 4. Captive Portal
A built-in HTTP server that forces unauthenticated network users to a login page before granting internet access. Designed for secure guest network management.

### 5. Web Application Firewall (WAF) & Reverse Proxy
A custom multi-threaded reverse proxy server that sits in front of web applications. It inspects incoming HTTP requests for:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal Attacks
- OS Command Injection

### 6. Additional Security Layers
- **Threat Intelligence Synchronizer:** Keeps malicious IP lists and signatures updated.
- **Honeypot Manager:** Deploys decoy servers to trap attackers.
- **QoS Manager:** Manages bandwidth limits and network traffic prioritization.
- **VPN Pool Manager:** Handles secure virtual private network tunneling configurations.

---

## 🏗️ Architecture & Code Structure

The application is modular and heavily multi-threaded to ensure the GUI remains highly responsive while doing intense packet processing.

*   **`FirewallManager` (`src/FirewallManager.cpp`):** The central controller. It owns and orchestrates all the individual subsystem engines (IPS, WAF, DPI, Sniffer) and controls the global state and configuration via thread-safe mutexes.
*   **`PacketSniffer` (`src/PacketSniffer.cpp`):** Uses `libpcap` to capture raw network traffic from the Network Interface Card (NIC). Runs on a dedicated background thread.
*   **`mainwindow` (`src/mainwindow.cpp`):** The Qt GUI. Contains the layouts, tabs, charts, and tables for real-time visualization. Connects via Qt Signals and Slots to update the UI safely from background threads.
*   **Cross-Platform Sockets:** Network code (`WafProxy`, `CaptivePortal`) uses preprocessor directives (`#ifdef _WIN32`) to utilize **Winsock** on Windows and **POSIX** sockets on Linux.

---

## 🚀 Installation & Setup Guide

### 🐧 Linux (Debian / Ubuntu)

Building on Linux is highly streamlined via the package manager.

**1. Install Prerequisites:**
```bash
sudo apt update
sudo apt install build-essential qtbase5-dev qt5-qmake libpcap-dev libcurl4-openssl-dev libreadline-dev
```

**2. Compile:**
```bash
cd yunademo01-main
qmake yunademo01.pro
make -j4
```

**3. Run (Requires Root for Packet Sniffing):**
```bash
sudo ./yunademo01
```

---

### 🪟 Windows Setup

Windows requires manual linking of network and web dependencies inside Qt Creator.

**1. Development Environment:**
*   Install [Qt Open Source](https://www.qt.io/download). Make sure to include the **MinGW 64-bit** compiler during setup.

**2. Install Dependencies:**
*   **Npcap:** Download and install [Npcap](https://npcap.com/#download). **Must check the box:** *"Install Npcap in WinPcap API-compatible Mode"*.
*   **Npcap SDK:** Download the Npcap SDK. Extract it to a known location (e.g., `C:\npcap-sdk`).
*   **cURL:** Download the libcurl development headers/libs for MinGW.

**3. Configure Qt Creator:**
Open `yunademo01.pro` in Qt Creator and update the `INCLUDEPATH` and `LIBS` to point to where you extracted the Npcap SDK and cURL.
```pro
INCLUDEPATH += "C:/path/to/npcap-sdk/Include"
INCLUDEPATH += "C:/path/to/curl/include"

LIBS += -L"C:/path/to/npcap-sdk/Lib/x64" -lpcap
LIBS += -L"C:/path/to/curl/lib" -lcurl
```

**4. Run (Requires Administrator):**
*   Right-click the Qt Creator icon and select **Run as Administrator**.
*   Open the project, configure with the MinGW kit, and press the green Run button.

---

## 🖥️ User Guide

Once the application launches with elevated privileges (root/admin):

1.  **Dashboard:** The main dashboard provides an overview of active connections, dropped packets, and threat statistics.
2.  **Topology:** Navigate to the `Topology` tab to see a real-time, animated node graph of IPs communicating across your network.
3.  **WAF Configuration:** Go to the `WAF Settings` tab to modify the Reverse Proxy Target Port, edit security rules, and view blocked injection attempts.
4.  **DPI & IPS:** The `Threats/DPI` tab shows real-time protocol breakdown and logs of packets dropped by the Boyer-Moore IPS scanner.
5.  **Captive Portal:** Can be toggled on/off to force local network users to authenticate on port 8082 before traffic is routed.

---

## 🛠️ Built With
*   [Qt](https://www.qt.io/) - GUI Framework
*   [libpcap/Npcap](https://www.tcpdump.org/) - Network Packet Capture
*   [libcurl](https://curl.se/) - Client URL Request Library

## 📄 License
This project is proprietary and confidential.
