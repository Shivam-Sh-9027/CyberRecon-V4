# ⚡ CyberRecon V4 — Advanced Reconnaissance Automation Framework

> ⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY**
> Unauthorized use of this tool is illegal.

---

## 🚀 Overview

**CyberRecon V4** is a powerful, all-in-one reconnaissance automation framework designed for penetration testers and security researchers.

It automates the complete reconnaissance process — from subdomain enumeration to vulnerability detection — in a single streamlined workflow.

---

## 🔥 Features

* 🌐 Subdomain Enumeration (Passive + Active)
* 🕵️ OSINT Collection (Emails, WHOIS, Breach Data)
* 🗺️ DNS & Infrastructure Mapping
* 🛡️ Web Technology & WAF Detection
* ⚡ Live Host Detection (httpx)
* 🕷️ Web Crawling (katana + waybackurls)
* 🔎 Attack Surface Expansion (Endpoints & Parameters)
* 🔌 Network Scanning (Nmap)
* 💀 Vulnerability Scanning (Nuclei)
* 📊 Automated Report Generation (TXT, JSON, HTML)

---

## 🧠 Why CyberRecon V4?

* ✔️ Fully automated recon pipeline
* ✔️ Real-world pentesting workflow
* ✔️ Multi-tool integration
* ✔️ Clean & structured output
* ✔️ Saves hours of manual work

---

## ⚙️ Requirements

* Kali Linux / Parrot OS / Debian-based system
* Bash
* Tools required:

```
nmap
nuclei
httpx
sublist3r
theHarvester
dnsrecon
dnsenum
whatweb
wafw00f
katana
waybackurls
httrack
```

---

## 🛠️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/CyberRecon-V4.git
cd CyberRecon-V4
chmod +x cyberrecon_v4.sh
```

---

## ▶️ Usage

```bash
sudo bash cyberrecon_v4.sh -d example.com
```

### 🔹 Options

```bash
-d  --domain     Target domain
-i  --ip         Target IP
-u  --url        Target URL

-p  --passive-only
-a  --active-only

--skip-nmap
--skip-nuclei
--skip-mirror
```

---

## 📂 Output Structure

```
recon_target_timestamp/
 ├── passive/
 ├── active/
 ├── dns/
 ├── web/
 ├── network/
 ├── osint/
 ├── endpoints/
 └── reports/
```

### 📊 Reports Generated:

* TXT Report
* JSON Report
* HTML Report

---

## 📸 Screenshots

### 🔹 Tool_Help
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-41-27.png" width="800">
</p>

### 🔹 Subdomain Enumeration
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-15-47.png" width="800">
</p>

### 🔹 Subdomain Results
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-15-57.png" width="800">
</p>

### 🔹 More Subdomains
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-16-04.png" width="800">
</p>

### 🔹 Final Subdomain List
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-16-22.png" width="800">
</p>

### 🔹 OSINT Collection
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-16-44.png" width="800">
</p>

### 🔹 Web Tech & Active Recon
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-29-32.png" width="800">
</p>

### 🔹 Terminal Dashboard
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-30-51.png" width="800">
</p>

### 🔹 Target Summary
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-31-08.png" width="800">
</p>

### 🔹 DNS Records
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-31-19.png" width="800">
</p>

### 🔹 Parameters & Endpoints
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-31-31.png" width="800">
</p>

### 🔹 Google Dorks
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-31-49.png" width="800">
</p>

### 🔹 Attack Surface
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-32-04.png" width="800">
</p>

### 🔹 HTML Report Dashboard
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-32-56.png" width="800">
</p>

### 🔹 HTML Report – Subdomains
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-33-13.png" width="800">
</p>

### 🔹 HTML Report – Details
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-33-24.png" width="800">
</p>

### 🔹 HTML Report – Final View
<p align="center">
  <img src="Screenshots/Screenshot From 2026-04-06 13-33-39.png" width="800">
</p>
---

## ⚠️ Disclaimer

This tool is created for **educational and authorized security testing only**.
The author is not responsible for any misuse of this tool.

---

## 👨‍💻 Author

**Shivam Sharma**
Cybersecurity Enthusiast | Pentester

---

## ⭐ Support

If you found this useful:

* ⭐ Star the repository
* 🍴 Fork it
* 🧠 Share feedback

---

## 🔥 Future Improvements

* AI-based vulnerability prioritization
* Dashboard UI
* API integration
* Cloud scanning support

---
