# JEHAD - Global Security Auditing & Incident Response Tool

**JEHAD** is an advanced, lightweight, and automated cybersecurity auditing and incident response tool written in Python. Designed for security professionals, penetration testers, and system administrators to perform rapid network monitoring, deep port auditing, vulnerability mapping, and immediate emergency isolation.

---

## 🇸🇦 🌴 ⚔️ Identity & Branding
* **Tool Name:** JEHAD
* **Symbol:** Two Swords & Palm Tree (KSA National Identity)
* **Author:** Jehad Alhisni

---

## 🚀 Key Features

1. **Global Active Connections Monitor (`Module 1`):**
   - Extracts active TCP/UDP sessions and socket states globally or filtered by a specific target IP using `ss`.
2. **Deep Nmap Port & Service Audit (`Module 2`):**
   - Performs a comprehensive, deep scan across all **65535 ports** with service version detection and script scanning (`-sV -sC -p-`).
3. **Full-Spectrum Vulnerability Mapping (`Module 3`):**
   - Instantly maps open ports to known historical and critical vulnerabilities (such as MS03-026, EternalBlue MS17-010, BlueKeep, and more).
4. **Global Incident Response & Network Isolation (`Module 4`):**
   - Immediately isolates and quarantines malicious or compromised hosts from the network using automated UFW firewall rules.
5. **Global CLI Support:**
   - Run any module directly from the command line using arguments for automated scripts and global accessibility.

---

## 🛠️ Installation

Clone the repository to your local machine (Kali Linux / Linux environment):

```bash
git clone [https://github.com/YOUR_USERNAME/jehad-tool.git](https://github.com/YOUR_USERNAME/jehad-tool.git)
cd jehad-tool
