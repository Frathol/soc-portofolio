# Security Operations & Systems Portfolio

Personal technical repository for documenting hands-on labs, OS internals, network analysis, and detection notes. Maintained both as a fast reference for daily troubleshooting and as a public log of my preparation for Security Operations (SOC) roles.

## Background & Technical Baseline

* **Systems & OS:** Linux (Arch/Debian administration, shell scripting, systemd, permissions) and Windows (Registry, WMI/CIM, Event Viewer, PowerShell, SMB).
* **Networking:** TCP/IP, VLANs, routing fundamentals, DHCP/DNS/NAT troubleshooting, packet inspection (`tcpdump`, Wireshark), and network monitoring.
* **Security Focus:** Log analysis, system enumeration, incident investigation, and mapping offensive techniques to blue-team detection artifacts.

## Active Roadmap

Currently focusing on building a hybrid Red/Blue foundation before specializing in detection and incident response.

| Track | Platform | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Junior Cybersecurity Analyst (CJCA)** | HTB Academy | In Progress | Core OS, networking, enumeration, and monitoring basics |
| **SOC Analyst (CDSA)** | HTB Academy | Planned | SIEM (Elastic/Splunk), Sysmon, threat hunting |
| **Starting Point & Sherlocks** | HTB Labs | Planned | Live box write-ups and DFIR/log investigations |
| **Detection Homelab** | Local VM | Planned | Wazuh/Elastic SIEM + Windows Sysmon attack simulation |

## Completed Modules & Logs

### HTB Academy — Junior Cybersecurity Analyst

* [x] [Linux Fundamentals](academy/01-cjca/linux-fundamentals.md) — filesystem hierarchy, permissions, process management, text processing
* [x] [Windows Fundamentals](academy/01-cjca/windows-fundamentals.md) — Registry hives, UAC, services, WMI/CIM, SIDs, SMB shares
* [ ] Introduction to Networking
* [ ] Web Requests
* [ ] Network Enumeration with Nmap

## Quick Reference Cheatsheets

Commands I actually use and revisit when debugging or running labs:

* [Linux Administration & Enumeration](cheatsheets/linux.md)
* [Windows PowerShell, CMD & Registry](cheatsheets/windows.md)
* [Networking & Packet Analysis](cheatsheets/networking.md)

## Projects

* **`siem-homelab`** *(Upcoming)* — Local detection lab simulating common Windows/Linux attack techniques and mapping telemetry to MITRE ATT&CK.

---

*Note: All Hack The Box notes focus on concepts, syntax, and defensive takeaways. No active machine spoilers or Academy assessment flags are published here.*
