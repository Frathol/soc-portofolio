# Networking, Packet Analysis & Enumeration Cheatsheet

Reference for interface debugging, DNS/HTTP inspection, packet captures, Nmap scanning, and remote access.

## Interface, Routing & Socket Diagnostics

```bash
# Linux interfaces, IP addresses, routing table, ARP/neighbor cache
ip -br a
ip route show
ip neigh show

# Listening and established TCP/UDP sockets with PIDs
ss -tulpn
ss -antp

# Check active DNS resolvers and local overrides
resolvectl status 2>/dev/null || cat /etc/resolv.conf
cat /etc/hosts
```

```cmd
:: Windows network diagnostics
ipconfig /all
route print
arp -a
netstat -ano
```

## DNS & HTTP Inspection

```bash
# DNS lookups (A, MX, TXT, NS, reverse PTR)
dig example.com ANY +noall +answer
dig @<dns-ip> example.com A +short
dig -x <ip> +short

# Attempt DNS zone transfer (AXFR)
dig axfr @<dns-ip> <domain>

# Inspect HTTP response headers only
curl -I -k https://<target>

# Verbose HTTP request (TLS handshake, headers, redirects)
curl -v -L http://<target>

# Send POST data with custom header
curl -s -X POST http://<target>/api -H "Content-Type: application/json" -d '{"user":"test"}'
```

## Packet Capture (`tcpdump` & `tshark`)

```bash
# Capture on specific interface without DNS/port resolution (faster, cleaner)
sudo tcpdump -i eth0 -nn

# Capture traffic for a specific host and port, save to PCAP
sudo tcpdump -i tun0 -nn host 10.129.40.192 and port 445 -w smb_capture.pcap

# Read PCAP with ASCII payload preview (good for cleartext HTTP/FTP/Telnet)
tcpdump -r capture.pcap -nn -A

# Capture only TCP SYN packets (detect port scans)
sudo tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'

# Extract DNS queries from a PCAP using tshark
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name

# Extract HTTP hosts, methods, and URIs from a PCAP
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.request.method -e http.host -e http.request.uri
```

### Useful Wireshark Display Filters

| Filter | What It Shows |
| :--- | :--- |
| `ip.addr == 10.129.40.192` | Traffic to or from a specific IP |
| `tcp.port == 445 && !tcp.analysis.keep_alive` | SMB traffic excluding keep-alives |
| `http.request.method == "POST"` | HTTP POST requests (logins, uploads, C2 check-ins) |
| `dns.qry.name contains "evil"` | DNS queries matching a substring |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Connection attempts / SYN scans |
| `tls.handshake.type == 1` | TLS Client Hello (inspect SNI domain names) |
| `smb2.filename` | Filenames accessed over SMBv2/v3 |
| `frame contains "flag"` | Raw string match anywhere in packet payload |

## Nmap Scanning Profiles

```bash
# Host discovery (ping sweep without port scan)
nmap -sn 10.129.40.0/24

# Fast initial TCP scan (top 1000 ports)
nmap -sS -T4 --open <target>

# Full TCP port scan (all 65,535 ports)
nmap -p- --min-rate 1500 -T4 <target> -oN all_ports.txt

# Service version + default NSE scripts on discovered ports
nmap -sC -sV -p 22,80,445,3389 <target> -oA detailed_scan

# Top 50 UDP ports (SNMP, DNS, TFTP, etc.)
sudo nmap -sU --top-ports 50 <target>

# Specific NSE script enumeration (e.g., SMB shares & OS discovery)
nmap --script smb-enum-shares,smb-os-discovery -p 445 <target>
```

## Remote Access, Listeners & Tunneling

```bash
# RDP from Linux (quote passwords containing '!' to prevent shell history expansion)
xfreerdp3 /v:<ip> /u:<user> /p:'<password>' /dynamic-resolution +clipboard /cert:ignore

# RDP with local folder mounted as a shared drive inside Windows
xfreerdp3 /v:<ip> /u:<user> /p:'<password>' /dynamic-resolution +clipboard /cert:ignore /drive:share,/tmp/share

# Netcat listener and manual banner grabbing
nc -lvnp 4444
nc -nv <target> 80

# SSH Local Port Forwarding (access remote internal 127.0.0.1:8080 via local 9090)
ssh -L 9090:127.0.0.1:8080 user@<jump-host>

# SSH Dynamic SOCKS5 Proxy (pivot via proxychains on local port 1080)
ssh -D 1080 -N -f user@<jump-host>
```

## Common Ports Reference

| Port | Proto | Service | Security / Triage Focus |
| :--- | :--- | :--- | :--- |
| `21` | TCP | FTP | Cleartext creds, anonymous login |
| `22` | TCP | SSH | Brute-force (`auth.log`), key persistence |
| `53` | TCP/UDP | DNS | Tunneling/exfiltration, zone transfers |
| `80`/`443` | TCP | HTTP/HTTPS | Web attacks, C2 beaconing, reverse proxies |
| `88` | TCP/UDP | Kerberos | Active Directory auth, Kerberoasting |
| `135`/`139` | TCP | RPC / NetBIOS | Windows enumeration |
| `389`/`636` | TCP | LDAP/LDAPS | AD enumeration, credential spraying |
| `445` | TCP | SMB | File shares, lateral movement, ransomware spread |
| `3389` | TCP | RDP | Brute-force, lateral movement (`Event ID 4624 Type 10`) |
| `5985`/`5986` | TCP | WinRM | Remote PowerShell administration & lateral movement |
