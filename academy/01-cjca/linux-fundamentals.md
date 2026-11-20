# Linux Fundamentals

**Source:** HTB Academy (CJCA Path)  
**Focus:** Filesystem hierarchy, text processing, redirection, permissions, process/service management, and basic networking.

## Key Concepts to Remember

* **Filesystem Hierarchy (FHS):**
  * `/etc` — system-wide configuration files (`passwd`, `shadow`, `sudoers`, `hosts`).
  * `/var/log` — system, auth, and application logs.
  * `/tmp` & `/dev/shm` — world-writable temporary storage (often used to drop payloads/scripts).
  * `/opt` — third-party or manually installed software.
  * `/proc` — virtual filesystem exposing live kernel and process data in memory.
* **File Descriptors & Redirection:** `0` = stdin, `1` = stdout, `2` = stderr. Use `2>/dev/null` to suppress permission-denied noise during enumeration, and `2>&1` to merge stderr into stdout.
* **Users & Credentials:** `/etc/passwd` is world-readable and lists user accounts, UIDs (`0` = root, `1000+` = regular users), home directories, and login shells. `/etc/shadow` stores salted password hashes and is restricted to `root`/`shadow`.
* **Special Permissions:**
  * **SUID (`4xxx`):** Executes a binary with the file owner's privileges (usually `root`).
  * **SGID (`2xxx`):** Executes with group privileges, or forces new files in a directory to inherit the group.
  * **Sticky Bit (`1xxx`):** Applied on shared directories like `/tmp` so users can only delete their own files.

## Commands Worth Keeping

```bash
# Find files by name/type/size while silencing permission errors
find / -type f -name "*.conf" -size +10k 2>/dev/null

# Enumerate binaries with the SUID bit set
find / -perm -4000 -type f 2>/dev/null

# List non-system users with an interactive shell
grep -E "/(bash|sh|zsh)$" /etc/passwd | cut -d":" -f1,3,7

# Text filtering pipeline (extract, normalize, count unique occurrences)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# Inspect active processes and parent-child tree
ps auxf

# Check listening TCP/UDP ports and owning processes (modern replacement for netstat)
ss -tulpn

# Inspect running systemd services and recent service logs
systemctl list-units --type=service --state=running
journalctl -u ssh --since "1 hour ago"

# Check scheduled tasks (user and system-wide)
crontab -l
ls -la /etc/cron* /var/spool/cron/crontabs/

# Quick file transfer / local HTTP listener
python3 -m http.server 8000
curl -s http://<ip>:8000/script.sh -o /tmp/script.sh
```

## Blue Team / SOC Takeaways

* **Privilege Escalation Signals:** Unexpected SUID binaries outside standard system paths (`/usr/bin`, `/bin`) or misconfigured `sudo -l` entries map to **MITRE ATT&CK `T1548.001` / `T1548.003`**.
* **Persistence Hotspots:** Audit `/etc/crontab`, `/etc/cron.d/`, custom `.service` unit files under `/etc/systemd/system/`, `~/.bashrc`, and `~/.ssh/authorized_keys` (**`T1053.003`**, **`T1543.002`**).
* **Log & Artifact Locations:** Monitor `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) and `journalctl` for brute-force SSH attempts, `sudo` abuse, and newly created UID `0` accounts.
* **Suspicious Execution Paths:** Processes running out of `/tmp`, `/dev/shm`, or `/var/tmp`—visible via `ps aux` or `/proc/<pid>/exe`—are high-priority indicators during triage.
