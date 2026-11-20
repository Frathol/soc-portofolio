# Linux Administration & Triage Cheatsheet

Quick reference for host enumeration, log parsing, persistence checks, and daily Linux troubleshooting.

## System & Host Triage

```bash
# OS, kernel, architecture, hostname
uname -a
cat /etc/os-release
hostnamectl

# Uptime, load average, and currently logged-in users
w
who -a
last -n 15                  # recent logins
lastb -n 15                 # failed login attempts (requires root)

# Environment variables and mounted filesystems
env
lsblk -f
df -hT
mount | column -t
```

## Users, Groups & Privileges

```bash
# Current identity, UID/GID, and group memberships
id
whoami

# List accounts with interactive login shells
grep -Ev "(nologin|false|sync)$" /etc/passwd

# Check accounts with UID 0 (root equivalents)
awk -F: '($3 == 0) {print $1}' /etc/passwd

# Inspect sudo privileges and sudoers rules
sudo -l
cat /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/

# Check group memberships for a specific user
groups <username>
getent group sudo wheel docker adm
```

## Filesystem, Search & Special Permissions

```bash
# Find files by name/size while suppressing permission errors
find / -type f -name "*.conf" 2>/dev/null
find / -type f -size +50M 2>/dev/null

# Find recently modified files (last 24 hours) — useful during incident triage
find /etc /var/www /tmp -type f -mtime -1 2>/dev/null

# World-writable directories and files
find / -type d -perm -0002 ! -path "/proc/*" 2>/dev/null

# SUID (4000) and SGID (2000) binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Linux capabilities assigned to binaries
getcap -r / 2>/dev/null

# Inspect extended attributes (e.g., immutable flag 'i')
lsattr /etc/passwd /etc/shadow
```

## Processes, Open Files & Persistence

```bash
# Full process tree with command lines
ps auxf
ps -eo pid,ppid,user,stat,lstart,cmd --sort=start_time

# Inspect deleted binaries still running in memory (common malware indicator)
ls -al /proc/*/exe 2>/dev/null | grep "(deleted)"

# Open network connections and files held by a process
lsof -i -P -n
lsof -p <PID>

# Running systemd services & custom unit files
systemctl list-units --type=service --state=running
ls -la /etc/systemd/system/
systemctl list-timers --all

# Cron jobs (user & system-wide)
crontab -l
ls -la /etc/crontab /etc/cron.* /var/spool/cron/crontabs/

# Shell initialization & SSH key persistence
ls -la ~/.bashrc ~/.profile ~/.bash_profile /etc/profile.d/
cat ~/.ssh/authorized_keys
```

## Log Inspection & Text Pipelines

```bash
# systemd journal queries
journalctl -u ssh --since "2 hours ago" --no-pager
journalctl -p err -n 50 --no-pager
journalctl _UID=0 --since today

# Top source IPs with failed SSH logins (Debian/Ubuntu)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -n 15

# Successful SSH logins (password & publickey)
grep -E "Accepted (password|publickey)" /var/log/auth.log

# Extract top requested URLs and status codes from Nginx/Apache access logs
awk '{print $9, $7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -n 20

# Quick recursive string search in configs/logs (ignore binary files)
grep -rnI "password\|secret\|token" /etc/ /var/www/ 2>/dev/null
```

## File Transfer & Integrity

```bash
# Serve current directory over HTTP
python3 -m http.server 8000

# Download file via curl or wget
curl -fsSL http://<ip>:8000/file -o /tmp/file
wget -q http://<ip>:8000/file -O /tmp/file

# Hash verification (IOC / file integrity)
sha256sum <file>
md5sum <file>
```

| Path | Purpose |
| :--- | :--- |
| `/var/log/auth.log` or `/var/log/secure` | Authentication, SSH, and `sudo` logs |
| `/var/log/syslog` or `/var/log/messages` | General system and daemon events |
| `/proc/<pid>/cmdline` & `/proc/<pid>/exe` | Live process arguments and binary path |
| `/tmp` & `/dev/shm` | World-writable directories (high-priority triage spots) |
