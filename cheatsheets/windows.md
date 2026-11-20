# Windows PowerShell, CMD & Registry Cheatsheet

Practical commands for Windows enumeration, system administration, Registry inspection, WMI/CIM queries, and SOC triage.

## Host & OS Triage

```powershell
# OS version, build, architecture, hotfixes
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber
Get-HotFix | Sort-Object InstalledOn -Descending

# OS serial number via CIM (note: Win32_BIOS returns VM UUID on hypervisors)
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, SerialNumber, LastBootUpTime

# Environment variables and drives
Get-ChildItem Env:
Get-PSDrive -PSProvider FileSystem
```

```cmd
:: CMD equivalents
systeminfo
hostname
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

## Users, Groups & Sessions

```powershell
# Current user, groups, SID, and token privileges
whoami /all

# Local accounts and security groups with SIDs
Get-LocalUser | Select-Object Name, Enabled, LastLogon, SID
Get-LocalGroup | Select-Object Name, SID
Get-LocalGroupMember -Group "Administrators"

# Active local and RDP sessions
qwinsta
query user
```

```cmd
:: CMD equivalents
net user
net user <username>
net localgroup Administrators
wmic useraccount get name,sid
```

### Notable Windows SIDs / RIDs

| SID / RID | Identity |
| :--- | :--- |
| `S-1-5-18` | `NT AUTHORITY\SYSTEM` |
| `S-1-5-19` | `LOCAL SERVICE` |
| `S-1-5-20` | `NETWORK SERVICE` |
| `...-500` | Built-in Administrator (even if renamed) |
| `...-501` | Built-in Guest |
| `...-1000+` | Standard local users and custom groups |

## Filesystem, Shares & Forensic Artifacts

```powershell
# List all items including hidden/system files (spot non-standard C:\ folders)
Get-ChildItem -Path C:\ -Force

# Recursive filename search (ignore access-denied errors)
Get-ChildItem -Path C:\ -Filter "*pass*" -Recurse -ErrorAction SilentlyContinue

# Search text inside files (PowerShell grep)
Select-String -Path "C:\inetpub\*" -Pattern "password|apikey|connectionstring" -Recurse -ErrorAction SilentlyContinue

# Check SMB shares and their local backing paths
Get-SmbShare
net share

# Resolve original target path of a Windows .lnk shortcut (Recent folder forensics)
(New-Object -ComObject WScript.Shell).CreateShortcut("C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\<file>.lnk").TargetPath

# Inspect Alternate Data Streams (ADS) such as Zone.Identifier
Get-Item -Path "C:\Users\<user>\Downloads\*" -Stream * -ErrorAction SilentlyContinue

# Calculate file hash for VirusTotal / IOC lookup
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA256
```

## Registry Inspection & Persistence

```cmd
:: Query a specific Registry value (e.g., UAC status: 0x1 = enabled, 0x0 = disabled)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

:: Add or overwrite a REG_DWORD value (requires Administrator for HKLM)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f

:: Recursive search in Registry for keywords
reg query HKLM /f "password" /t REG_SZ /s
```

```powershell
# Common user/machine startup persistence keys
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# Check enabled/disabled startup items (Task Manager Startup tab backing key)
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
```

### Registry Data Types

| Type | Description |
| :--- | :--- |
| `REG_SZ` | Fixed-length single string |
| `REG_EXPAND_SZ` | String containing environment variables (e.g., `%SystemRoot%`) |
| `REG_MULTI_SZ` | Array of multiple strings |
| `REG_DWORD` | 32-bit integer (common for boolean flags `0x0`/`0x1`) |
| `REG_QWORD` | 64-bit integer |
| `REG_BINARY` | Raw binary data |

## Processes, Services & Scheduled Tasks

```powershell
# Running processes with full command line and parent PID
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Format-Table -AutoSize

# Running services with full executable path (use Format-List to avoid truncation)
Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" } | Select-Object Name, DisplayName, StartMode, PathName | Format-List

# Non-Microsoft / third-party running services
Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" -and $_.PathName -notlike "*\Windows\*" } | Select-Object Name, PathName | Format-List

# Scheduled tasks outside default Microsoft paths
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | Select-Object TaskName, TaskPath, State
```

```cmd
:: CMD service & task checks
sc qc <ServiceName>
tasklist /v /svc
schtasks /query /fo LIST /v
```

## PowerShell Security & Event Logs

```powershell
# Inspect Execution Policy across all scopes
Get-ExecutionPolicy -List

# Inspect command aliases (e.g., check what maps to ipconfig)
Get-Alias -Definition *ipconfig*

# Read persistent PowerShell command history (PSReadLine)
Get-Content (Get-PSReadLineOption).HistorySavePath

# Query recent Security Event Logs by Event ID (requires Administrator)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 20 | Format-Table TimeCreated, Id, Message -Wrap

# Query Sysmon process creation events (Event ID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 15 | Format-List TimeCreated, Message
```

### High-Value Windows Event IDs

| Event ID | Log Source | Meaning |
| :--- | :--- | :--- |
| `4624` / `4625` | Security | Successful / Failed account logon |
| `4648` | Security | Logon attempted using explicit credentials (`runas`) |
| `4688` | Security | New process created (audit command-line if enabled) |
| `4698` | Security | Scheduled task created |
| `4720` / `4726` | Security | Local user account created / deleted |
| `4731` / `4732` | Security | Security-enabled local group created / member added |
| `7045` | System | New Windows service installed |
| `1` / `3` / `11` | Sysmon | Process creation / Network connection / File creation |
| `4104` | PowerShell Operational | Script Block Logging (captures deobfuscated scripts) |

## Networking & Clipboard Utilities

```powershell
# Active TCP connections mapped to owning process name
Get-NetTCPConnection -State Listen,Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}} | Format-Table -AutoSize

# Download file via PowerShell
Invoke-WebRequest -Uri "http://<ip>:8000/file.exe" -OutFile "C:\Temp\file.exe"

# Pipe command output directly to clipboard (fast copy over RDP)
Get-Content flag.txt | Set-Clipboard
```

```cmd
:: CMD equivalents
netstat -ano
type flag.txt | clip
```
