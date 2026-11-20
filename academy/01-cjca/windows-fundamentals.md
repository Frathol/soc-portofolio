# Windows Fundamentals

**Source:** HTB Academy (CJCA Path)  
**Focus:** Windows internals, CLI administration, Registry, WMI, and local account management.

## Key Concepts to Remember

* **Non-standard root directories:** Default `C:\` only holds `PerfLogs`, `Program Files`, `Program Files (x86)`, `Users`, and `Windows` (plus hidden `ProgramData`, `$Recycle.Bin`, `Recovery`). Anything else warrants inspection.
* **Registry Hives:** `HKLM` = machine-wide config; `HKCU` = current user config (mapped from `NTUSER.DAT`).
* **Data Types:** `REG_DWORD` (32-bit integer/boolean flags like `EnableLUA`), `REG_SZ` (single string), `REG_EXPAND_SZ` (contains env vars), `REG_MULTI_SZ` (multiple strings).
* **SID Structure:** `S-1-5-21-<machine/domain-id>-<RID>`. RID `500` is always the built-in Administrator; local user/group accounts start at `1000+`.

## Commands Worth Keeping

```powershell
# Inspect non-standard/hidden directories in C:\
Get-ChildItem -Path C:\ -Force

# Check SMB shares and local paths
Get-SmbShare        # or CMD: net share

# Inspect UAC status via Registry (0x0 = disabled, 0x1 = enabled)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

# List running third-party services with full executable path (avoid table truncation)
Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" } | Select-Object Name, PathName | Format-List

# Query OS serial number via WMI/CIM (Win32_BIOS returns VM UUID on hypervisors)
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object SerialNumber

# Check local users/groups and SIDs
Get-LocalUser | Select-Object Name, SID
Get-LocalGroup | Select-Object Name, SID

# Check PowerShell Execution Policy across all scopes
Get-ExecutionPolicy -List

# Resolve original target path of a Windows .lnk shortcut
(New-Object -ComObject WScript.Shell).CreateShortcut("C:\path\to\file.lnk").TargetPath
```

## Blue Team / SOC Takeaways

* **Registry Persistence & Defense Evasion:** Watch `HKCU/HKLM\...\Run` and `StartupApproved` for disabled security tools (`T1562.001`), and `EnableLUA` tampering (`T1548.002`).
* **Forensic Artifacts:** `.lnk` files in `AppData\Roaming\Microsoft\Windows\Recent\` prove historical access to local folders or SMB shares even after a share is removed.
* **Account Auditing:** Track Security Event ID `4720` (user created) and `4731` (local security group created) when monitoring unauthorized privilege changes.
