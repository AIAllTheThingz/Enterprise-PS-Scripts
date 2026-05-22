# MSXML4 Enterprise Detection and Remediation

## Purpose

This solution is a Windows PowerShell 5.1 workflow for identifying Microsoft MSXML 4 exposure across Windows servers and, when explicitly approved, performing reversible remediation.

The design goal is enterprise safety:

- Audit-first by default
- No credentials written to disk
- No remediation unless `-Remediate` is explicitly enabled
- No changes during `-DryRun`, `-PreviewRemediation`, or `-ConnectivityOnly`
- Quarantine before removal from the active path
- Registry export before optional registry deletion
- Rollback metadata generated for every remediation run

The solution targets:

- Windows Server 2012
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

## Delivered Files

- [Invoke-MSXML4Remediation.ps1](</D:/PS Scripts/MSXML4_Remediation/Invoke-MSXML4Remediation.ps1>)
- [ReportingTools.psm1](</D:/PS Scripts/MSXML4_Remediation/ReportingTools.psm1>)
- [MSXML4Remediation.config.psd1](</D:/PS Scripts/MSXML4_Remediation/MSXML4Remediation.config.psd1>)
- [Servers.csv](</D:/PS Scripts/MSXML4_Remediation/Servers.csv>)

## MSXML 4 Vulnerability Overview

MSXML 4 is retired and no longer supported by Microsoft. Its presence can indicate:

- An installed legacy MSXML 4 component
- A left-behind `msxml4.dll`
- Uninstall remnants
- Registry remnants that show prior installation or incomplete cleanup

This solution treats both active DLL exposure and installation remnants as findings worth reporting. File-based detections are classified as confirmed exposure. Registry-only or uninstall-only findings are classified as exposure or remnant detections so they can be reviewed before cleanup.

## Operating Modes

### Audit Mode

Default mode. The script:

- Reads servers from CSV
- Prompts for credentials using `Get-Credential`
- Checks connectivity
- Collects OS information
- Searches registry locations
- Searches for `msxml4.dll`
- Optionally checks `Win32_Product` if enabled in config
- Exports reports only

No system changes are made.

### Dry Run Mode

Enabled with `-DryRun` or config `DryRun = $true`.

Dry run:

- Detects exposure
- Builds a remediation plan summary
- Produces reports
- Does not unregister DLLs
- Does not export or remove registry keys
- Does not move or quarantine files

### Preview Remediation Mode

Enabled with `-PreviewRemediation` or config `PreviewRemediation = $true`.

Preview mode:

- Performs detection
- Shows what would be remediated
- Produces remediation planning output in reports
- Makes no changes

### Connectivity Only Mode

Enabled with `-ConnectivityOnly`.

Connectivity mode:

- Validates reachability
- Tests WinRM when allowed
- Tests WMI/DCOM access
- Captures OS data when available
- Does not perform full detection or remediation

### Remediation Mode

Enabled with `-Remediate` or config `EnableRemediation = $true`.

Remediation mode:

- Requires explicit operator approval
- Prompts for confirmation unless `-Force` is used
- Unregisters `msxml4.dll` when configured
- Moves detected DLLs into quarantine
- Exports registry keys
- Optionally removes registry keys if configured
- Writes rollback metadata

This workflow is quarantine-first. The active DLL is removed from its original path by moving it into quarantine, but the quarantine copy is preserved for rollback.

## Detection Logic

The script checks:

- `HKLM:\Software\Microsoft\MSXML4`
- `HKLM:\Software\WOW6432Node\Microsoft\MSXML4`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- `msxml4.dll` in configured search paths or full fixed-drive scans
- Optional `Win32_Product` matches when explicitly enabled

By default, `Win32_Product` is disabled because it can trigger MSI self-repair.

## CSV Input Format

The server CSV must contain a `ServerName` header.

Example:

```csv
ServerName
SERVER01
SERVER02
server03.domain.local
```

## Configuration File

The configuration file is [MSXML4Remediation.config.psd1](</D:/PS Scripts/MSXML4_Remediation/MSXML4Remediation.config.psd1>).

Key settings include:

- `Domain`
- `Username`
- `ServerCsvPath`
- `OutputPath`
- `LogPath`
- `UseFqdn`
- `FqdnSuffix`
- `ReportFormats`
- `DryRun`
- `PreviewRemediation`
- `NoWinRM`
- `UseDcomWmi`
- `VerboseLogging`
- `TimeoutSeconds`
- `SkipFileSearch`
- `FullFileSearch`
- `IncludeHash`
- `UseWin32Product`
- `LocalDrives`
- `IncludeAllFixedDrives`
- `SearchPaths`
- `ExcludedDrives`
- `ExcludedPaths`
- `EnableRemediation`
- `QuarantinePath`
- `RemoveFiles`
- `UnregisterDll`
- `RemoveRegistryKeys`
- `CreateRestoreMetadata`
- `RequireConfirmation`

Relative paths in the PSD1 are resolved against the script directory.

## Credential Handling

The script prompts with `Get-Credential` if `-Credential` is not supplied. It prepopulates the username from:

1. `Domain` and `Username` in the PSD1
2. `Username` in the PSD1
3. The current `USERDOMAIN\USERNAME`

Passwords are never stored in:

- Script files
- Config files
- Logs
- Reports
- Metadata output

## Quarantine Structure

The default quarantine layout is:

```text
C:\MSXML4_Remediation_Quarantine\
    SERVER01\
        2026-05-22_213000\
            Files\
            Registry\
            Metadata.json
```

The quarantine folder contains:

- Quarantined DLLs
- Exported `.reg` backups
- Rollback metadata in JSON

## Rollback Process

Rollback is intentionally manual and reviewable.

For each remediated server:

1. Open `Metadata.json` in the server quarantine folder.
2. Review the original DLL path, quarantine path, exported registry files, remediation timestamp, and operator account.
3. Copy the quarantined DLL back to its original path if rollback is required.
4. Re-import exported registry files as needed.
5. Re-register the DLL only if the application owner approves it and the dependency is still required.

Typical rollback commands:

```powershell
Copy-Item -Path 'C:\MSXML4_Remediation_Quarantine\SERVER01\2026-05-22_213000\Files\C__Program Files_LegacyApp_msxml4.dll' -Destination 'C:\Program Files\LegacyApp\msxml4.dll' -Force
reg import 'C:\MSXML4_Remediation_Quarantine\SERVER01\2026-05-22_213000\Registry\HKLM_SOFTWARE_Microsoft_MSXML4.reg'
& 'C:\Windows\System32\regsvr32.exe' /s 'C:\Program Files\LegacyApp\msxml4.dll'
```

Rollback should be coordinated with the application owner because MSXML 4 is retired software and restoring it may reintroduce a security exposure.

## WinRM and No-WinRM Modes

### WinRM Mode

When WinRM is allowed, the script prefers PowerShell remoting for:

- Registry inspection
- File discovery
- Remediation actions
- Metadata generation

### No-WinRM Mode

Enable with `-NoWinRM`.

When `-NoWinRM` is used, the script avoids:

- `Invoke-Command`
- `Enter-PSSession`
- `New-PSSession`
- WSMan-backed CIM sessions

Instead it uses:

- `Get-WmiObject` over DCOM
- `Win32_Process.Create` over WMI/DCOM
- SMB admin shares for file search and quarantine
- Remote registry-compatible export and deletion logic

No-WinRM mode usually requires:

- WMI/DCOM access to the target
- SMB admin share access such as `C$`
- Firewall rules that allow RPC/DCOM and SMB
- An account with local administrator rights on the target

If file search over SMB is blocked, registry detections can still succeed and will be reported as such.

## Command-Line Switches

### Core Inputs

- `-ConfigPath`
- `-ServerCsvPath`
- `-OutputPath`
- `-Credential`
- `-ReportFormat`
- `-VerboseLogging`

### Scan and Validation

- `-DryRun`
- `-ConnectivityOnly`
- `-NoWinRM`
- `-UseDcomWmi`
- `-SkipFileSearch`
- `-FullFileSearch`
- `-IncludeHash`
- `-TimeoutSeconds`
- `-LocalDrives`
- `-IncludeAllFixedDrives`
- `-ExcludeDrives`
- `-ExcludePaths`

### Remediation

- `-PreviewRemediation`
- `-Remediate`
- `-QuarantinePath`
- `-RemoveRegistryKeys`
- `-UnregisterDll`
- `-Force`

## Example Usage

Audit only:

```powershell
.\Invoke-MSXML4Remediation.ps1
```

Audit only with explicit config:

```powershell
.\Invoke-MSXML4Remediation.ps1 -ConfigPath .\MSXML4Remediation.config.psd1
```

Connectivity validation only:

```powershell
.\Invoke-MSXML4Remediation.ps1 -ConnectivityOnly
```

Dry run with full file search:

```powershell
.\Invoke-MSXML4Remediation.ps1 -DryRun -FullFileSearch -IncludeAllFixedDrives
```

No-WinRM audit:

```powershell
.\Invoke-MSXML4Remediation.ps1 -NoWinRM -UseDcomWmi
```

Preview remediation:

```powershell
.\Invoke-MSXML4Remediation.ps1 -PreviewRemediation
```

Approved remediation:

```powershell
.\Invoke-MSXML4Remediation.ps1 -Remediate
```

Approved remediation without confirmation prompt:

```powershell
.\Invoke-MSXML4Remediation.ps1 -Remediate -Force
```

## Reporting

The reporting module exports:

- CSV
- JSON
- TXT
- HTML

Generated report sets include:

- Full inventory report
- Vulnerable servers report
- Remediation actions report
- Remediation failures report
- Not detected report
- Failed servers report
- Dry-run report
- Executive summary report

Report records include:

- Server name and FQDN
- OS caption, version, and build
- Connectivity and scan status
- Detection status and vulnerability classification
- Remediation status and action taken
- Product and version data
- Registry path
- DLL path, drive, version, modified date, size, and hash
- Quarantine and rollback metadata paths
- Detection method
- Collection mode
- Scanned drives, excluded drives, and excluded paths
- Failure reason
- Notes

## Code Signing

This solution is compatible with Authenticode signing.

Sign these files after review and before broad deployment:

- [Invoke-MSXML4Remediation.ps1](</D:/PS Scripts/MSXML4_Remediation/Invoke-MSXML4Remediation.ps1>)
- [ReportingTools.psm1](</D:/PS Scripts/MSXML4_Remediation/ReportingTools.psm1>)

Certificate requirements:

- EKU must include `Code Signing`
- The private key should remain only on the admin or signing workstation

Example signing commands:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\Invoke-MSXML4Remediation.ps1 -Certificate $cert -TimestampServer 'http://timestamp.digicert.com'
Set-AuthenticodeSignature -FilePath .\ReportingTools.psm1 -Certificate $cert -TimestampServer 'http://timestamp.digicert.com'
```

Validate signatures:

```powershell
Get-AuthenticodeSignature .\Invoke-MSXML4Remediation.ps1
Get-AuthenticodeSignature .\ReportingTools.psm1
```

Execution policy examples:

```powershell
Set-ExecutionPolicy AllSigned
Set-ExecutionPolicy RemoteSigned
```

Code signing does not enable WinRM. WinRM must still be configured separately if you want remoting mode.

WinRM validation examples:

```powershell
Test-WSMan SERVER01
Invoke-Command -ComputerName SERVER01 -ScriptBlock { hostname }
```

## Troubleshooting

Unknown publisher:

- Import the code-signing certificate chain into the trusted publisher and trusted root stores as required.

Untrusted root CA:

- Ensure the issuing CA chain is trusted on the execution host.

Expired certificate:

- Re-sign the files with a valid code-signing certificate.

Missing timestamp:

- Re-sign with a timestamp server so the signature remains valid after certificate expiration.

Modified script after signing:

- Re-sign after any content change. Authenticode signatures are invalidated by file modification.

Execution policy blocking the script:

- Confirm the host execution policy with `Get-ExecutionPolicy -List`.

WinRM not working:

- Validate WSMan with `Test-WSMan`.
- Confirm listener, firewall, and trusted host settings if applicable.
- Remember that a valid signature does not configure or enable WinRM.

No-WinRM file search failures:

- Confirm RPC/DCOM access.
- Confirm WMI namespace access.
- Confirm SMB admin shares such as `C$`.
- Confirm the supplied account has local admin rights.

`Win32_Product` is slow or causes MSI repair:

- Leave `UseWin32Product = $false` unless you have a strong reason to enable it.

Registry export or delete failed:

- Confirm the target account has permission to the affected registry paths.
- Review the log file in the configured log folder.
- Review the failed server and remediation failure reports.

## Server 2012 Compatibility Notes

The solution is written for Windows PowerShell 5.1 and avoids:

- PowerShell 7 requirements
- Paid third-party modules
- WSMan-only CIM session requirements in No-WinRM mode
- Runtime self-modifying code

The reporting module and main script are plain-text PowerShell files suitable for source control, code review, and enterprise signing workflows.