# FileSharePermissionsAudit

## Overview

FileSharePermissionsAudit is a read-only Windows PowerShell 5.0 compatible solution for auditing SMB share permissions and NTFS folder permissions across one or more Windows servers. It reports SMB permissions, NTFS ACL entries, inheritance, ownership, inaccessible folders, errors, and the folder hierarchy beneath each share.

The solution never enumerates files, never collects file-level ACLs, and never modifies shares, folders, or permissions.

## Files Included

- `Get-FileSharePermissionsAudit.ps1` - Main audit script.
- `FileSharePermissionsAudit.Config.psd1` - External configuration file.
- `FileSharePermissionsAudit.Servers.csv` - Example server input file.
- `ReportingTools.psm1` - Reusable CSV, JSON, and HTML reporting module.
- `README.md` - This documentation.

## Localhost Support

The script automatically detects local targets and uses optimized local filesystem and SMB enumeration where possible. These values are treated as the local computer:

- `localhost`
- `.`
- `127.0.0.1`
- `::1`
- `$env:COMPUTERNAME`
- The fully qualified local hostname

When a target is local, the script avoids unnecessary WinRM calls and uses direct local paths for `Get-Acl`.

## Targeting Specific Shares

By default, the script scans all eligible non-administrative shares on each target server. You can narrow the scope in two ways:

- Use `-ShareName` to scan one or more named shares on the selected server or CSV targets.
- Use `-SharePath` to scan one or more direct UNC share roots such as `\\server\share`.

`-SharePath` must point to the share root, not a subfolder. For example, `\\FILESERVER01\Finance` is valid, but `\\FILESERVER01\Finance\Payroll` is intentionally rejected so folder depth and share-root reporting remain accurate.

When `-SharePath` is used, the script groups paths by server and scans those share roots directly. WinRM precheck is skipped for direct share path targets because UNC access can be valid even when WinRM is unavailable. Ping precheck still runs unless `-SkipPreCheck` is supplied.

Do not combine `-SharePath` with `-ServerName`, `-ServerCsvPath`, or `-ShareName`; the UNC path already contains the server and share name.

## Configuration

All environment settings are externalized in `FileSharePermissionsAudit.Config.psd1`.

```powershell
@{
    ServerCsvPath = "C:\Scripts\FileSharePermissionsAudit\FileSharePermissionsAudit.Servers.csv"

    Output = @{
        ReportPath = "C:\Reports\FileSharePermissionsAudit"
        LogPath = "C:\Logs\FileSharePermissionsAudit"
        ReportPrefix = "FileSharePermissionsAudit"
    }

    Enumeration = @{
        EnumerateSubFolders = $true
        FolderOnlyEnumeration = $true
        SkipFiles = $true
        IncludeInheritedPermissions = $true
        IncludeAdminShares = $false
        ExcludeReparsePoints = $true
        MaxDepth = 0
    }

    ShareExclusions = @{
        Shares = @(
            'ADMIN$',
            'C$',
            'D$',
            'IPC$',
            'PRINT$'
        )
    }

    HealthChecks = @{
        Ping = $true
        WinRM = $true
    }

    Reporting = @{
        GenerateCSV = $true
        GenerateJSON = $true
        GenerateHTML = $true
        IncludeFolderTree = $true
    }

    Execution = @{
        RetryIntervalSeconds = 15
        FolderEnumerationThrottleLimit = 5
        ContinueOnServerFailure = $true
    }

    Remote = @{
        UseCimSessions = $true
        UseUNCFallback = $true
    }

    UseCredential = $false
}
```

`MaxDepth = 0` means unlimited folder recursion. Any value greater than zero limits traversal to that depth below the share root.

## Server CSV

The server CSV must contain these columns:

```csv
ServerName,Enabled,Notes
FILESERVER01.domain.com,true,Primary file server
FILESERVER02.domain.com,true,Department share server
localhost,true,Local machine example
.,true,Alternate localhost example
127.0.0.1,true,Loopback example
FILESERVER03.domain.com,false,Disabled example
```

Disabled servers are ignored. Blank rows are ignored. Server names are trimmed and de-duplicated. Duplicate localhost-equivalent entries are normalized internally so the local machine is scanned once.

## Folder Enumeration

The script enumerates folders only. It uses directory-only traversal equivalent to `Get-ChildItem -Directory`, not unrestricted recursive file enumeration.

The share root and each subfolder are reported with:

- `FolderDepth`
- `FolderTree`
- `ParentFolder`
- `FolderName`
- `IsShareRoot`

Example folder tree output:

```text
main
    sub folder 1
        sub folder 2
            sub folder 3
```

Reparse points and junctions are skipped by default to prevent loops.

## Share And NTFS Permissions

The script collects:

- SMB share permissions with `Get-SmbShareAccess` when available.
- SMB share permission fallback data from `Win32_LogicalShareSecuritySetting`.
- NTFS folder ACLs with `Get-Acl`.
- Folder ownership.
- Inheritance flags and propagation flags.
- Access control type and rights.

Administrative shares are excluded by default, including `ADMIN$`, drive-letter admin shares such as `C$`, `IPC$`, and `PRINT$`. Use `-IncludeAdminShares` to include them.

## Remote Collection

The script prefers:

- `Get-SmbShare`
- `Get-SmbShareAccess`
- WinRM remote command execution when needed

Fallbacks include:

- `Win32_Share`
- `Win32_LogicalShareSecuritySetting`
- UNC path access for remote NTFS ACL reads when configured

Remote scans require appropriate network access, administrative share access or share path access, and permissions to read ACLs.

## Logging

The script creates timestamped logs and transcript logs. Logging includes configuration loading, parameter handling, localhost detection, server processing, share processing, folder traversal, ACL enumeration, warnings, errors, report paths, and completion status.

## Reports

Reports are generated in the configured report directory:

- CSV - Flattened rows for Excel, filtering, and ticket attachments.
- JSON - Structured server, share, folder, and permission objects.
- HTML - Self-contained report with embedded CSS and embedded JavaScript for collapsible folder tree sections.

Report fields include:

- `ServerName`
- `ShareName`
- `SharePath`
- `FolderPath`
- `FolderName`
- `ParentFolder`
- `FolderDepth`
- `FolderTree`
- `IsShareRoot`
- `Owner`
- `ShareDescription`
- `SharePermissionIdentity`
- `SharePermissionAccessControlType`
- `SharePermissionRight`
- `NTFSIdentity`
- `NTFSAccessControlType`
- `NTFSRights`
- `NTFSIsInherited`
- `NTFSInheritanceFlags`
- `NTFSPropagationFlags`
- `EnumerationStatus`
- `ErrorMessage`
- `ScanDurationSeconds`

## Command-Line Switches

| Switch | Required | Description |
|---|---:|---|
| `-ConfigPath` | Yes | Path to `FileSharePermissionsAudit.Config.psd1`. |
| `-ServerName` | No | Scans one server. Supports localhost aliases. |
| `-ServerCsvPath` | No | Scans servers listed in a CSV with `ServerName`, `Enabled`, and `Notes`. |
| `-ShareName` | No | Scans one or more specific SMB share names on the selected target servers. |
| `-SharePath` | No | Scans one or more direct UNC share roots such as `\\server\share`. |
| `-Credential` | No | Optional credential for remote operations. Passwords are never stored. |
| `-OutputDirectory` | No | Overrides both report and log paths for the current run. |
| `-ReportPath` | No | Overrides only the report path for the current run. |
| `-Verbose` | No | Enables PowerShell verbose output. |
| `-WhatIf` | No | Accepted through `SupportsShouldProcess`; target systems are read-only and are never modified. Local report and log files may still be created. |
| `-IncludeAdminShares` | No | Includes administrative shares that are excluded by default. |
| `-MaxDepth` | No | Overrides recursion depth. `0` means unlimited. |
| `-ContinueOnFailure` | No | Continues processing remaining servers after nonfatal server failures. |
| `-SkipPreCheck` | No | Skips ping and WinRM prechecks before enumeration. |
| `-NonInteractive` | No | Prevents prompts. Fails if `UseCredential = $true` and no `-Credential` is supplied. |

## Examples

Run locally using the configured defaults:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1
```

Run an explicit localhost scan:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName localhost
```

Run using the dot localhost alias:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName .
```

Run using the loopback address:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName 127.0.0.1
```

Run one remote server:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName FILESERVER01
```

Scan one specific share name on a server:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName FILESERVER01 -ShareName Finance
```

Scan multiple specific share names on a server:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName FILESERVER01 -ShareName Finance,HR,Projects
```

Scan a direct UNC share root:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -SharePath "\\FILESERVER01\Finance"
```

Scan a direct UNC share root by IP address:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -SharePath "\\192.168.1.25\ShareName"
```

Scan multiple direct UNC share roots:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -SharePath "\\FILESERVER01\Finance","\\FILESERVER02\Projects"
```

Run all enabled servers from CSV:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerCsvPath .\FileSharePermissionsAudit.Servers.csv
```

Scan one share name across all enabled CSV targets:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerCsvPath .\FileSharePermissionsAudit.Servers.csv -ShareName Finance
```

Use the CSV path from the PSD1:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1
```

Include administrative shares:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -IncludeAdminShares
```

Limit recursion depth:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -MaxDepth 3
```

Use alternate credentials:

```powershell
$cred = Get-Credential
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName FILESERVER01 -Credential $cred
```

Override both report and log output directories:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -OutputDirectory C:\AuditOutput\FileSharePermissions
```

Override only the report path:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ReportPath C:\Reports\FileSharePermissions
```

Enable verbose output:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName FILESERVER01 -Verbose
```

Run with `WhatIf`:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName FILESERVER01 -WhatIf
```

Continue after server failures:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerCsvPath .\FileSharePermissionsAudit.Servers.csv -ContinueOnFailure
```

Skip ping and WinRM prechecks:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerName FILESERVER01 -SkipPreCheck
```

Run unattended:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerCsvPath .\FileSharePermissionsAudit.Servers.csv -NonInteractive
```

Combine common operational switches:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -ServerCsvPath .\FileSharePermissionsAudit.Servers.csv -IncludeAdminShares -MaxDepth 2 -ContinueOnFailure -NonInteractive
```

Scan a UNC share path unattended with limited recursion:

```powershell
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1 -SharePath "\\FILESERVER01\Finance" -MaxDepth 2 -NonInteractive
```

## Scheduled Task Example

```powershell
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy RemoteSigned -File "C:\Scripts\FileSharePermissionsAudit\Get-FileSharePermissionsAudit.ps1" -ConfigPath "C:\Scripts\FileSharePermissionsAudit\FileSharePermissionsAudit.Config.psd1" -NonInteractive'
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00am
$Principal = New-ScheduledTaskPrincipal -UserId 'DOMAIN\FileAuditService' -LogonType Password -RunLevel Highest
Register-ScheduledTask -TaskName 'FileSharePermissionsAudit' -Action $Action -Trigger $Trigger -Principal $Principal
```

Do not store passwords in the PSD1, CSV, script, or README examples. Use the Scheduled Task credential store or an approved enterprise credential mechanism.

## Required Permissions

The executing user or service account needs:

- Permission to enumerate SMB shares.
- Permission to read share security descriptors.
- Permission to read folder ACLs and ownership.
- Access to administrative shares or configured UNC paths when remote ACL reads are required.
- WinRM rights when WinRM collection is used.
- Write access to configured report and log directories.

## WinRM Validation

```powershell
Test-WSMan -ComputerName FILESERVER01
Invoke-Command -ComputerName FILESERVER01 -ScriptBlock { hostname }
```

Code signing does not configure WinRM, firewall rules, SMB administrative shares, RPC, DCOM, or remote permissions.

## Performance Considerations

Recursive folder ACL scans can take a long time on large file servers. Start with a limited depth, test on a representative share, and schedule full scans during approved maintenance or low-usage windows. `MaxDepth = 0` is unlimited and can produce very large CSV, JSON, and HTML reports.

## Exit Codes

- `0` - Completed successfully.
- `1` - Completed with warnings or nonfatal errors.
- `2` - Fatal script error.

## Code Signing

The script and module are compatible with Authenticode signing and do not modify themselves at runtime.

The signing certificate must include the Code Signing enhanced key usage.

```powershell
$CodeSigningCert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

Set-AuthenticodeSignature -FilePath ".\Get-FileSharePermissionsAudit.ps1" -Certificate $CodeSigningCert -TimestampServer "<approved timestamp service URL>"
Set-AuthenticodeSignature -FilePath ".\ReportingTools.psm1" -Certificate $CodeSigningCert -TimestampServer "<approved timestamp service URL>"

Get-AuthenticodeSignature -FilePath ".\Get-FileSharePermissionsAudit.ps1"
Get-AuthenticodeSignature -FilePath ".\ReportingTools.psm1"
```

Use the organization-approved timestamp service. Do not hardcode public timestamp services unless your security policy approves them.

Execution policy options:

```powershell
Set-ExecutionPolicy AllSigned -Scope LocalMachine
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
```

## Troubleshooting

Configuration validation failure: Verify the PSD1 path and required sections: `Output`, `Enumeration`, `ShareExclusions`, `HealthChecks`, `Reporting`, `Execution`, and `Remote`.

Server CSV invalid: Confirm the CSV exists and contains `ServerName`, `Enabled`, and `Notes`.

Share path rejected: Confirm `-SharePath` uses the UNC share-root form `\\server\share` and does not include a subfolder.

Server unreachable: Validate DNS, firewall access, routing, and the target server state.

WinRM failure: Run `Test-WSMan` and confirm the service account is allowed to connect.

Access denied: Confirm the account can enumerate shares and read folder ACLs.

Admin shares unavailable: Use explicit share paths or enable the administrative shares according to organizational policy.

ACL read failure: The folder may be inaccessible, removed during scan, blocked by permissions, or protected by a reparse point.

Large scan duration: Use `-MaxDepth` or reduce target scope.

Report generation failure: Confirm report and log directories exist or can be created by the executing account.

Execution policy errors: Validate Authenticode signatures and use `AllSigned` or `RemoteSigned` according to policy.
