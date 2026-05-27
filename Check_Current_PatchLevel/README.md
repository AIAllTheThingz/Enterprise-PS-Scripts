# Server Update Audit

# Test connectivity to csv server list

.\Get-ServerUpdateAudit.ps1 -ConfigPath ".\ServerUpdateAudit.config.psd1" -ServerCsvPath ".\ServerList.csv" -NoWinRM -DryRun

# Run actual Audit

.\Get-ServerUpdateAudit.ps1 -ConfigPath ".\ServerUpdateAudit.config.psd1" -ServerCsvPath ".\ServerList.csv" -NoWinRM

## Purpose

This solution audits Windows servers for their installed updates and exports
modular reports through a reusable reporting framework.

It was built for enterprise operations where support staff need both:

- trustworthy data collection logic
- reusable report generation that can be dropped into future scripts

## Deliverables

- `Get-ServerUpdateAudit.ps1`
- `ReportingTools.psm1`
- `ServerUpdateAudit.config.psd1`
- `ServerList.csv`
- `README.md`

## Requirements

- Windows PowerShell 5.1
- Administrative or delegated rights to query remote server update data
- Network connectivity to the target servers
- WinRM enabled for full remote PowerShell and Windows Update history coverage
- WMI/CIM access for OS information and compatibility fallback collection

## Supported Operating Systems

The script is designed to support and identify:

- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

Reported OS details include:

- OS Caption
- OS Version
- Build Number
- UBR
- Detected server release

## What the Solution Collects

The audit collects update information by category:

- Cumulative Updates
- Security Updates
- .NET Updates
- Microsoft Defender Security Intelligence updates
- General Windows Updates
- Hotfix / KB Updates
- Servicing Stack Updates
- Other or Unknown updates when metadata is incomplete

It also records:

- Server name
- Resolved FQDN
- Online status
- Query status
- Last successful query time
- KB number
- Update title
- Installed date
- Installed by
- Source method
- Notes and partial failure details

By default, the sample configuration is set to report matching updates from the
previous 6 months. Set `HistoryMonthsBack = 0` to return only the latest update
per category instead.

## Files and Roles

### `Get-ServerUpdateAudit.ps1`

Main orchestration script.

Responsibilities:

- load configuration
- prompt for credentials
- parse the server CSV
- validate connectivity
- query OS and update information
- classify updates
- pass structured objects into the reporting module

### `ReportingTools.psm1`

Reusable reporting module.

Functions exported:

- `Export-ReportCsv`
- `Export-ReportJson`
- `Export-ReportTxt`
- `Export-ReportHtml`
- `Export-ReportBundle`

This module:

- does not prompt for credentials
- does not query servers
- does not contain environment-specific audit logic

## Configuration

All configurable settings are stored in `ServerUpdateAudit.config.psd1`.

Example structure:

```powershell
@{
    Domain = "DOMAIN"
    Username = "username"

    ServerCsvPath = "D:\PS Scripts\Check_Current_PatchLevel\ServerList.csv"
    OutputPath = "D:\PS Scripts\Check_Current_PatchLevel\Reports"

    UseFqdn = $true
    FqdnSuffix = "domain.local"

    Reports = @{
        Csv  = $true
        Json = $true
        Txt  = $true
        Html = $true
    }

    Logging = @{
        Enabled = $true
        LogPath = "D:\PS Scripts\Check_Current_PatchLevel\Logs"
    }

    Query = @{
        IncludeHotFix = $true
        IncludeWindowsUpdateHistory = $true
        IncludeDefenderUpdates = $true
        IncludeDotNetUpdates = $true
        IncludeSecurityUpdates = $true
        IncludeCumulativeUpdates = $true
        IncludeGeneralWindowsUpdates = $true
        IncludeServicingStackUpdates = $true
        IncludeSecurityIntelligenceUpdatesInReports = $false
        IncludeSecurityUpdatesInReports = $false
        HistoryMonthsBack = 6
        CategoryFilters = @()
        ExclusionList = @()
    }

    Connection = @{
        TimeoutSeconds = 30
        TestConnectionFirst = $true
        DryRunEnabled = $false
        UseWinRM = $true
    }
}
```

## Credential Handling

The script prompts for credentials with `Get-Credential` unless `-Credential`
is supplied.

The default username is prepopulated as:

```text
DOMAIN\Username
```

Passwords are never stored in:

- config files
- logs
- reports
- source code

## Server CSV Format

The input CSV must contain:

```csv
ServerName
SERVER01
SERVER02
server03.domain.local
```

Behavior:

- blank rows are ignored
- duplicate servers are removed
- exclusion list entries from config are skipped
- if `UseFqdn` is enabled and a name does not contain a domain suffix, the configured `FqdnSuffix` is appended automatically

## WinRM and Remote Access Requirements

Best results require:

- WinRM enabled and reachable
- PowerShell remoting allowed for the supplied credential
- WMI/CIM accessible from the system running the audit

The script handles partial access gracefully:

- if WinRM is unavailable, update history and Defender collection may fail
- if CIM/WMI is unavailable, OS information may fail
- if one source fails, the script preserves the error in notes and continues where possible
- if `-NoWinRM` is used, WinRM-dependent collectors are skipped intentionally

## Command-Line Parameters

### `-ConfigPath`

Required.

Path to the PSD1 configuration file.

### `-ServerCsvPath`

Optional.

Overrides `ServerCsvPath` from config.

### `-OutputPath`

Optional.

Overrides `OutputPath` from config.

### `-Credential`

Optional.

Supplies a credential object instead of prompting.

### `-ReportFormat`

Optional.

Overrides the report formats enabled in config.

Supported values:

- `Csv`
- `Json`
- `Txt`
- `Html`

### `-VerboseLogging`

Optional.

Writes additional troubleshooting information to the console and log file.

### `-DryRun`

Optional.

Runs connectivity validation only. No update history is queried.

### `-ConnectivityOnly`

Optional.

Alias-style operational mode for connectivity validation only.

### `-NoWinRM`

Optional.

Disables WinRM and PowerShell remoting usage.

When used:

- WinRM and PowerShell remoting checks are marked as skipped in dry-run mode
- Windows Update history collection is skipped
- Defender collection is skipped
- registry-based remoting fallback collection is skipped
- UBR collection is skipped
- CIM/WMI-based OS and hotfix paths remain available

### `-MonthsBack`

Optional.

Overrides the historical lookback window.

Examples:

- `0` = latest update per category only
- `6` = all matching updates installed within the last 6 months

## Command Examples

### Standard audit run

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1"
```

### Audit run with report format override

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -ReportFormat Csv,Html
```

### Audit run with verbose troubleshooting output

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -VerboseLogging
```

### Audit run with alternate server CSV and output path

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -ServerCsvPath "D:\PS Scripts\Check_Current_PatchLevel\ServerList.csv" `
  -OutputPath "D:\PS Scripts\Check_Current_PatchLevel\Reports"
```

### Audit run with pre-supplied credentials

```powershell
$cred = Get-Credential

.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -Credential $cred
```

### Dry-run connectivity validation

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -DryRun
```

### Connectivity-only validation with HTML output

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -ConnectivityOnly `
  -ReportFormat Html
```

### Audit run without WinRM

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -NoWinRM
```

### Audit run for the previous 6 months

```powershell
.\Get-ServerUpdateAudit.ps1 `
  -ConfigPath ".\ServerUpdateAudit.config.psd1" `
  -MonthsBack 6
```

## Dry-Run Behavior

Dry-run mode validates:

- DNS resolution
- hostname/FQDN resolution
- ICMP reachability where allowed
- WinRM availability
- PowerShell remoting access
- WMI/CIM access
- credential authentication success where the platform allows it to be tested

Dry-run mode does not:

- query installed update history
- change remote systems
- install software
- modify configuration

If `-NoWinRM` is used during dry-run mode:

- WinRM status is reported as skipped
- PowerShell remoting status is reported as skipped
- CIM/WMI validation is still attempted

## Update Query Sources

The main script uses multiple sources to improve resilience:

1. `Get-HotFix`
2. Windows Update history through `Microsoft.Update.Session`
3. `Get-MpComputerStatus` for Defender
4. registry-based fallback signals through PowerShell remoting
5. `Win32_ReliabilityRecords` for broader historical update visibility

When `-NoWinRM` is used, only the non-WinRM-compatible sources are used.

When `HistoryMonthsBack` or `-MonthsBack` is greater than 0, the report returns
all matching updates with an install date inside that window instead of only the
latest update per category.

This matters because `Get-HotFix` and QFE data only show what is currently
installed. For broader historical reporting, the script now also uses
`Win32_ReliabilityRecords` to surface older update activity when available.

## Update Classification

Updates are normalized into these report categories:

- `Cumulative Update`
- `Security Update`
- `.NET Update`
- `Security Intelligence Update`
- `Servicing Stack Update`
- `General Windows Update`
- `Hotfix / KB Update`
- `Other Update`
- `Unknown`

`Security Intelligence Update`, including Microsoft Defender Antivirus security intelligence titles, is omitted from reports unless `Query.IncludeSecurityIntelligenceUpdatesInReports = $true`.

`Security Update` is omitted from reports unless `Query.IncludeSecurityUpdatesInReports = $true`.

The source collection settings, such as `IncludeDefenderUpdates` and `IncludeSecurityUpdates`, still control whether those sources are queried. The report-specific settings above control whether the matching categories are emitted to CSV, JSON, TXT, and HTML outputs.

## Report Output

Output files are timestamped. Examples:

- `ServerUpdateAudit_2026-05-18_213000.csv`
- `ServerUpdateAudit_2026-05-18_213000.json`
- `ServerUpdateAudit_2026-05-18_213000.html`
- `ServerUpdateAudit_2026-05-18_213000.txt`
- `ServerUpdateAudit_FailedServers_2026-05-18_213000.csv`
- `ServerUpdateAudit_Summary_2026-05-18_213000.csv`
- `ServerUpdateAudit_DryRun_2026-05-18_213000.html`

### HTML Reports

HTML output includes:

- report title
- run date/time
- username used
- grouped tables
- metadata
- summary information
- failed item details
- color-coded status values

Color standards:

- green = success
- yellow = warning
- red = failed

## Logging

When logging is enabled, the script creates timestamped log files and records:

- startup details
- config path
- CSV path
- output path
- module import actions
- server processing progress
- warnings
- errors
- report generation
- completion timing

Passwords are never logged.

## Required Permissions

Recommended privileges:

- rights to access the server CSV and report paths
- rights to connect to remote systems with WinRM
- rights to query WMI/CIM remotely
- rights to query installed update information
- rights to run `Get-MpComputerStatus` remotely when Defender is present

## Troubleshooting

### WinRM unavailable

- verify WinRM is enabled on the target server
- confirm firewall rules allow WinRM traffic
- run the script with `-DryRun` first to confirm the failure point
- if WinRM cannot be used in your environment, run with `-NoWinRM`

### PowerShell remoting failed

- verify the credential is valid
- confirm the account is allowed to use remoting
- verify the server allows remote session creation

### CIM or WMI failed

- verify RPC and WMI access
- confirm firewall rules allow remote management
- try dry-run mode to isolate whether the failure is DNS, WinRM, or CIM/WMI

### No update history returned

- Windows Update history via COM requires remoting
- some servers may only expose hotfix data
- registry fallback data may be less descriptive than full update history

### Defender data missing

- not every server has Defender enabled
- some roles or hardened builds may not include `Get-MpComputerStatus`
- the script treats this as a compatibility condition, not always a hard failure

### Access denied

- verify the supplied credential has remote query permissions
- confirm the account can use both WinRM and WMI/CIM where required

## Reuse Guidance for `ReportingTools.psm1`

The reporting module can be reused from other scripts like this:

```powershell
Import-Module ".\ReportingTools.psm1"

Export-ReportBundle `
    -Data $Results `
    -Title "Server Update Audit Report" `
    -OutputPath "C:\Reports" `
    -BaseFileName "ServerUpdateAudit" `
    -Formats @("Csv","Json","Html","Txt") `
    -GroupBy "ServerName" `
    -Summary $Summary `
    -FailedItems $FailedServers `
    -Metadata @{
        RunDate = Get-Date
        ScriptName = "Example.ps1"
        User = $env:USERNAME
    }
```
