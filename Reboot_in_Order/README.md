# Reboot_In_Order

## Overview

`Reboot_In_Order` is a Windows PowerShell 5.0 solution for orchestrating controlled reboots of multiple enterprise application stacks. It reads stack definitions from `Reboot-InOrder.Stacks.csv`, groups servers by `StackName`, reboots servers in `RebootOrder`, waits for recovery, validates health checks, optionally validates services listed directly on each CSV row, and generates CSV, JSON, and HTML reports.

The solution is designed for Windows Server, domain-joined environments, enterprise code signing, and unattended Scheduled Task execution.

The script does not hardcode server names, service names, credentials, or output paths. It does not store passwords in files and does not modify scripts dynamically at runtime.

## Files Included

- `Reboot-InOrder.ps1`
- `Reboot-InOrder.Config.psd1`
- `Reboot-InOrder.Stacks.csv`
- `ReportingTools.psm1`
- `README.md`

There is no separate services CSV. Service monitoring is defined directly in `Service1`, `Service2`, and `Service3` columns in `Reboot-InOrder.Stacks.csv`.

## Multi-Stack Orchestration

The script imports the stack CSV and processes each `StackName` independently. Within each stack, servers are sorted by `RebootOrder` and processed one at a time. The next server in the same stack is not rebooted until the current server has completed health validation or failure handling has been applied.

Parallel stack switches and settings are present for operational intent:

- `AllowParallelStacks`
- `MaxParallelStacks`
- `-AllowParallelStacks`
- `-MaxParallelStacks`

This PowerShell 5.0 implementation processes stacks sequentially to preserve signed-script safety and ordered reporting. If parallel execution is requested, the script warns and continues sequentially.

## Stack CSV Configuration

`Reboot-InOrder.Stacks.csv` defines stacks, servers, schedule, maintenance windows, enablement, notes, and up to three services per server.

Required format:

```csv
StackName,ServerName,RebootOrder,ScheduledStartTime,Enabled,MaintenanceWindowStart,MaintenanceWindowEnd,Service1,Service2,Service3,Notes
AppStackA,Server3.domain.com,1,23:00,true,22:00,04:00,AppService1,W3SVC,,Reboot first
AppStackA,Server1.domain.com,2,23:00,true,22:00,04:00,W3SVC,,,
AppStackA,Server4.domain.com,3,23:00,true,22:00,04:00,MSSQLSERVER,SQLSERVERAGENT,,Database server
AppStackA,Server2.domain.com,4,23:00,true,22:00,04:00,,,,
AppStackB,Server7.domain.com,1,01:00,true,00:00,05:00,AppService2,WAS,W3SVC,Web tier
AppStackB,Server5.domain.com,2,01:00,true,00:00,05:00,,,,
AppStackB,Server6.domain.com,3,01:00,true,00:00,05:00,Spooler,,,Example service check
```

### CSV Columns

| Column | Description |
|---|---|
| `StackName` | Application stack name. |
| `ServerName` | FQDN or hostname to reboot. |
| `RebootOrder` | Numeric order within the stack. |
| `ScheduledStartTime` | Stack start time in `HH:mm`. |
| `Enabled` | `true` or `false`; disabled rows are skipped. |
| `MaintenanceWindowStart` | Maintenance window start in `HH:mm`. |
| `MaintenanceWindowEnd` | Maintenance window end in `HH:mm`; overnight windows are supported. |
| `Service1` | Optional service name to validate after reboot. |
| `Service2` | Optional second service name. |
| `Service3` | Optional third service name. |
| `Notes` | Optional operational notes. |

## Service Monitoring

Service monitoring is optional and comes directly from `Service1`, `Service2`, and `Service3`.

Behavior:

- Blank service columns are skipped.
- Whitespace is trimmed.
- Empty service fields are ignored.
- If one or more service columns contain values, only those services are checked.
- If all service columns are blank for a server, service validation is skipped and normal health checks still run.
- Each listed service must exist and reach `Running`.
- Service checks retry until `MaxServiceWaitMinutes` is reached.
- Each service check attempt is written to CSV, JSON, HTML, and transcript logs.

Examples:

One service:

```csv
AppStackA,Server1.domain.com,2,23:00,true,22:00,04:00,W3SVC,,,
```

Two services:

```csv
AppStackA,Server4.domain.com,3,23:00,true,22:00,04:00,MSSQLSERVER,SQLSERVERAGENT,,Database server
```

Three services:

```csv
AppStackB,Server7.domain.com,1,01:00,true,00:00,05:00,AppService2,WAS,W3SVC,Web tier
```

Blank service columns:

```csv
AppStackB,Server5.domain.com,2,01:00,true,00:00,05:00,,,,
```

## PSD1 Configuration

Configuration lives in `Reboot-InOrder.Config.psd1`.

```powershell
@{
    StackCsvPath = "C:\Scripts\Reboot_In_Order\Reboot-InOrder.Stacks.csv"

    AllowParallelStacks = $false
    MaxParallelStacks   = 1

    WaitTimeoutMinutes    = 30
    MaxServiceWaitMinutes = 20
    RetryIntervalSeconds  = 30

    EnforceMaintenanceWindow           = $true
    SkipStacksOutsideMaintenanceWindow = $true

    HealthChecks = @{
        Ping          = $true
        WinRM         = $true
        RemoteCommand = $false
        Services      = $true
    }

    RemoteCommandScriptBlock = "hostname"

    ReportPath = "C:\Reports\Reboot_In_Order"
    LogPath    = "C:\Logs\Reboot_In_Order"

    IncludeTranscript = $true
    ReportFormats     = @("CSV", "JSON", "HTML")

    UseCredential      = $false
    CredentialUserName = "DOMAIN\service.account"

    OfflineDetectionGraceSeconds = 15
    RequiredOfflineObservations  = 2
    RequiredOnlineObservations   = 2
}
```

## Scheduled Processing And Maintenance Windows

Each stack uses the first enabled row, sorted by `RebootOrder`, as the schedule reference.

- `ScheduledStartTime` controls when a stack is eligible.
- `MaintenanceWindowStart` and `MaintenanceWindowEnd` define the allowed maintenance window.
- Overnight windows such as `22:00` to `04:00` are supported.
- `-IgnoreSchedule` bypasses schedule gating.
- `-IgnoreMaintenanceWindow` bypasses maintenance window gating.
- If `SkipStacksOutsideMaintenanceWindow = $true`, stacks outside their window are reported as skipped instead of failing.

## Reboot Workflow

For each enabled server row:

1. Validate reachability before reboot unless `-SkipPreCheck` is used.
2. Issue `Restart-Computer`.
3. Wait until the server goes offline.
4. Wait until the server returns online.
5. Validate ping if enabled.
6. Validate WinRM if enabled.
7. Validate optional remote command if enabled.
8. Validate services from `Service1`, `Service2`, and `Service3` when populated.
9. Skip service validation when no services are listed.
10. Log and report results.
11. Continue to the next server.

## Command-Line Switches

| Switch | Required | Description |
|---|---:|---|
| `-ConfigPath` | Yes | Path to `Reboot-InOrder.Config.psd1`. |
| `-StackCsvPath` | No | Overrides `StackCsvPath` from the PSD1. |
| `-StackName` | No | Runs one or more named stacks. |
| `-AllStacks` | No | Runs all stacks in the CSV. |
| `-Credential` | No | Supplies a `PSCredential` for remote operations. |
| `-WhatIf` | No | Shows intended reboot actions without rebooting. |
| `-SkipPreCheck` | No | Skips pre-reboot ping and WinRM checks. |
| `-ContinueOnFailure` | No | Continues after stack/server failures. |
| `-ReportPath` | No | Overrides report output path. |
| `-Verbose` | No | Enables verbose output from advanced functions. |
| `-NonInteractive` | No | Disables prompts and requires explicit inputs. |
| `-AllowParallelStacks` | No | Requests parallel stack execution; this implementation warns and runs sequentially. |
| `-MaxParallelStacks` | No | Overrides configured maximum parallel stacks. |
| `-IgnoreSchedule` | No | Ignores `ScheduledStartTime`. |
| `-IgnoreMaintenanceWindow` | No | Ignores maintenance window checks. |
| `-MaxServiceWaitMinutes` | No | Overrides service validation timeout. |

`-ServiceFilePath` is not supported because services are defined in `Reboot-InOrder.Stacks.csv`.

## Usage Examples

Run all stacks:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -AllStacks
```

Run one stack:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -StackName "AppStackA"
```

Run multiple named stacks:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -StackName "AppStackA","AppStackB"
```

Ignore schedule:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -AllStacks -IgnoreSchedule
```

Ignore schedule and maintenance window:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -AllStacks -IgnoreSchedule -IgnoreMaintenanceWindow
```

Request parallel stacks:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -AllStacks -AllowParallelStacks -MaxParallelStacks 2
```

WhatIf execution:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -AllStacks -IgnoreSchedule -IgnoreMaintenanceWindow -WhatIf
```

Credential usage:

```powershell
$Credential = Get-Credential
.\Reboot-InOrder.ps1 -ConfigPath ".\Reboot-InOrder.Config.psd1" -StackName "AppStackA" -Credential $Credential
```

NonInteractive scheduled-task style execution:

```powershell
.\Reboot-InOrder.ps1 -ConfigPath "C:\Scripts\Reboot_In_Order\Reboot-InOrder.Config.psd1" -AllStacks -NonInteractive
```

## Scheduled Task Setup

Use a domain service account, managed service account, or gMSA with the required permissions. Do not store passwords in script files, CSV files, PSD1 files, or README examples.

```powershell
$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument '-NoProfile -ExecutionPolicy AllSigned -File "C:\Scripts\Reboot_In_Order\Reboot-InOrder.ps1" -ConfigPath "C:\Scripts\Reboot_In_Order\Reboot-InOrder.Config.psd1" -AllStacks -NonInteractive'

$Trigger = New-ScheduledTaskTrigger -Once -At "2026-05-25 23:00"

$Principal = New-ScheduledTaskPrincipal `
    -UserId "DOMAIN\svc-RebootStack" `
    -LogonType Password `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName "Reboot_In_Order_Application_Stacks" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Description "Reboots application stacks in CSV-defined order."
```

## Service Account Permissions

The execution account needs:

- Remote reboot rights on target servers.
- WinRM access.
- Remote service query permissions.
- Local administrator rights where required by reboot and WMI service queries.
- Write access to `ReportPath`.
- Write access to `LogPath`.
- Permission to run as a Scheduled Task.

## WinRM Requirements

Validate WinRM before production execution:

```powershell
Test-WSMan ServerName
Invoke-Command -ComputerName ServerName -ScriptBlock { hostname }
```

## Logging And Reporting

The solution writes transcript logs when `IncludeTranscript = $true`.

Reports:

- `Reboot_In_Order_Results_yyyyMMdd_HHmmss.csv`
- `Reboot_In_Order_ServiceChecks_yyyyMMdd_HHmmss.csv`
- `Reboot_In_Order_Results_yyyyMMdd_HHmmss.json`
- `Reboot_In_Order_Results_yyyyMMdd_HHmmss.html`

Reports include:

- `StackName`
- `ServerName`
- `RebootOrder`
- `ScheduledStartTime`
- `ActualStartTime`
- `ActualEndTime`
- `MaintenanceWindowStart`
- `MaintenanceWindowEnd`
- `Service1`
- `Service2`
- `Service3`
- `ServicesChecked`
- `ServiceCheckStatus`
- `RebootStatus`
- `HealthCheckStatus`
- `FailureReason`
- `DurationMinutes`

HTML reports group by `StackName`, show services checked per server, clearly show `SkippedNoServices`, use color-coded status indicators, show timelines, and include summary statistics.

## Failure Handling

If a server fails to reboot, return online, pass health checks, or validate listed services, the current stack stops unless `-ContinueOnFailure` is supplied. Failures are recorded in all reports and transcript logs.

## Code Signing

The solution is compatible with Authenticode signing and does not modify script or module files at runtime.

```powershell
$CodeSigningCert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

Set-AuthenticodeSignature -FilePath ".\Reboot-InOrder.ps1" -Certificate $CodeSigningCert -TimestampServer "<approved timestamp service URL>"
Set-AuthenticodeSignature -FilePath ".\ReportingTools.psm1" -Certificate $CodeSigningCert -TimestampServer "<approved timestamp service URL>"

Get-AuthenticodeSignature -FilePath ".\Reboot-InOrder.ps1"
Get-AuthenticodeSignature -FilePath ".\ReportingTools.psm1"
```

The certificate must include the Code Signing EKU. Use `AllSigned` or `RemoteSigned` according to organizational policy. Code signing does not grant WinRM, reboot, service-query, firewall, or file-system permissions.

## Troubleshooting

Server unreachable:

- Confirm DNS resolution and network connectivity.
- Confirm ICMP is allowed if ping health checks are enabled.

WinRM failures:

- Run `Test-WSMan ServerName`.
- Verify WinRM listener, firewall, SPN, and remoting policy.

Access denied:

- Confirm service account permissions for remote reboot and service queries.

Restart-Computer failures:

- Confirm permissions, RPC/firewall access, and target availability.

Service validation failures:

- Confirm the service name is the real service name.
- Confirm the service exists on the target server.
- Confirm the service can reach `Running` within `MaxServiceWaitMinutes`.

Scheduled task issues:

- Confirm the task account has batch logon rights.
- Confirm `-NonInteractive` is used.
- Confirm `-AllStacks` or `-StackName` is supplied.
- Confirm report and log paths are writable.

Report generation failures:

- Confirm `ReportPath` exists or can be created.
- Confirm disk space and file permissions.

Maintenance window skips:

- Use `-IgnoreMaintenanceWindow` only with approved change control.
- Verify `MaintenanceWindowStart` and `MaintenanceWindowEnd` use `HH:mm`.
