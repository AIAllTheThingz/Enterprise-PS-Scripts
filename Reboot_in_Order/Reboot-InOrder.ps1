[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ConfigPath,
    [ValidateNotNullOrEmpty()][string]$StackCsvPath,
    [ValidateNotNullOrEmpty()][string[]]$StackName,
    [switch]$AllStacks,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SkipPreCheck,
    [switch]$ContinueOnFailure,
    [ValidateNotNullOrEmpty()][string]$ReportPath,
    [switch]$NonInteractive,
    [switch]$AllowParallelStacks,
    [ValidateRange(1,32)][int]$MaxParallelStacks,
    [switch]$IgnoreSchedule,
    [switch]$IgnoreMaintenanceWindow,
    [ValidateRange(1,1440)][int]$MaxServiceWaitMinutes
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Script:RunId = [guid]::NewGuid().ToString()
$Script:TranscriptPath = $null
$Script:Results = @()
$Script:ServiceResults = @()
$Script:Failures = @()
$Script:Config = $null
$Script:ExecutionMode = 'Execute'
$Script:ExitCode = 0

function Import-RebootConfiguration {
<#
.SYNOPSIS
Imports the PSD1 configuration.
.DESCRIPTION
Loads and validates external configuration for the multi-stack reboot workflow.
All environment-specific values are kept outside the signed script.
.PARAMETER Path
Path to Reboot-InOrder.Config.psd1.
.EXAMPLE
Import-RebootConfiguration -Path .\Reboot-InOrder.Config.psd1
.OUTPUTS
System.Collections.Hashtable
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "ConfigPath does not exist: $Path" }
    try { $config = Import-PowerShellDataFile -LiteralPath $Path } catch { throw "Failed to import configuration: $($_.Exception.Message)" }
    foreach ($key in @('StackCsvPath','AllowParallelStacks','MaxParallelStacks','WaitTimeoutMinutes','MaxServiceWaitMinutes','RetryIntervalSeconds','EnforceMaintenanceWindow','SkipStacksOutsideMaintenanceWindow','HealthChecks','ReportPath','LogPath','UseCredential')) {
        Test-RequiredConfigValue -Config $config -Key $key
    }
    foreach ($check in @('Ping','WinRM','Services')) {
        if (-not $config.HealthChecks.ContainsKey($check)) { throw "HealthChecks must contain key: $check" }
    }
    if (-not $config.HealthChecks.ContainsKey('RemoteCommand')) { $config.HealthChecks['RemoteCommand'] = $false }
    if (-not $config.ContainsKey('ReportFormats')) { $config['ReportFormats'] = @('CSV','JSON','HTML') }
    foreach ($format in @($config.ReportFormats)) {
        if (@('CSV','JSON','HTML') -notcontains $format) { throw "Unsupported ReportFormats value: $format" }
    }
    if ([int]$config.WaitTimeoutMinutes -lt 1) { throw "WaitTimeoutMinutes must be at least 1." }
    if ([int]$config.MaxServiceWaitMinutes -lt 1) { throw "MaxServiceWaitMinutes must be at least 1." }
    if ([int]$config.RetryIntervalSeconds -lt 5) { throw "RetryIntervalSeconds must be at least 5." }
    return $config
}

function Test-RequiredConfigValue {
<#
.SYNOPSIS
Validates a required configuration key.
.DESCRIPTION
Ensures a PSD1 key exists and has a usable value. Boolean false is accepted.
.PARAMETER Config
Configuration hashtable.
.PARAMETER Key
Required key name.
.EXAMPLE
Test-RequiredConfigValue -Config $Config -Key StackCsvPath
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([hashtable]$Config,[string]$Key)
    if (-not $Config.ContainsKey($Key)) { throw "Required configuration key is missing: $Key" }
    $value = $Config[$Key]
    if ($null -eq $value) { throw "Required configuration key is null: $Key" }
    if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) { throw "Required configuration key is blank: $Key" }
}

function Initialize-RebootOutput {
<#
.SYNOPSIS
Creates output folders.
.DESCRIPTION
Creates report and log folders. This runtime data creation is allowed for
signed scripts because it does not modify script files.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Initialize-RebootOutput -Config $Config
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([hashtable]$Config)
    foreach ($path in @($Config.ReportPath,$Config.LogPath)) {
        if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force -WhatIf:$false | Out-Null }
    }
}

function Start-RebootTranscript {
<#
.SYNOPSIS
Starts transcript logging.
.DESCRIPTION
Starts transcript logging when enabled. The script does not write credentials
or passwords to disk.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Start-RebootTranscript -Config $Config
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([hashtable]$Config)
    if (-not ($Config.ContainsKey('IncludeTranscript') -and $Config.IncludeTranscript)) { return $null }
    $path = Join-Path $Config.LogPath ("Reboot_In_Order_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try { Start-Transcript -Path $path -Force | Out-Null; $Script:TranscriptPath = $path; return $path } catch { Write-Warning "Failed to start transcript: $($_.Exception.Message)"; return $null }
}

function Stop-RebootTranscript {
<#
.SYNOPSIS
Stops transcript logging.
.DESCRIPTION
Stops transcript logging when a transcript was started.
.EXAMPLE
Stop-RebootTranscript
.OUTPUTS
None
#>
    [CmdletBinding()]
    param()
    if ($Script:TranscriptPath) { try { Stop-Transcript | Out-Null } catch { Write-Warning "Failed to stop transcript: $($_.Exception.Message)" } }
}

function Resolve-RebootCredential {
<#
.SYNOPSIS
Resolves remote operation credentials.
.DESCRIPTION
Uses the supplied PSCredential or prompts only when UseCredential is enabled and
the run is interactive. In NonInteractive mode missing required credentials fail.
.PARAMETER Config
Validated configuration.
.PARAMETER Credential
Optional credential.
.PARAMETER NonInteractive
Prevents prompts.
.EXAMPLE
Resolve-RebootCredential -Config $Config -Credential $Credential -NonInteractive $true
.OUTPUTS
System.Management.Automation.PSCredential
#>
    [CmdletBinding()]
    param([hashtable]$Config,[System.Management.Automation.PSCredential]$Credential,[bool]$NonInteractive)
    if ($Credential) { return $Credential }
    if (-not $Config.UseCredential) { return $null }
    if ($NonInteractive) { throw "UseCredential is true, but -Credential was not supplied and -NonInteractive forbids prompting." }
    $user = ''
    if ($Config.ContainsKey('CredentialUserName')) { $user = $Config.CredentialUserName }
    if ([string]::IsNullOrWhiteSpace($user)) { return Get-Credential -Message 'Enter credentials for reboot operations' }
    return Get-Credential -UserName $user -Message 'Enter credentials for reboot operations'
}

function Resolve-StackCsvPath {
<#
.SYNOPSIS
Resolves the effective stack CSV path.
.DESCRIPTION
Uses -StackCsvPath first, then configuration. Relative paths are resolved from
the script folder for scheduled task reliability.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Resolve-StackCsvPath -Config $Config
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([hashtable]$Config)
    $path = $StackCsvPath
    if ([string]::IsNullOrWhiteSpace($path)) { $path = $Config.StackCsvPath }
    if ([string]::IsNullOrWhiteSpace($path)) { throw "No stack CSV path was supplied." }
    if ([System.IO.Path]::IsPathRooted($path)) { return $path }
    return (Join-Path $PSScriptRoot $path)
}

function Import-StackDefinition {
<#
.SYNOPSIS
Imports stack definitions from CSV.
.DESCRIPTION
Imports Reboot-InOrder.Stacks.csv, validates required columns, trims values,
ignores disabled rows, and leaves service columns optional.
.PARAMETER Path
Stack CSV path.
.EXAMPLE
Import-StackDefinition -Path .\Reboot-InOrder.Stacks.csv
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Stack CSV file does not exist: $Path" }
    $rows = Import-Csv -LiteralPath $Path
    if (@($rows).Count -eq 0) { throw "Stack CSV contains no rows." }
    foreach ($column in @('StackName','ServerName','RebootOrder','ScheduledStartTime','Enabled','MaintenanceWindowStart','MaintenanceWindowEnd','Service1','Service2','Service3','Notes')) {
        if ($rows[0].PSObject.Properties.Name -notcontains $column) { throw "Stack CSV missing required column: $column" }
    }
    $normalized = @()
    foreach ($row in @($rows)) {
        if ([string]::IsNullOrWhiteSpace($row.StackName) -or [string]::IsNullOrWhiteSpace($row.ServerName) -or [string]::IsNullOrWhiteSpace($row.RebootOrder)) { throw "Stack CSV row has blank StackName, ServerName, or RebootOrder." }
        $enabled = $false
        [void][bool]::TryParse(([string]$row.Enabled).Trim(), [ref]$enabled)
        $normalized += [pscustomobject]@{
            StackName = ([string]$row.StackName).Trim()
            ServerName = ([string]$row.ServerName).Trim()
            RebootOrder = [int](([string]$row.RebootOrder).Trim())
            ScheduledStartTime = ([string]$row.ScheduledStartTime).Trim()
            Enabled = $enabled
            MaintenanceWindowStart = ([string]$row.MaintenanceWindowStart).Trim()
            MaintenanceWindowEnd = ([string]$row.MaintenanceWindowEnd).Trim()
            Service1 = ([string]$row.Service1).Trim()
            Service2 = ([string]$row.Service2).Trim()
            Service3 = ([string]$row.Service3).Trim()
            Notes = ([string]$row.Notes).Trim()
        }
    }
    return $normalized
}

function Get-RowServiceList {
<#
.SYNOPSIS
Gets populated service columns from a stack row.
.DESCRIPTION
Trims Service1, Service2, and Service3 values, ignores blanks, and returns only
service names that should be monitored.
.PARAMETER Row
Stack CSV row.
.EXAMPLE
Get-RowServiceList -Row $Row
.OUTPUTS
System.String[]
#>
    [CmdletBinding()]
    param([object]$Row)
    $services = @()
    foreach ($name in @($Row.Service1,$Row.Service2,$Row.Service3)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) { $services += ([string]$name).Trim() }
    }
    return $services
}

function Resolve-SelectedStack {
<#
.SYNOPSIS
Filters selected stacks.
.DESCRIPTION
Applies -StackName or -AllStacks selection. In NonInteractive mode missing stack
selection fails immediately. Interactive mode defaults to all stacks.
.PARAMETER Rows
Imported stack rows.
.EXAMPLE
Resolve-SelectedStack -Rows $Rows
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object[]]$Rows)
    if ($AllStacks) { return @($Rows) }
    if ($StackName -and $StackName.Count -gt 0) {
        $wanted = @{}
        foreach ($name in $StackName) { $wanted[$name.ToLowerInvariant()] = $true }
        $selected = @($Rows | Where-Object { $wanted.ContainsKey($_.StackName.ToLowerInvariant()) })
        if ($selected.Count -eq 0) { throw "No rows matched requested -StackName values." }
        return $selected
    }
    if ($NonInteractive) { throw "Use -AllStacks or -StackName in -NonInteractive mode." }
    return @($Rows)
}

function ConvertTo-TimeSpanOfDay {
<#
.SYNOPSIS
Parses HH:mm time values.
.DESCRIPTION
Parses scheduled start and maintenance window values from stack CSV rows.
.PARAMETER Value
Time value in HH:mm format.
.PARAMETER FieldName
Field name for error messages.
.EXAMPLE
ConvertTo-TimeSpanOfDay -Value '23:00' -FieldName ScheduledStartTime
.OUTPUTS
System.TimeSpan
#>
    [CmdletBinding()]
    param([string]$Value,[string]$FieldName)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$FieldName is blank." }
    $time = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($Value,'HH:mm',[System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::None,[ref]$time)) {
        throw "$FieldName must use HH:mm format. Value: $Value"
    }
    return $time.TimeOfDay
}

function Test-TimeWithinWindow {
<#
.SYNOPSIS
Tests whether current time is inside a maintenance window.
.DESCRIPTION
Supports same-day and overnight maintenance windows such as 22:00 to 04:00.
.PARAMETER Current
Current time of day.
.PARAMETER Start
Window start.
.PARAMETER End
Window end.
.EXAMPLE
Test-TimeWithinWindow -Current (Get-Date).TimeOfDay -Start ([timespan]'22:00') -End ([timespan]'04:00')
.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param([timespan]$Current,[timespan]$Start,[timespan]$End)
    if ($Start -eq $End) { return $true }
    if ($Start -lt $End) { return ($Current -ge $Start -and $Current -le $End) }
    return ($Current -ge $Start -or $Current -le $End)
}

function Test-StackSchedule {
<#
.SYNOPSIS
Evaluates schedule and maintenance eligibility for a stack.
.DESCRIPTION
Checks ScheduledStartTime and maintenance window using the first enabled row in
the stack. -IgnoreSchedule and -IgnoreMaintenanceWindow bypass these checks.
.PARAMETER StackRows
Rows for one stack.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Test-StackSchedule -StackRows $Rows -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object[]]$StackRows,[hashtable]$Config)
    $reference = @($StackRows | Sort-Object RebootOrder | Select-Object -First 1)[0]
    $now = (Get-Date).TimeOfDay
    $scheduleStatus = 'Allowed'
    $maintenanceStatus = 'Allowed'
    $eligible = $true
    if (-not $IgnoreSchedule) {
        $scheduled = ConvertTo-TimeSpanOfDay -Value $reference.ScheduledStartTime -FieldName 'ScheduledStartTime'
        if ($now -lt $scheduled) { $scheduleStatus = 'NotYetScheduled'; $eligible = $false }
    }
    if ($Config.EnforceMaintenanceWindow -and -not $IgnoreMaintenanceWindow) {
        $start = ConvertTo-TimeSpanOfDay -Value $reference.MaintenanceWindowStart -FieldName 'MaintenanceWindowStart'
        $end = ConvertTo-TimeSpanOfDay -Value $reference.MaintenanceWindowEnd -FieldName 'MaintenanceWindowEnd'
        if (-not (Test-TimeWithinWindow -Current $now -Start $start -End $end)) { $maintenanceStatus = 'OutsideMaintenanceWindow'; $eligible = $false }
    }
    return [pscustomobject]@{ Eligible = $eligible; ScheduleStatus = $scheduleStatus; MaintenanceStatus = $maintenanceStatus }
}

function Add-RebootFailure {
<#
.SYNOPSIS
Records a structured failure.
.DESCRIPTION
Adds a failure record with timestamp, stack, server, reason, duration, and stack
trace where available.
.PARAMETER StackName
Stack name.
.PARAMETER ServerName
Server name.
.PARAMETER Status
Failure status.
.PARAMETER FailureReason
Failure reason.
.PARAMETER StartTime
Optional start time.
.PARAMETER ErrorRecord
Optional error record.
.EXAMPLE
Add-RebootFailure -StackName AppStackA -ServerName Server1 -Status FailedHealthCheck -FailureReason 'WinRM failed'
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([string]$StackName,[string]$ServerName,[string]$Status,[string]$FailureReason,[datetime]$StartTime,[System.Management.Automation.ErrorRecord]$ErrorRecord)
    $duration = ''
    if ($StartTime) { $duration = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 2) }
    $stack = ''
    if ($ErrorRecord) { $stack = [string]$ErrorRecord.ScriptStackTrace }
    $Script:Failures += [pscustomobject]@{ Timestamp = (Get-Date).ToString('s'); StackName = $StackName; ServerName = $ServerName; Status = $Status; FailureReason = $FailureReason; DurationMinutes = $duration; StackTrace = $stack }
}

function Test-ServerPing {
<#
.SYNOPSIS
Tests ICMP connectivity.
.DESCRIPTION
Uses Test-Connection with one packet.
.PARAMETER ServerName
Target server.
.EXAMPLE
Test-ServerPing -ServerName Server1.domain.com
.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param([string]$ServerName)
    try { return [bool](Test-Connection -ComputerName $ServerName -Count 1 -Quiet -ErrorAction Stop) } catch { return $false }
}

function Test-ServerWinRM {
<#
.SYNOPSIS
Tests WinRM connectivity.
.DESCRIPTION
Uses Test-WSMan to confirm the target WinRM listener is available.
.PARAMETER ServerName
Target server.
.EXAMPLE
Test-ServerWinRM -ServerName Server1.domain.com
.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param([string]$ServerName)
    try { Test-WSMan -ComputerName $ServerName -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Invoke-RemoteCommandHealthCheck {
<#
.SYNOPSIS
Runs optional remote command validation.
.DESCRIPTION
Executes a configured script block through Invoke-Command to validate remote
command execution after reboot.
.PARAMETER ServerName
Target server.
.PARAMETER Credential
Optional credential.
.PARAMETER CommandText
Command text.
.EXAMPLE
Invoke-RemoteCommandHealthCheck -ServerName Server1 -CommandText hostname
.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param([string]$ServerName,[System.Management.Automation.PSCredential]$Credential,[string]$CommandText)
    if ([string]::IsNullOrWhiteSpace($CommandText)) { $CommandText = 'hostname' }
    try {
        $scriptBlock = [scriptblock]::Create($CommandText)
        if ($Credential) { Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock $scriptBlock -ErrorAction Stop | Out-Null }
        else { Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock -ErrorAction Stop | Out-Null }
        return $true
    } catch { return $false }
}

function Test-RebootPreCheck {
<#
.SYNOPSIS
Runs pre-reboot checks.
.DESCRIPTION
Validates ping and WinRM before reboot unless -SkipPreCheck is supplied.
.PARAMETER ServerName
Target server.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Test-RebootPreCheck -ServerName Server1 -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([string]$ServerName,[hashtable]$Config)
    $ping = 'Skipped'
    $winrm = 'Skipped'
    if ($Config.HealthChecks.Ping) { if (Test-ServerPing -ServerName $ServerName) { $ping = 'Passed' } else { $ping = 'Failed' } }
    if ($Config.HealthChecks.WinRM) { if (Test-ServerWinRM -ServerName $ServerName) { $winrm = 'Passed' } else { $winrm = 'Failed' } }
    return [pscustomobject]@{ Ping = $ping; WinRM = $winrm; Passed = (($ping -ne 'Failed') -and ($winrm -ne 'Failed')) }
}

function Wait-ServerOffline {
<#
.SYNOPSIS
Waits for server offline state.
.DESCRIPTION
Polls ping until the server is observed offline or timeout is reached.
.PARAMETER ServerName
Target server.
.PARAMETER Config
Validated configuration.
.PARAMETER StartTime
Workflow start time.
.EXAMPLE
Wait-ServerOffline -ServerName Server1 -Config $Config -StartTime (Get-Date)
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([string]$ServerName,[hashtable]$Config,[datetime]$StartTime)
    Start-Sleep -Seconds ([int]$Config.OfflineDetectionGraceSeconds)
    $deadline = $StartTime.AddMinutes([int]$Config.WaitTimeoutMinutes)
    $offlineCount = 0
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-ServerPing -ServerName $ServerName)) {
            $offlineCount++
            if ($offlineCount -ge [int]$Config.RequiredOfflineObservations) { return [pscustomobject]@{ Status = 'OfflineObserved'; FailureReason = '' } }
        } else { $offlineCount = 0 }
        Start-Sleep -Seconds ([int]$Config.RetryIntervalSeconds)
    }
    return [pscustomobject]@{ Status = 'Failed'; FailureReason = "Server did not go offline within $($Config.WaitTimeoutMinutes) minutes." }
}

function Wait-ServerOnline {
<#
.SYNOPSIS
Waits for server online state.
.DESCRIPTION
Polls ping until the server is observed online or timeout is reached.
.PARAMETER ServerName
Target server.
.PARAMETER Config
Validated configuration.
.PARAMETER StartTime
Workflow start time.
.EXAMPLE
Wait-ServerOnline -ServerName Server1 -Config $Config -StartTime (Get-Date)
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([string]$ServerName,[hashtable]$Config,[datetime]$StartTime)
    $deadline = $StartTime.AddMinutes([int]$Config.WaitTimeoutMinutes)
    $onlineCount = 0
    while ((Get-Date) -lt $deadline) {
        if (Test-ServerPing -ServerName $ServerName) {
            $onlineCount++
            if ($onlineCount -ge [int]$Config.RequiredOnlineObservations) { return [pscustomobject]@{ Status = 'Online'; FailureReason = '' } }
        } else { $onlineCount = 0 }
        Start-Sleep -Seconds ([int]$Config.RetryIntervalSeconds)
    }
    return [pscustomobject]@{ Status = 'Failed'; FailureReason = "Server did not return online within $($Config.WaitTimeoutMinutes) minutes." }
}

function Get-RemoteServiceState {
<#
.SYNOPSIS
Gets remote service state.
.DESCRIPTION
Uses Win32_Service through Get-WmiObject for Windows PowerShell 5.0 compatibility.
.PARAMETER ServerName
Target server.
.PARAMETER ServiceName
Service name.
.PARAMETER Credential
Optional credential.
.EXAMPLE
Get-RemoteServiceState -ServerName Server1 -ServiceName W3SVC
.OUTPUTS
System.Object
#>
    [CmdletBinding()]
    param([string]$ServerName,[string]$ServiceName,[System.Management.Automation.PSCredential]$Credential)
    $filter = "Name='$($ServiceName.Replace("'","''"))'"
    if ($Credential) { return Get-WmiObject -Class Win32_Service -ComputerName $ServerName -Credential $Credential -Filter $filter -ErrorAction Stop }
    return Get-WmiObject -Class Win32_Service -ComputerName $ServerName -Filter $filter -ErrorAction Stop
}

function Wait-StackServiceHealth {
<#
.SYNOPSIS
Waits for listed services to become running.
.DESCRIPTION
Checks only populated Service1, Service2, and Service3 values. Blank service
columns are ignored. If no services are listed, service validation is skipped.
.PARAMETER Row
Stack CSV row.
.PARAMETER Services
Trimmed service names.
.PARAMETER Config
Validated configuration.
.PARAMETER Credential
Optional credential.
.EXAMPLE
Wait-StackServiceHealth -Row $Row -Services @('W3SVC') -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Row,[string[]]$Services,[hashtable]$Config,[System.Management.Automation.PSCredential]$Credential)
    if (@($Services).Count -eq 0) { return [pscustomobject]@{ Status = 'SkippedNoServices'; FailureReason = 'No services listed for this server.' } }
    if (-not $Config.HealthChecks.Services) { return [pscustomobject]@{ Status = 'Skipped'; FailureReason = 'Service health checks disabled in configuration.' } }
    $start = Get-Date
    $deadline = $start.AddMinutes([int]$Config.MaxServiceWaitMinutes)
    $attempt = 0
    do {
        $attempt++
        $allPassed = $true
        foreach ($serviceName in @($Services)) {
            $status = 'Failed'
            $actual = ''
            $reason = ''
            try {
                $service = Get-RemoteServiceState -ServerName $Row.ServerName -ServiceName $serviceName -Credential $Credential
                if ($null -eq $service) {
                    $reason = 'Service does not exist.'
                } elseif ([string]$service.State -ieq 'Running') {
                    $status = 'Healthy'
                    $actual = $service.State
                    $reason = 'Service is running.'
                } else {
                    $actual = $service.State
                    $reason = "Service state is $($service.State), expected Running."
                }
            } catch {
                $reason = $_.Exception.Message
            }
            $Script:ServiceResults += [pscustomobject]@{
                Timestamp = (Get-Date).ToString('s')
                StackName = $Row.StackName
                ServerName = $Row.ServerName
                RebootOrder = $Row.RebootOrder
                ServiceName = $serviceName
                Attempt = $attempt
                ActualStatus = $actual
                ServiceCheckStatus = $status
                FailureReason = $reason
            }
            if ($status -ne 'Healthy') { $allPassed = $false }
        }
        if ($allPassed) { return [pscustomobject]@{ Status = 'Healthy'; FailureReason = '' } }
        if ((Get-Date) -lt $deadline) { Start-Sleep -Seconds ([int]$Config.RetryIntervalSeconds) }
    } while ((Get-Date) -lt $deadline)
    return [pscustomobject]@{ Status = 'FailedServiceValidation'; FailureReason = "One or more services did not reach Running within $($Config.MaxServiceWaitMinutes) minutes." }
}

function Invoke-ServerReboot {
<#
.SYNOPSIS
Issues Restart-Computer for one server.
.DESCRIPTION
Reboots exactly one server. The caller waits for recovery before proceeding.
.PARAMETER ServerName
Target server.
.PARAMETER Credential
Optional credential.
.EXAMPLE
Invoke-ServerReboot -ServerName Server1.domain.com
.OUTPUTS
None
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([string]$ServerName,[System.Management.Automation.PSCredential]$Credential)
    if ($PSCmdlet.ShouldProcess($ServerName, 'Restart remote computer')) {
        if ($Credential) { Restart-Computer -ComputerName $ServerName -Credential $Credential -Force -ErrorAction Stop }
        else { Restart-Computer -ComputerName $ServerName -Force -ErrorAction Stop }
    }
}

function New-ResultObject {
<#
.SYNOPSIS
Creates a per-server report row.
.DESCRIPTION
Creates the required report schema for each stack/server action.
.PARAMETER Row
Stack CSV row.
.PARAMETER ActualStartTime
Actual start time.
.PARAMETER ActualEndTime
Actual end time.
.PARAMETER ServicesChecked
Services checked text.
.PARAMETER ServiceCheckStatus
Service check status.
.PARAMETER RebootStatus
Reboot status.
.PARAMETER HealthCheckStatus
Health check status.
.PARAMETER FailureReason
Failure reason.
.EXAMPLE
New-ResultObject -Row $Row -RebootStatus Success
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Row,[datetime]$ActualStartTime,[datetime]$ActualEndTime,[string]$ServicesChecked,[string]$ServiceCheckStatus,[string]$RebootStatus,[string]$HealthCheckStatus,[string]$FailureReason)
    [pscustomobject]@{
        StackName = $Row.StackName
        ServerName = $Row.ServerName
        RebootOrder = $Row.RebootOrder
        ScheduledStartTime = $Row.ScheduledStartTime
        ActualStartTime = $ActualStartTime.ToString('s')
        ActualEndTime = $ActualEndTime.ToString('s')
        MaintenanceWindowStart = $Row.MaintenanceWindowStart
        MaintenanceWindowEnd = $Row.MaintenanceWindowEnd
        Service1 = $Row.Service1
        Service2 = $Row.Service2
        Service3 = $Row.Service3
        ServicesChecked = $ServicesChecked
        ServiceCheckStatus = $ServiceCheckStatus
        RebootStatus = $RebootStatus
        HealthCheckStatus = $HealthCheckStatus
        FailureReason = $FailureReason
        DurationMinutes = [math]::Round(($ActualEndTime - $ActualStartTime).TotalMinutes, 2)
        Notes = $Row.Notes
    }
}

function Invoke-StackServer {
<#
.SYNOPSIS
Processes one server in a stack.
.DESCRIPTION
Runs prechecks, reboot, offline/online waits, ping/WinRM/remote command checks,
and optional service checks from Service1, Service2, and Service3.
.PARAMETER Row
Stack CSV row.
.PARAMETER Config
Validated configuration.
.PARAMETER Credential
Optional credential.
.EXAMPLE
Invoke-StackServer -Row $Row -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([object]$Row,[hashtable]$Config,[System.Management.Automation.PSCredential]$Credential)
    $start = Get-Date
    $services = @(Get-RowServiceList -Row $Row)
    $servicesChecked = ($services -join ';')
    $serviceStatus = 'SkippedNoServices'
    if ($services.Count -gt 0) { $serviceStatus = 'NotStarted' }
    $rebootStatus = 'Success'
    $healthStatus = 'Passed'
    $failureReason = ''
    try {
        if (-not $SkipPreCheck) {
            $pre = Test-RebootPreCheck -ServerName $Row.ServerName -Config $Config
            if (-not $pre.Passed) { throw "Precheck failed. Ping=$($pre.Ping); WinRM=$($pre.WinRM)" }
        }
        if ($WhatIfPreference) {
            if ($PSCmdlet.ShouldProcess($Row.ServerName, 'Restart remote computer and validate stack health')) { }
            $rebootStatus = 'WhatIf'
            $healthStatus = 'WhatIf'
            if ($services.Count -gt 0) { $serviceStatus = 'WhatIf' }
        } else {
            Invoke-ServerReboot -ServerName $Row.ServerName -Credential $Credential
            $offline = Wait-ServerOffline -ServerName $Row.ServerName -Config $Config -StartTime $start
            if ($offline.Status -ne 'OfflineObserved') { throw $offline.FailureReason }
            $online = Wait-ServerOnline -ServerName $Row.ServerName -Config $Config -StartTime $start
            if ($online.Status -ne 'Online') { throw $online.FailureReason }
            if ($Config.HealthChecks.Ping -and -not (Test-ServerPing -ServerName $Row.ServerName)) { throw 'Ping health check failed after reboot.' }
            if ($Config.HealthChecks.WinRM -and -not (Test-ServerWinRM -ServerName $Row.ServerName)) { throw 'WinRM health check failed after reboot.' }
            if ($Config.HealthChecks.RemoteCommand) {
                $commandText = 'hostname'
                if ($Config.ContainsKey('RemoteCommandScriptBlock')) { $commandText = $Config.RemoteCommandScriptBlock }
                if (-not (Invoke-RemoteCommandHealthCheck -ServerName $Row.ServerName -Credential $Credential -CommandText $commandText)) { throw 'Remote command health check failed after reboot.' }
            }
            if ($services.Count -gt 0) {
                $svc = Wait-StackServiceHealth -Row $Row -Services $services -Config $Config -Credential $Credential
                $serviceStatus = $svc.Status
                if ($svc.Status -notin @('Healthy','Skipped')) { throw $svc.FailureReason }
            }
        }
    } catch {
        $failureReason = $_.Exception.Message
        $rebootStatus = 'Failed'
        $healthStatus = 'Failed'
        if ($failureReason -match 'service') { $serviceStatus = 'FailedServiceValidation'; $rebootStatus = 'FailedServiceValidation' }
        elseif ($failureReason -match 'Precheck') { $rebootStatus = 'FailedPreCheck' }
        elseif ($failureReason -match 'online|offline|reboot') { $rebootStatus = 'FailedReboot' }
        else { $rebootStatus = 'FailedHealthCheck' }
        Add-RebootFailure -StackName $Row.StackName -ServerName $Row.ServerName -Status $rebootStatus -FailureReason $failureReason -StartTime $start -ErrorRecord $_
        if ($ContinueOnFailure) { $rebootStatus = 'ContinueOnFailure'; Write-Warning ("Continuing after failure on {0}/{1}: {2}" -f $Row.StackName,$Row.ServerName,$failureReason) }
    }
    $end = Get-Date
    return New-ResultObject -Row $Row -ActualStartTime $start -ActualEndTime $end -ServicesChecked $servicesChecked -ServiceCheckStatus $serviceStatus -RebootStatus $rebootStatus -HealthCheckStatus $healthStatus -FailureReason $failureReason
}

function New-SkippedStackResult {
<#
.SYNOPSIS
Creates skipped result rows for a stack.
.DESCRIPTION
Creates result rows when a stack is skipped due to schedule, maintenance window,
or disabled rows.
.PARAMETER Row
Stack row.
.PARAMETER Status
Skipped status.
.PARAMETER Reason
Reason text.
.EXAMPLE
New-SkippedStackResult -Row $Row -Status SkippedBySchedule -Reason 'Not yet scheduled'
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Row,[string]$Status,[string]$Reason)
    $now = Get-Date
    return New-ResultObject -Row $Row -ActualStartTime $now -ActualEndTime $now -ServicesChecked ((Get-RowServiceList -Row $Row) -join ';') -ServiceCheckStatus 'Skipped' -RebootStatus $Status -HealthCheckStatus 'Skipped' -FailureReason $Reason
}

function Invoke-StackSequence {
<#
.SYNOPSIS
Processes one application stack.
.DESCRIPTION
Processes enabled servers in RebootOrder sequence and never reboots multiple
servers simultaneously within the same stack.
.PARAMETER StackName
Stack name.
.PARAMETER StackRows
Rows for the stack.
.PARAMETER Config
Validated configuration.
.PARAMETER Credential
Optional credential.
.EXAMPLE
Invoke-StackSequence -StackName AppStackA -StackRows $Rows -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([string]$StackName,[object[]]$StackRows,[hashtable]$Config,[System.Management.Automation.PSCredential]$Credential)
    $results = @()
    $enabledRows = @($StackRows | Where-Object { $_.Enabled } | Sort-Object RebootOrder)
    if ($enabledRows.Count -eq 0) {
        foreach ($row in @($StackRows)) { $results += New-SkippedStackResult -Row $row -Status 'SkippedDisabled' -Reason 'No enabled rows in stack.' }
        return $results
    }
    $schedule = Test-StackSchedule -StackRows $enabledRows -Config $Config
    if (-not $schedule.Eligible) {
        $status = 'SkippedBySchedule'
        $reason = $schedule.ScheduleStatus
        if ($schedule.MaintenanceStatus -eq 'OutsideMaintenanceWindow') { $status = 'SkippedOutsideMaintenanceWindow'; $reason = $schedule.MaintenanceStatus }
        if ($status -eq 'SkippedOutsideMaintenanceWindow' -and -not $Config.SkipStacksOutsideMaintenanceWindow) { throw "Stack $StackName is outside maintenance window." }
        foreach ($row in $enabledRows) { $results += New-SkippedStackResult -Row $row -Status $status -Reason $reason }
        return $results
    }
    $index = 0
    foreach ($row in $enabledRows) {
        $index++
        Write-Progress -Activity 'Reboot_In_Order' -Status ("{0} {1}/{2} {3}" -f $StackName,$index,$enabledRows.Count,$row.ServerName) -PercentComplete (($index / $enabledRows.Count) * 100)
        Write-Information -MessageData ("[{0}] Stack {1}: processing order {2} server {3}" -f (Get-Date -Format 's'),$StackName,$row.RebootOrder,$row.ServerName) -InformationAction Continue
        $result = Invoke-StackServer -Row $row -Config $Config -Credential $Credential
        $results += $result
        if ($result.RebootStatus -match '^Failed' -and -not $ContinueOnFailure) { throw "Stopping stack $StackName after failure on $($row.ServerName): $($result.FailureReason)" }
    }
    Write-Progress -Activity 'Reboot_In_Order' -Completed
    return $results
}

function Invoke-AllStackSequence {
<#
.SYNOPSIS
Processes all selected stacks.
.DESCRIPTION
Processes stacks independently. Parallel stack execution is accepted by switch
and configuration, but Windows PowerShell 5.0-compatible implementation processes
stacks sequentially unless a future signed worker implementation is approved.
.PARAMETER Rows
Selected stack rows.
.PARAMETER Config
Validated configuration.
.PARAMETER Credential
Optional credential.
.EXAMPLE
Invoke-AllStackSequence -Rows $Rows -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object[]]$Rows,[hashtable]$Config,[System.Management.Automation.PSCredential]$Credential)
    $results = @()
    $stackNames = @($Rows | Select-Object -ExpandProperty StackName -Unique | Sort-Object)
    if (($AllowParallelStacks -or $Config.AllowParallelStacks) -and ([int]$Config.MaxParallelStacks -gt 1 -or $MaxParallelStacks -gt 1)) {
        Write-Warning 'Parallel stack execution was requested, but this PowerShell 5.0 implementation processes stacks sequentially to preserve signed-script safety and ordered logging.'
    }
    foreach ($stack in $stackNames) {
        try {
            $stackRows = @($Rows | Where-Object { $_.StackName -eq $stack })
            $results += Invoke-StackSequence -StackName $stack -StackRows $stackRows -Config $Config -Credential $Credential
        } catch {
            Add-RebootFailure -StackName $stack -ServerName '' -Status 'TerminatingFailure' -FailureReason $_.Exception.Message -StartTime (Get-Date) -ErrorRecord $_
            if (-not $ContinueOnFailure) { throw }
        }
    }
    return $results
}

function Get-RebootSummary {
<#
.SYNOPSIS
Builds summary statistics.
.DESCRIPTION
Aggregates stack/server/service/failure counts for reports.
.PARAMETER Results
Per-server results.
.PARAMETER ServiceResults
Per-service results.
.PARAMETER Failures
Failure records.
.EXAMPLE
Get-RebootSummary -Results $Results -ServiceResults $Services -Failures $Failures
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object[]]$Results,[object[]]$ServiceResults,[object[]]$Failures)
    [pscustomobject]@{
        TotalStacks = @($Results | Select-Object -ExpandProperty StackName -Unique).Count
        TotalServers = @($Results).Count
        SuccessfulServers = @($Results | Where-Object { $_.RebootStatus -eq 'Success' -or $_.RebootStatus -eq 'WhatIf' }).Count
        FailedServers = @($Results | Where-Object { $_.RebootStatus -match '^Failed' }).Count
        SkippedServers = @($Results | Where-Object { $_.RebootStatus -match '^Skipped' }).Count
        ContinueOnFailureServers = @($Results | Where-Object { $_.RebootStatus -eq 'ContinueOnFailure' }).Count
        ServersWithServices = @($Results | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ServicesChecked) }).Count
        ServersWithoutServices = @($Results | Where-Object { [string]::IsNullOrWhiteSpace($_.ServicesChecked) }).Count
        ServiceCheckAttempts = @($ServiceResults).Count
        FailedServiceChecks = @($ServiceResults | Where-Object { $_.ServiceCheckStatus -eq 'Failed' }).Count
        FailureRecords = @($Failures).Count
        TranscriptPath = $Script:TranscriptPath
    }
}

function Write-RebootSummary {
<#
.SYNOPSIS
Writes a run summary.
.DESCRIPTION
Writes non-secret summary and generated report path information.
.PARAMETER Summary
Summary object.
.PARAMETER ReportPaths
Report path object.
.EXAMPLE
Write-RebootSummary -Summary $Summary -ReportPaths $Paths
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([object]$Summary,[object]$ReportPaths)
    Write-Output ''
    Write-Output 'Reboot_In_Order summary'
    foreach ($property in $Summary.PSObject.Properties) { Write-Output ("{0}: {1}" -f $property.Name,$property.Value) }
    Write-Output 'Report paths'
    foreach ($property in $ReportPaths.PSObject.Properties) { if ($property.Value) { Write-Output ("{0}: {1}" -f $property.Name,$property.Value) } }
}

try {
    if ($WhatIfPreference) { $Script:ExecutionMode = 'WhatIf' }
    $Script:Config = Import-RebootConfiguration -Path $ConfigPath
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) { $Script:Config['ReportPath'] = $ReportPath }
    if ($MaxServiceWaitMinutes -gt 0) { $Script:Config['MaxServiceWaitMinutes'] = $MaxServiceWaitMinutes }
    if ($AllowParallelStacks) { $Script:Config['AllowParallelStacks'] = $true }
    if ($MaxParallelStacks -gt 0) { $Script:Config['MaxParallelStacks'] = $MaxParallelStacks }
    Initialize-RebootOutput -Config $Script:Config
    Start-RebootTranscript -Config $Script:Config | Out-Null
    $resolvedCsv = Resolve-StackCsvPath -Config $Script:Config
    $rows = Import-StackDefinition -Path $resolvedCsv
    $selectedRows = Resolve-SelectedStack -Rows $rows
    $effectiveCredential = Resolve-RebootCredential -Config $Script:Config -Credential $Credential -NonInteractive ([bool]$NonInteractive)
    Write-Output ("RunId: {0}" -f $Script:RunId)
    Write-Output ("ExecutionMode: {0}" -f $Script:ExecutionMode)
    Write-Output ("StackCsvPath: {0}" -f $resolvedCsv)
    Write-Output ("SelectedStacks: {0}" -f (@($selectedRows | Select-Object -ExpandProperty StackName -Unique) -join ', '))
    Write-Output ("ReportPath: {0}" -f $Script:Config.ReportPath)
    Write-Output ("LogPath: {0}" -f $Script:Config.LogPath)
    Write-Output ("NonInteractive: {0}" -f ([bool]$NonInteractive))
    $Script:Results = Invoke-AllStackSequence -Rows $selectedRows -Config $Script:Config -Credential $effectiveCredential
} catch {
    Add-RebootFailure -StackName '' -ServerName '' -Status 'TerminatingFailure' -FailureReason $_.Exception.Message -StartTime (Get-Date) -ErrorRecord $_
    Write-Error $_.Exception.Message
    if (-not $ContinueOnFailure) { $Script:ExitCode = 1 }
} finally {
    try {
        $csvForReport = ''
        if ($Script:Config) { $csvForReport = Resolve-StackCsvPath -Config $Script:Config }
        $metadata = [pscustomobject]@{
            ReportTitle = 'Reboot In Order Report'
            RunId = $Script:RunId
            RunTimestamp = (Get-Date).ToString('s')
            ExecutionMode = $Script:ExecutionMode
            ConfigPath = $ConfigPath
            StackCsvPath = $csvForReport
            ReportPath = $Script:Config.ReportPath
            LogPath = $Script:Config.LogPath
            AllowParallelStacks = $Script:Config.AllowParallelStacks
            MaxParallelStacks = $Script:Config.MaxParallelStacks
            IgnoreSchedule = [bool]$IgnoreSchedule
            IgnoreMaintenanceWindow = [bool]$IgnoreMaintenanceWindow
            NonInteractive = [bool]$NonInteractive
            TranscriptPath = $Script:TranscriptPath
        }
        $summary = Get-RebootSummary -Results $Script:Results -ServiceResults $Script:ServiceResults -Failures $Script:Failures
        Import-Module (Join-Path $PSScriptRoot 'ReportingTools.psm1') -Force
        $paths = Export-RebootReportBundle -Metadata $metadata -Summary $summary -Results $Script:Results -ServiceResults $Script:ServiceResults -Failures $Script:Failures -OutputPath $Script:Config.ReportPath -ReportFormats $Script:Config.ReportFormats
        Write-RebootSummary -Summary $summary -ReportPaths $paths
    } catch {
        Write-Warning "Report generation failed: $($_.Exception.Message)"
    }
    Stop-RebootTranscript
    if ($Script:ExitCode -ne 0) { exit $Script:ExitCode }
}
