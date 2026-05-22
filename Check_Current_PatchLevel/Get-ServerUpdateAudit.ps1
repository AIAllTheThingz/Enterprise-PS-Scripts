<#
.SYNOPSIS
Audits Windows servers for recently installed updates and exports modular reports.

.DESCRIPTION
Get-ServerUpdateAudit.ps1 reads enterprise settings from a PSD1 configuration
file, prompts for runtime credentials when needed, validates connectivity, and
collects update information from supported Windows Server platforms.

The script is intentionally split into small functions so operators and support
staff can understand what failed, why it failed, and which fallback path was
used. Reporting is handled by a separate reusable module.

.PARAMETER ConfigPath
Path to the PSD1 configuration file.

.PARAMETER ServerCsvPath
Optional override for the server list CSV path defined in configuration.

.PARAMETER OutputPath
Optional override for the report output path defined in configuration.

.PARAMETER Credential
Optional credential to use for remote queries. When omitted, the script prompts
using a prepopulated DOMAIN\Username value from configuration.

.PARAMETER ReportFormat
Optional report format override. Supported values are Csv, Json, Txt, and Html.

.PARAMETER VerboseLogging
Enables extra console and log detail for troubleshooting.

.PARAMETER DryRun
Runs only the connectivity and access validation workflow. No update history is
queried in this mode.

.PARAMETER ConnectivityOnly
Alias-style switch for dry-run connectivity validation.

.PARAMETER NoWinRM
Disables WinRM and PowerShell remoting usage. This keeps the audit on CIM/WMI-
compatible paths only and skips update sources that require remoting.

.PARAMETER MonthsBack
Optional override for the historical lookback window. A value of 0 keeps the
report in latest-by-category mode. A value greater than 0 returns all matching
updates installed within the last N months.

.EXAMPLE
.\Get-ServerUpdateAudit.ps1 -ConfigPath .\ServerUpdateAudit.config.psd1

.EXAMPLE
.\Get-ServerUpdateAudit.ps1 -ConfigPath .\ServerUpdateAudit.config.psd1 -DryRun

.EXAMPLE
.\Get-ServerUpdateAudit.ps1 -ConfigPath .\ServerUpdateAudit.config.psd1 -ReportFormat Csv,Html -VerboseLogging

.EXAMPLE
.\Get-ServerUpdateAudit.ps1 -ConfigPath .\ServerUpdateAudit.config.psd1 -NoWinRM

.EXAMPLE
.\Get-ServerUpdateAudit.ps1 -ConfigPath .\ServerUpdateAudit.config.psd1 -MonthsBack 6

.NOTES
Compatible with Windows PowerShell 5.1.
#>

# ------------------------------------------------------------
# Parameter definition and script startup
# This section defines supported command-line switches and
# enables strict behavior so production failures are surfaced
# consistently and early.
# ------------------------------------------------------------
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [string]$ServerCsvPath,

    [string]$OutputPath,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateSet('Csv', 'Json', 'Txt', 'Html')]
    [string[]]$ReportFormat,

    [switch]$VerboseLogging,

    [switch]$DryRun,

    [switch]$ConnectivityOnly,

    [switch]$NoWinRM,

    [ValidateRange(0, 60)]
    [int]$MonthsBack
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:LogFilePath = $null
$script:VerboseLoggingEnabled = $false
$script:RunTimeStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'

# ------------------------------------------------------------
# General utility functions
# These helpers centralize common validation, path handling,
# Boolean conversion, and logging behavior used everywhere else.
# ------------------------------------------------------------

<#
.SYNOPSIS
Resolves a path to an absolute filesystem path.

.DESCRIPTION
Converts relative paths to absolute paths so later file and logging operations
always work with a normalized location.

.PARAMETER Path
Path to resolve.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Resolve-AbsolutePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path cannot be blank.'
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location).Path -ChildPath $Path))
}

<#
.SYNOPSIS
Ensures a directory exists.

.DESCRIPTION
Creates the target folder when it is missing. This keeps reporting and logging
code simple and avoids repetitive path-creation logic throughout the script.

.PARAMETER Path
Folder path to verify or create.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Ensure-Directory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolved = Resolve-AbsolutePath -Path $Path
    if (-not (Test-Path -LiteralPath $resolved)) {
        New-Item -Path $resolved -ItemType Directory -Force | Out-Null
    }

    return $resolved
}

<#
.SYNOPSIS
Determines whether a value is blank.

.DESCRIPTION
Returns true when the supplied value is null, empty, or whitespace only.

.PARAMETER Value
Value to test.

.OUTPUTS
System.Boolean

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Test-Blank {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    return ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value))
}

<#
.SYNOPSIS
Writes a timestamped log message.

.DESCRIPTION
Sends a message to the console and, when logging is enabled, appends the same
entry to the current run log file. Sensitive data such as passwords must never
be passed into this function.

.PARAMETER Level
Severity level for the message.

.PARAMETER Message
Message text to write.

.OUTPUTS
None

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Level -eq 'DEBUG' -and -not $script:VerboseLoggingEnabled) {
        return
    }

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line }
    }

    if (-not (Test-Blank $script:LogFilePath)) {
        Add-Content -LiteralPath $script:LogFilePath -Value $line
    }
}

<#
.SYNOPSIS
Converts common configuration values into a Boolean.

.DESCRIPTION
Allows configuration files to use either native Boolean values or the strings
true and false without leaving parsing behavior ambiguous.

.PARAMETER Value
Value to convert.

.PARAMETER Name
Friendly setting name used in errors.

.OUTPUTS
System.Boolean

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function ConvertTo-BooleanSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Value -is [bool]) {
        return $Value
    }

    $textValue = [string]$Value
    if ($textValue -eq 'true' -or $textValue -eq 'false') {
        return [System.Convert]::ToBoolean($textValue)
    }

    throw "Configuration setting '$Name' must be Boolean."
}

<#
.SYNOPSIS
Reads a required or optional value from a hashtable.

.DESCRIPTION
Validates that a configuration setting exists and, unless blank values are
allowed, also verifies that it contains a usable value.

.PARAMETER Table
Hashtable to read from.

.PARAMETER Name
Setting name to retrieve.

.PARAMETER AllowBlank
Allows blank values when specified.

.OUTPUTS
System.Object

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-HashtableValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Table,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$AllowBlank
    )

    if (-not $Table.ContainsKey($Name)) {
        throw "Configuration is missing required setting '$Name'."
    }

    $value = $Table[$Name]
    if (-not $AllowBlank -and (Test-Blank $value)) {
        throw "Configuration setting '$Name' cannot be blank."
    }

    return $value
}

<#
.SYNOPSIS
Creates a report-safe error message.

.DESCRIPTION
Extracts the most useful details from an ErrorRecord so support staff can see
what failed without opening a debugger or rerunning the script interactively.

.PARAMETER ErrorRecord
The PowerShell error record to summarize.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-ErrorMessageDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add($ErrorRecord.Exception.Message)

    if ($null -ne $ErrorRecord.CategoryInfo) {
        $parts.Add('Category: {0}' -f $ErrorRecord.CategoryInfo.Category)
    }

    if (-not (Test-Blank $ErrorRecord.FullyQualifiedErrorId)) {
        $parts.Add('FQID: {0}' -f $ErrorRecord.FullyQualifiedErrorId)
    }

    return ($parts -join ' | ')
}

<#
.SYNOPSIS
Safely converts a value to DateTime when possible.

.DESCRIPTION
Normalizes date handling across update sources that may return true DateTime
values, strings, or blanks.

.PARAMETER Value
Value to convert.

.OUTPUTS
System.DateTime or $null

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function ConvertTo-NullableDateTime {
    [CmdletBinding()]
    param(
        $Value
    )

    if ($null -eq $Value -or (Test-Blank $Value)) {
        return $null
    }

    try {
        return [datetime]$Value
    }
    catch {
        return $null
    }
}

# ------------------------------------------------------------
# Configuration and credential handling
# These functions load external settings and prompt for runtime
# credentials without ever persisting the password.
# ------------------------------------------------------------

<#
.SYNOPSIS
Imports and validates the audit configuration.

.DESCRIPTION
Loads the PSD1 file, validates the expected hashtable structure, and returns a
normalized configuration object used by the main workflow.

.PARAMETER ConfigPath
Path to the PSD1 configuration file.

.PARAMETER ServerCsvPathOverride
Optional command-line override for the server CSV path.

.PARAMETER OutputPathOverride
Optional command-line override for the report output path.

.PARAMETER ReportFormatOverride
Optional command-line override for enabled report formats.

.PARAMETER VerboseLogging
Enables verbose logging regardless of config.

.PARAMETER DryRun
Forces dry-run mode regardless of config.

.PARAMETER ConnectivityOnly
Alias-style dry-run override.

.PARAMETER NoWinRM
Disables WinRM and PowerShell remoting usage regardless of configuration.

.PARAMETER MonthsBackOverride
Optional command-line override for the historical lookback window.

.OUTPUTS
System.Collections.Hashtable

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Import-AuditConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [string]$ServerCsvPathOverride,

        [string]$OutputPathOverride,

        [string[]]$ReportFormatOverride,

        [switch]$VerboseLogging,

        [switch]$DryRun,

        [switch]$ConnectivityOnly,

        [switch]$NoWinRM,

        [int]$MonthsBackOverride
    )

    $resolvedConfigPath = Resolve-AbsolutePath -Path $ConfigPath
    if (-not (Test-Path -LiteralPath $resolvedConfigPath)) {
        throw "Configuration file was not found: $resolvedConfigPath"
    }

    $config = Import-PowerShellDataFile -LiteralPath $resolvedConfigPath
    if ($null -eq $config -or -not ($config -is [hashtable])) {
        throw "Configuration file did not return a hashtable: $resolvedConfigPath"
    }

    $reports = [hashtable](Get-HashtableValue -Table $config -Name 'Reports')
    $logging = [hashtable](Get-HashtableValue -Table $config -Name 'Logging')
    $query = [hashtable](Get-HashtableValue -Table $config -Name 'Query')
    $connection = [hashtable](Get-HashtableValue -Table $config -Name 'Connection')

    $enabledFormats = @()
    foreach ($formatName in @('Csv', 'Json', 'Txt', 'Html')) {
        if ($reports.ContainsKey($formatName) -and (ConvertTo-BooleanSetting -Value $reports[$formatName] -Name "Reports.$formatName")) {
            $enabledFormats += $formatName
        }
    }

    if ($ReportFormatOverride) {
        $enabledFormats = @($ReportFormatOverride | Select-Object -Unique)
    }
    else {
        $enabledFormats = @($enabledFormats)
    }

    if ($enabledFormats.Count -eq 0) {
        throw 'At least one report format must be enabled.'
    }

    $effectiveServerCsvPath = $ServerCsvPathOverride
    if (Test-Blank $effectiveServerCsvPath) {
        $effectiveServerCsvPath = [string](Get-HashtableValue -Table $config -Name 'ServerCsvPath')
    }

    $effectiveOutputPath = $OutputPathOverride
    if (Test-Blank $effectiveOutputPath) {
        $effectiveOutputPath = [string](Get-HashtableValue -Table $config -Name 'OutputPath')
    }

    $effective = @{
        ConfigPath        = $resolvedConfigPath
        Domain            = [string](Get-HashtableValue -Table $config -Name 'Domain')
        Username          = [string](Get-HashtableValue -Table $config -Name 'Username')
        ServerCsvPath     = [string]$effectiveServerCsvPath
        OutputPath        = [string]$effectiveOutputPath
        UseFqdn           = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $config -Name 'UseFqdn') -Name 'UseFqdn'
        FqdnSuffix        = [string](Get-HashtableValue -Table $config -Name 'FqdnSuffix' -AllowBlank)
        Reports           = $enabledFormats
        LoggingEnabled    = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $logging -Name 'Enabled') -Name 'Logging.Enabled'
        LogPath           = [string](Get-HashtableValue -Table $logging -Name 'LogPath')
        Query             = @{
            IncludeHotFix                  = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $query -Name 'IncludeHotFix') -Name 'Query.IncludeHotFix'
            IncludeWindowsUpdateHistory    = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $query -Name 'IncludeWindowsUpdateHistory') -Name 'Query.IncludeWindowsUpdateHistory'
            IncludeDefenderUpdates         = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $query -Name 'IncludeDefenderUpdates') -Name 'Query.IncludeDefenderUpdates'
            IncludeDotNetUpdates           = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $query -Name 'IncludeDotNetUpdates') -Name 'Query.IncludeDotNetUpdates'
            IncludeSecurityUpdates         = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $query -Name 'IncludeSecurityUpdates') -Name 'Query.IncludeSecurityUpdates'
            IncludeCumulativeUpdates       = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $query -Name 'IncludeCumulativeUpdates') -Name 'Query.IncludeCumulativeUpdates'
            IncludeGeneralWindowsUpdates   = if ($query.ContainsKey('IncludeGeneralWindowsUpdates')) { ConvertTo-BooleanSetting -Value $query['IncludeGeneralWindowsUpdates'] -Name 'Query.IncludeGeneralWindowsUpdates' } else { $true }
            IncludeServicingStackUpdates   = if ($query.ContainsKey('IncludeServicingStackUpdates')) { ConvertTo-BooleanSetting -Value $query['IncludeServicingStackUpdates'] -Name 'Query.IncludeServicingStackUpdates' } else { $true }
            HistoryMonthsBack              = if ($query.ContainsKey('HistoryMonthsBack')) { [int]$query['HistoryMonthsBack'] } else { 0 }
            CategoryFilters                = if ($query.ContainsKey('CategoryFilters')) { @($query['CategoryFilters']) } else { @() }
            ExclusionList                  = if ($query.ContainsKey('ExclusionList')) { @($query['ExclusionList']) } else { @() }
        }
        Connection        = @{
            TimeoutSeconds      = [int](Get-HashtableValue -Table $connection -Name 'TimeoutSeconds')
            TestConnectionFirst = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $connection -Name 'TestConnectionFirst') -Name 'Connection.TestConnectionFirst'
            DryRunEnabled       = ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $connection -Name 'DryRunEnabled') -Name 'Connection.DryRunEnabled'
            UseWinRM            = if ($connection.ContainsKey('UseWinRM')) { ConvertTo-BooleanSetting -Value $connection['UseWinRM'] -Name 'Connection.UseWinRM' } else { $true }
        }
        VerboseLogging    = ($VerboseLogging.IsPresent)
        DryRunEnabled     = ($DryRun.IsPresent -or $ConnectivityOnly.IsPresent -or (ConvertTo-BooleanSetting -Value (Get-HashtableValue -Table $connection -Name 'DryRunEnabled') -Name 'Connection.DryRunEnabled'))
        ConnectivityOnly  = ($ConnectivityOnly.IsPresent)
    }

    if ($NoWinRM.IsPresent) {
        $effective.Connection.UseWinRM = $false
    }

    if ($PSBoundParameters.ContainsKey('MonthsBackOverride')) {
        $effective.Query.HistoryMonthsBack = [int]$MonthsBackOverride
    }

    $effective.ServerCsvPath = Resolve-AbsolutePath -Path $effective.ServerCsvPath
    $effective.OutputPath = Ensure-Directory -Path $effective.OutputPath
    if ($effective.LoggingEnabled) {
        $effective.LogPath = Ensure-Directory -Path $effective.LogPath
    }

    return $effective
}

<#
.SYNOPSIS
Prompts for a runtime credential when one was not supplied.

.DESCRIPTION
Builds a prepopulated DOMAIN\Username value from configuration and uses
Get-Credential to securely collect the password at runtime.

.PARAMETER Domain
Default domain to prepopulate.

.PARAMETER Username
Default username to prepopulate.

.PARAMETER Credential
Optional credential already provided by the caller.

.OUTPUTS
System.Management.Automation.PSCredential

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-AuditCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [System.Management.Automation.PSCredential]$Credential
    )

    if ($null -ne $Credential) {
        return $Credential
    }

    $defaultUser = '{0}\{1}' -f $Domain, $Username
    Write-Log -Level INFO -Message "Prompting for credentials using default username $defaultUser."
    return (Get-Credential -UserName $defaultUser -Message 'Enter credentials for server update audit queries.')
}

# ------------------------------------------------------------
# CSV parsing and FQDN handling
# These functions load the target server list, validate input,
# apply naming conventions, and remove duplicates and exclusions.
# ------------------------------------------------------------

<#
.SYNOPSIS
Builds the server name that should be used for remote access.

.DESCRIPTION
Applies FQDN settings from configuration when the input name is a short host
name and UseFqdn is enabled.

.PARAMETER ServerName
Name read from the input CSV.

.PARAMETER UseFqdn
Enables automatic FQDN construction.

.PARAMETER FqdnSuffix
Suffix appended when UseFqdn is enabled and the name lacks a domain.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Resolve-ServerFqdn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [bool]$UseFqdn,

        [string]$FqdnSuffix
    )

    $trimmed = $ServerName.Trim()
    if (-not $UseFqdn) {
        return $trimmed
    }

    if ($trimmed -like '*.*' -or [string]::IsNullOrWhiteSpace($FqdnSuffix)) {
        return $trimmed
    }

    return '{0}.{1}' -f $trimmed, $FqdnSuffix.Trim('.')
}

<#
.SYNOPSIS
Imports the server CSV and returns normalized server entries.

.DESCRIPTION
Validates the CSV, removes blank and duplicate rows, honors optional exclusion
lists, and resolves the effective FQDN for each server.

.PARAMETER CsvPath
Path to the CSV file.

.PARAMETER UseFqdn
Enables FQDN construction.

.PARAMETER FqdnSuffix
Suffix appended to short names when UseFqdn is enabled.

.PARAMETER ExclusionList
Optional list of servers to skip.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-ServerListFromCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [Parameter(Mandatory = $true)]
        [bool]$UseFqdn,

        [string]$FqdnSuffix,

        [string[]]$ExclusionList
    )

    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "Server CSV file was not found: $CsvPath"
    }

    $rows = @(Import-Csv -LiteralPath $CsvPath)
    if ($rows.Count -eq 0) {
        throw "Server CSV does not contain any rows: $CsvPath"
    }

    if (-not ($rows[0].PSObject.Properties.Name -contains 'ServerName')) {
        throw 'Server CSV must contain a ServerName column.'
    }

    $exclusionLookup = @{}
    foreach ($excluded in @($ExclusionList)) {
        if (-not (Test-Blank $excluded)) {
            $exclusionLookup[$excluded.Trim().ToUpperInvariant()] = $true
        }
    }

    $seen = @{}
    $servers = @()

    foreach ($row in $rows) {
        $name = [string]$row.ServerName
        if (Test-Blank $name) {
            continue
        }

        $shortName = $name.Trim()
        $resolvedName = Resolve-ServerFqdn -ServerName $shortName -UseFqdn $UseFqdn -FqdnSuffix $FqdnSuffix
        $dedupeKey = $resolvedName.ToUpperInvariant()

        if ($exclusionLookup.ContainsKey($shortName.ToUpperInvariant()) -or $exclusionLookup.ContainsKey($dedupeKey)) {
            continue
        }

        if ($seen.ContainsKey($dedupeKey)) {
            continue
        }

        $seen[$dedupeKey] = $true
        $servers += [pscustomobject]@{
            ServerName = $shortName
            ResolvedFqdn = $resolvedName
        }
    }

    return @($servers)
}

# ------------------------------------------------------------
# Connectivity testing
# These functions validate DNS, ICMP, WinRM, PowerShell remoting,
# WMI/CIM access, and credential usability before expensive
# update queries are attempted.
# ------------------------------------------------------------

<#
.SYNOPSIS
Creates a remoting session option object.

.DESCRIPTION
Builds a reusable PSSessionOption using configuration timeouts. Timeout values
are converted to milliseconds because that is how remoting expects them.

.PARAMETER TimeoutSeconds
Timeout value from configuration.

.OUTPUTS
System.Management.Automation.Remoting.PSSessionOption

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function New-RemotingSessionOption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $milliseconds = $TimeoutSeconds * 1000
    return (New-PSSessionOption -OpenTimeout $milliseconds -OperationTimeout $milliseconds)
}

<#
.SYNOPSIS
Creates a CIM session using alternate credentials.

.DESCRIPTION
Windows PowerShell 5.1 does not support passing -Credential directly to
Get-CimInstance in the same way many remoting cmdlets do. This helper creates a
 reusable CIM session so CIM-based queries can authenticate cleanly.

.PARAMETER ComputerName
Remote server name or FQDN.

.PARAMETER Credential
Credential used for remote CIM access.

.OUTPUTS
Microsoft.Management.Infrastructure.CimSession

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function New-ServerCimSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    return (New-CimSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop)
}

<#
.SYNOPSIS
Tests remote connectivity and access for a server.

.DESCRIPTION
Performs layered validation for DNS, ICMP, WinRM, PowerShell remoting, CIM/WMI,
and credential usage. This function is used both by dry-run mode and by the
main audit workflow when connection testing is enabled.

.PARAMETER ServerEntry
Server object returned by Get-ServerListFromCsv.

.PARAMETER Credential
Credential used for remote access tests.

.PARAMETER TimeoutSeconds
Timeout value used for remoting-related calls.

.OUTPUTS
System.Management.Automation.PSCustomObject

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Test-ServerConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$ServerEntry,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [bool]$UseWinRM
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $sessionOption = New-RemotingSessionOption -TimeoutSeconds $TimeoutSeconds
    $fqdn = [string]$ServerEntry.ResolvedFqdn

    $result = [ordered]@{
        ServerName                    = [string]$ServerEntry.ServerName
        FQDN                          = $fqdn
        DNSResolutionStatus           = 'NotTested'
        PingStatus                    = 'NotTested'
        WinRMStatus                   = 'NotTested'
        PowerShellRemotingStatus      = 'NotTested'
        WmiCimStatus                  = 'NotTested'
        CredentialAuthenticationStatus = 'NotTested'
        OverallConnectivityStatus     = 'Failed'
        FailureReason                 = $null
        ResponseTimeMs                = $null
    }

    try {
        try {
            [System.Net.Dns]::GetHostEntry($fqdn) | Out-Null
            $result.DNSResolutionStatus = 'Success'
        }
        catch {
            $result.DNSResolutionStatus = 'Failed'
            throw "DNS resolution failed for $fqdn. $($_.Exception.Message)"
        }

        try {
            if (Test-Connection -ComputerName $fqdn -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                $result.PingStatus = 'Success'
            }
            else {
                $result.PingStatus = 'Failed'
            }
        }
        catch {
            $result.PingStatus = 'Failed'
        }

        if ($UseWinRM) {
            try {
                Test-WSMan -ComputerName $fqdn -Authentication Default -ErrorAction Stop | Out-Null
                $result.WinRMStatus = 'Success'
            }
            catch {
                $result.WinRMStatus = 'Failed'
                Write-Log -Level DEBUG -Message "WinRM test failed for $fqdn. $($_.Exception.Message)"
            }

            try {
                $remoteComputerName = Invoke-Command -ComputerName $fqdn -Credential $Credential -SessionOption $sessionOption -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
                if (-not (Test-Blank $remoteComputerName)) {
                    $result.PowerShellRemotingStatus = 'Success'
                    $result.CredentialAuthenticationStatus = 'Success'
                }
            }
            catch {
                $result.PowerShellRemotingStatus = 'Failed'
                Write-Log -Level DEBUG -Message "PowerShell remoting test failed for $fqdn. $($_.Exception.Message)"
            }
        }
        else {
            $result.WinRMStatus = 'Skipped'
            $result.PowerShellRemotingStatus = 'Skipped'
        }

        try {
            $cimSession = $null
            try {
                $cimSession = New-ServerCimSession -ComputerName $fqdn -Credential $Credential
                $null = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession -OperationTimeoutSec $TimeoutSeconds -ErrorAction Stop
                $result.WmiCimStatus = 'Success'
                $result.CredentialAuthenticationStatus = 'Success'
            }
            finally {
                if ($null -ne $cimSession) {
                    Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            $result.WmiCimStatus = 'Failed'
            Write-Log -Level DEBUG -Message "CIM/WMI test failed for $fqdn. $($_.Exception.Message)"
        }

        if ($result.DNSResolutionStatus -eq 'Success' -and ($result.PowerShellRemotingStatus -eq 'Success' -or $result.WmiCimStatus -eq 'Success')) {
            $result.OverallConnectivityStatus = 'Success'
        }
        elseif ($result.DNSResolutionStatus -eq 'Success' -and ($result.WinRMStatus -eq 'Success' -or $result.WinRMStatus -eq 'Skipped' -or $result.PingStatus -eq 'Success')) {
            $result.OverallConnectivityStatus = 'Warning'
        }
        else {
            $result.OverallConnectivityStatus = 'Failed'
        }
    }
    catch {
        $result.FailureReason = $_.Exception.Message
    }
    finally {
        $stopwatch.Stop()
        $result.ResponseTimeMs = [int]$stopwatch.ElapsedMilliseconds
        if ((Test-Blank $result.FailureReason) -and $result.OverallConnectivityStatus -eq 'Failed') {
            $result.FailureReason = 'Connectivity validation failed.'
        }
    }

    return ([pscustomobject]$result)
}

# ------------------------------------------------------------
# OS and update collection helpers
# These functions query operating system information and collect
# update signals from multiple sources so the solution can keep
# working even when one source is incomplete.
# ------------------------------------------------------------

<#
.SYNOPSIS
Maps a Windows build number to a supported server release.

.DESCRIPTION
Translates build numbers into the expected Windows Server release names so
reports remain human-readable and support staff can quickly see platform level.

.PARAMETER BuildNumber
OS build number to translate.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-ServerReleaseFromBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildNumber
    )

    switch ($BuildNumber) {
        '14393' { return 'Windows Server 2016' }
        '17763' { return 'Windows Server 2019' }
        '20348' { return 'Windows Server 2022' }
        default {
            if ([int]$BuildNumber -ge 26100) {
                return 'Windows Server 2025'
            }

            return 'Unknown Windows Server Release'
        }
    }
}

<#
.SYNOPSIS
Collects base operating system information from a remote server.

.DESCRIPTION
Uses CIM for cross-version compatibility and PowerShell remoting for the UBR
registry value when available. If UBR cannot be collected, the script continues
and reports the value as unknown rather than failing the full audit.

.PARAMETER ComputerName
Remote server name or FQDN.

.PARAMETER Credential
Credential used for remote queries.

.PARAMETER TimeoutSeconds
Timeout used for remoting calls.

.OUTPUTS
System.Management.Automation.PSCustomObject

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-ServerOsInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [bool]$UseWinRM
    )

    $cimSession = $null
    try {
        $cimSession = New-ServerCimSession -ComputerName $ComputerName -Credential $Credential
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession -OperationTimeoutSec $TimeoutSeconds -ErrorAction Stop
    }
    finally {
        if ($null -ne $cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }
    $ubr = $null

    if ($UseWinRM) {
        $sessionOption = New-RemotingSessionOption -TimeoutSeconds $TimeoutSeconds
        try {
            # UBR is stored in the registry and is the reliable way to show the full
            # post-patch build number used heavily during Windows patch validation.
            $ubr = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock {
                (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction Stop).UBR
            } -ErrorAction Stop
        }
        catch {
            Write-Log -Level DEBUG -Message "UBR lookup failed for $ComputerName. $($_.Exception.Message)"
        }
    }
    else {
        Write-Log -Level DEBUG -Message "Skipping UBR lookup for $ComputerName because WinRM usage is disabled."
    }

    return [pscustomobject]@{
        OSCaption    = [string]$os.Caption
        OSVersion    = [string]$os.Version
        BuildNumber  = [string]$os.BuildNumber
        UBR          = $ubr
        ServerRelease = Get-ServerReleaseFromBuild -BuildNumber ([string]$os.BuildNumber)
        LastBootTime = $os.LastBootUpTime
    }
}

<#
.SYNOPSIS
Creates a normalized update record.

.DESCRIPTION
Returns a standard update object used by all query methods so later
classification, grouping, and reporting logic can treat all sources the same.

.PARAMETER ServerName
Input server name from the CSV.

.PARAMETER Fqdn
Resolved FQDN used for the remote query.

.PARAMETER OsInfo
Operating system information object for the server.

.PARAMETER KB
KB number associated with the update.

.PARAMETER Title
Human-readable title or description.

.PARAMETER RawCategory
Category or description from the source method.

.PARAMETER InstalledOn
Install date for the update.

.PARAMETER InstalledBy
User or source that installed the update, if known.

.PARAMETER SourceMethod
Collection method used to discover the update.

.PARAMETER Notes
Additional notes or fallback details.

.OUTPUTS
System.Management.Automation.PSCustomObject

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function New-UpdateRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [psobject]$OsInfo,

        [string]$KB,

        [string]$Title,

        [string]$RawCategory,

        $InstalledOn,

        [string]$InstalledBy,

        [Parameter(Mandatory = $true)]
        [string]$SourceMethod,

        [string]$Notes
    )

    [pscustomobject]@{
        ServerName             = $ServerName
        ResolvedFqdn           = $Fqdn
        OSCaption              = $OsInfo.OSCaption
        OSVersion              = $OsInfo.OSVersion
        BuildNumber            = $OsInfo.BuildNumber
        UBR                    = $OsInfo.UBR
        ServerRelease          = $OsInfo.ServerRelease
        OnlineStatus           = 'Online'
        QueryStatus            = 'Success'
        LastSuccessfulQueryTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        KBNumber               = $KB
        UpdateTitle            = $Title
        RawCategory            = $RawCategory
        UpdateType             = $null
        InstalledDate          = $InstalledOn
        InstalledBy            = $InstalledBy
        SourceMethod           = $SourceMethod
        Notes                  = $Notes
    }
}

<#
.SYNOPSIS
Classifies a normalized update record.

.DESCRIPTION
Uses the KB number, title, description, and source category to assign a
standardized update type. This keeps reporting stable even when source systems
use inconsistent wording across server releases.

.PARAMETER Record
Update record to classify.

.OUTPUTS
System.Management.Automation.PSCustomObject

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Classify-UpdateRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Record
    )

    $text = '{0} {1} {2}' -f [string]$Record.KBNumber, [string]$Record.UpdateTitle, [string]$Record.RawCategory
    $classification = 'Unknown'

    if ($text -match '(?i)security intelligence|defender|antimalware|signature update|platform update') {
        $classification = 'Security Intelligence Update'
    }
    elseif ($text -match '(?i)\.net framework|\.net|dotnet') {
        $classification = '.NET Update'
    }
    elseif ($text -match '(?i)cumulative update|rollupfix|monthly rollup') {
        $classification = 'Cumulative Update'
    }
    elseif ($text -match '(?i)servicing stack|ssu') {
        $classification = 'Servicing Stack Update'
    }
    elseif ($text -match '(?i)security update') {
        $classification = 'Security Update'
    }
    elseif ($text -match '(?i)hotfix') {
        $classification = 'Hotfix / KB Update'
    }
    elseif ($text -match '(?i)update') {
        $classification = 'General Windows Update'
    }
    else {
        $classification = 'Other Update'
    }

    $Record.UpdateType = $classification
    return $Record
}

<#
.SYNOPSIS
Collects installed hotfixes from a server.

.DESCRIPTION
Uses Get-HotFix first because it is a common enterprise-safe method for
installed KB visibility across Windows Server releases.

.PARAMETER ServerName
Friendly server name from the CSV.

.PARAMETER ComputerName
Resolved name or FQDN used to query the server.

.PARAMETER Credential
Credential used for remote queries.

.PARAMETER OsInfo
Operating system information for the server.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-HotFixUpdateRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [psobject]$OsInfo,

        [Parameter(Mandatory = $true)]
        [bool]$UseWinRM
    )

    $records = @()
    $hotFixes = @()
    $sourceMethod = 'Get-HotFix'

    if ($UseWinRM) {
        $cimSession = $null
        try {
            # Get-HotFix does not reliably support alternate credentials across all
            # environments, so run it through PowerShell remoting when available.
            $hotFixes = @(Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                Get-HotFix -ErrorAction Stop | Select-Object HotFixID, Description, InstalledOn, InstalledBy
            } -ErrorAction Stop)
            $sourceMethod = 'Invoke-Command:Get-HotFix'
        }
        catch {
            Write-Log -Level DEBUG -Message "Remote Get-HotFix collection failed for $ComputerName. Falling back to CIM. $($_.Exception.Message)"
        }
    }
    else {
        Write-Log -Level DEBUG -Message "Skipping WinRM-based Get-HotFix collection for $ComputerName because WinRM usage is disabled."
    }

    if (@($hotFixes).Count -eq 0) {
        $cimSession = $null
        try {
            $cimSession = New-ServerCimSession -ComputerName $ComputerName -Credential $Credential
            $hotFixes = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -CimSession $cimSession -ErrorAction Stop |
                Select-Object @{ Name = 'HotFixID'; Expression = { $_.HotFixID } },
                              @{ Name = 'Description'; Expression = { $_.Description } },
                              @{ Name = 'InstalledOn'; Expression = { $_.InstalledOn } },
                              @{ Name = 'InstalledBy'; Expression = { $null } })
        }
        finally {
            if ($null -ne $cimSession) {
                Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
            }
        }
        $sourceMethod = 'Get-CimInstance:Win32_QuickFixEngineering'
    }

    foreach ($hotFix in @($hotFixes)) {
        $records += (New-UpdateRecord -ServerName $ServerName -Fqdn $ComputerName -OsInfo $OsInfo -KB ([string]$hotFix.HotFixID) -Title ([string]$hotFix.Description) -RawCategory 'HotFix' -InstalledOn $hotFix.InstalledOn -InstalledBy ([string]$hotFix.InstalledBy) -SourceMethod $sourceMethod -Notes $null)
    }

    return @($records)
}

<#
.SYNOPSIS
Collects Windows Update history entries through remoting.

.DESCRIPTION
Uses the Microsoft.Update.Session COM API inside a remote PowerShell session.
This is one of the most useful ways to collect update titles and categories,
but it requires PowerShell remoting and will be skipped gracefully if remoting
is unavailable.

.PARAMETER ServerName
Friendly server name from the CSV.

.PARAMETER ComputerName
Resolved name or FQDN used to query the server.

.PARAMETER Credential
Credential used for remote queries.

.PARAMETER OsInfo
Operating system information for the server.

.PARAMETER TimeoutSeconds
Timeout used for remoting calls.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-WindowsUpdateHistoryRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [psobject]$OsInfo,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [bool]$UseWinRM
    )

    if (-not $UseWinRM) {
        Write-Log -Level DEBUG -Message "Skipping Windows Update history collection for $ComputerName because WinRM usage is disabled."
        return @()
    }

    $sessionOption = New-RemotingSessionOption -TimeoutSeconds $TimeoutSeconds
    $history = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -le 0) {
            return @()
        }

        $items = $searcher.QueryHistory(0, $count)
        foreach ($item in $items) {
            $kbValue = $null
            if ($item.Title -match '(?i)KB\d+') {
                $kbValue = $matches[0].ToUpperInvariant()
            }

            [pscustomobject]@{
                KB          = $kbValue
                Title       = [string]$item.Title
                Category    = [string]$item.Description
                InstalledOn = $item.Date
                InstalledBy = $null
                Notes       = 'ResultCode={0}; Operation={1}' -f $item.ResultCode, $item.Operation
            }
        }
    } -ErrorAction Stop

    $records = @()
    foreach ($item in @($history)) {
        $records += (New-UpdateRecord -ServerName $ServerName -Fqdn $ComputerName -OsInfo $OsInfo -KB ([string]$item.KB) -Title ([string]$item.Title) -RawCategory ([string]$item.Category) -InstalledOn $item.InstalledOn -InstalledBy ([string]$item.InstalledBy) -SourceMethod 'WindowsUpdateHistoryApi' -Notes ([string]$item.Notes))
    }

    return $records
}

<#
.SYNOPSIS
Collects update history from Win32_ReliabilityRecords.

.DESCRIPTION
Uses CIM/WMI reliability records as a non-WinRM historical source for installed
updates. This is especially useful when operators need a broader update history
window and PowerShell remoting is unavailable or restricted.

.PARAMETER ServerName
Friendly server name from the CSV.

.PARAMETER ComputerName
Resolved name or FQDN used to query the server.

.PARAMETER Credential
Credential used for remote queries.

.PARAMETER OsInfo
Operating system information for the server.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-ReliabilityUpdateRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [psobject]$OsInfo
    )

    $cimSession = $null
    try {
        $cimSession = New-ServerCimSession -ComputerName $ComputerName -Credential $Credential
        $items = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -Namespace root\cimv2 -CimSession $cimSession -ErrorAction Stop |
            Where-Object {
                ($_.SourceName -eq 'Microsoft-Windows-WindowsUpdateClient') -or
                ($_.ProductName -match '(?i)kb\d+|update|defender|security intelligence|\.net|cumulative|servicing stack')
            })
    }
    finally {
        if ($null -ne $cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }

    $records = @()
    foreach ($item in @($items)) {
        $title = [string]$item.ProductName
        if (Test-Blank $title) {
            $title = [string]$item.Message
        }

        $kbValue = $null
        $searchText = '{0} {1}' -f [string]$item.ProductName, [string]$item.Message
        if ($searchText -match '(?i)KB\d+') {
            $kbValue = $matches[0].ToUpperInvariant()
        }

        $installedDate = $null
        if ($null -ne $item.TimeGenerated) {
            try {
                $installedDate = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$item.TimeGenerated)
            }
            catch {
                $installedDate = $item.TimeGenerated
            }
        }

        $records += (New-UpdateRecord -ServerName $ServerName -Fqdn $ComputerName -OsInfo $OsInfo -KB $kbValue -Title $title -RawCategory ([string]$item.SourceName) -InstalledOn $installedDate -InstalledBy ([string]$item.User) -SourceMethod 'Win32_ReliabilityRecords' -Notes ([string]$item.Message))
    }

    return @($records)
}

<#
.SYNOPSIS
Collects Microsoft Defender update information when available.

.DESCRIPTION
Uses Get-MpComputerStatus inside a remote PowerShell session. Defender is not
available on every server role or build, so this function treats missing cmdlets
as a supported compatibility condition rather than a hard failure.

.PARAMETER ServerName
Friendly server name from the CSV.

.PARAMETER ComputerName
Resolved name or FQDN used to query the server.

.PARAMETER Credential
Credential used for remote queries.

.PARAMETER OsInfo
Operating system information for the server.

.PARAMETER TimeoutSeconds
Timeout used for remoting calls.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-DefenderUpdateRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [psobject]$OsInfo,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [bool]$UseWinRM
    )

    if (-not $UseWinRM) {
        Write-Log -Level DEBUG -Message "Skipping Defender collection for $ComputerName because WinRM usage is disabled."
        return @()
    }

    $sessionOption = New-RemotingSessionOption -TimeoutSeconds $TimeoutSeconds
    $status = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock {
        if (-not (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{
                Available = $false
            }
        }

        $mp = Get-MpComputerStatus
        return [pscustomobject]@{
            Available                         = $true
            AntivirusSignatureVersion         = $mp.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated     = $mp.AntivirusSignatureLastUpdated
            EngineVersion                     = $mp.AMEngineVersion
            ProductVersion                    = $mp.AMProductVersion
        }
    } -ErrorAction Stop

    if (-not $status.Available) {
        return @()
    }

    return @(
        (New-UpdateRecord -ServerName $ServerName -Fqdn $ComputerName -OsInfo $OsInfo -KB $null -Title ('Microsoft Defender Security Intelligence {0}' -f [string]$status.AntivirusSignatureVersion) -RawCategory 'Defender' -InstalledOn $status.AntivirusSignatureLastUpdated -InstalledBy 'Microsoft Defender' -SourceMethod 'Get-MpComputerStatus' -Notes ('EngineVersion={0}; ProductVersion={1}' -f [string]$status.EngineVersion, [string]$status.ProductVersion))
    )
}

<#
.SYNOPSIS
Collects registry-based fallback update signals.

.DESCRIPTION
Uses PowerShell remoting to inspect common registry locations that expose the
server build revision and component-based servicing package names. This is a
fallback source when richer update history data is incomplete.

.PARAMETER ServerName
Friendly server name from the CSV.

.PARAMETER ComputerName
Resolved name or FQDN used to query the server.

.PARAMETER Credential
Credential used for remote queries.

.PARAMETER OsInfo
Operating system information for the server.

.PARAMETER TimeoutSeconds
Timeout used for remoting calls.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-RegistryFallbackUpdateRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [psobject]$OsInfo,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [bool]$UseWinRM
    )

    if (-not $UseWinRM) {
        Write-Log -Level DEBUG -Message "Skipping registry fallback collection for $ComputerName because WinRM usage is disabled."
        return @()
    }

    $sessionOption = New-RemotingSessionOption -TimeoutSeconds $TimeoutSeconds
    $packages = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock {
        $packageRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
        if (-not (Test-Path -LiteralPath $packageRoot)) {
            return @()
        }

        Get-ChildItem -Path $packageRoot -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match 'Package_for_(RollupFix|ServicingStack|DotNetRollup)' } |
            Select-Object -First 20 -ExpandProperty PSChildName
    } -ErrorAction Stop

    $records = @()
    foreach ($packageName in @($packages)) {
        $kb = $null
        if ($packageName -match '(?i)KB\d+') {
            $kb = $matches[0].ToUpperInvariant()
        }

        $records += (New-UpdateRecord -ServerName $ServerName -Fqdn $ComputerName -OsInfo $OsInfo -KB $kb -Title ([string]$packageName) -RawCategory 'RegistryFallback' -InstalledOn $null -InstalledBy $null -SourceMethod 'RegistryFallback' -Notes 'Component Based Servicing package name fallback.')
    }

    return $records
}

<#
.SYNOPSIS
Returns reportable update records for a server.

.DESCRIPTION
Applies category filters and then either returns:
- the latest update per category, or
- all matching updates installed within a historical lookback window

A MonthsBack value of 0 preserves the original latest-by-category behavior.

.PARAMETER Records
Normalized update records from all source methods.

.PARAMETER QuerySettings
Query settings from configuration used to include or exclude categories.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-LatestCategoryUpdates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Records,

        [Parameter(Mandatory = $true)]
        [hashtable]$QuerySettings,

        [Parameter(Mandatory = $true)]
        [int]$MonthsBack
    )

    $classified = @()
    foreach ($record in $Records) {
        $classified += (Classify-UpdateRecord -Record $record)
    }

    $filtered = foreach ($record in $classified) {
        switch ($record.UpdateType) {
            'Cumulative Update' {
                if ($QuerySettings.IncludeCumulativeUpdates) { $record }
            }
            'Security Update' {
                if ($QuerySettings.IncludeSecurityUpdates) { $record }
            }
            '.NET Update' {
                if ($QuerySettings.IncludeDotNetUpdates) { $record }
            }
            'Security Intelligence Update' {
                if ($QuerySettings.IncludeDefenderUpdates) { $record }
            }
            'Servicing Stack Update' {
                if ($QuerySettings.IncludeServicingStackUpdates) { $record }
            }
            'General Windows Update' {
                if ($QuerySettings.IncludeGeneralWindowsUpdates) { $record }
            }
            default {
                $record
            }
        }
    }

    $categoryFilters = @($QuerySettings.CategoryFilters)
    if ($categoryFilters.Count -gt 0) {
        $lookup = @{}
        foreach ($item in $categoryFilters) {
            if (-not (Test-Blank $item)) {
                $lookup[$item.ToString().ToUpperInvariant()] = $true
            }
        }

        $filtered = @($filtered | Where-Object { $lookup.ContainsKey($_.UpdateType.ToUpperInvariant()) })
    }

    if ($MonthsBack -gt 0) {
        $cutoffDate = (Get-Date).Date.AddMonths(-1 * $MonthsBack)
        $historyResults = @(
            $filtered |
                Where-Object {
                    $installedDate = ConvertTo-NullableDateTime -Value $_.InstalledDate
                    $null -ne $installedDate -and $installedDate -ge $cutoffDate
                } |
                Sort-Object -Property @{ Expression = { ConvertTo-NullableDateTime -Value $_.InstalledDate }; Descending = $true }, UpdateType, KBNumber, SourceMethod
        )

        return @($historyResults)
    }

    return @(
        $filtered |
            Sort-Object -Property @{ Expression = { if ($_.InstalledDate) { [datetime]$_.InstalledDate } else { [datetime]'1900-01-01' } }; Descending = $true }, UpdateType |
            Group-Object -Property UpdateType |
            ForEach-Object { $_.Group | Select-Object -First 1 }
    )
}

<#
.SYNOPSIS
Collects audit data for one server.

.DESCRIPTION
Combines connectivity validation, OS detection, update collection, and fallback
logic into a single structured result that can be consumed by the reporting
layer. Partial failures are preserved in notes instead of being silently lost.

.PARAMETER ServerEntry
Server object returned by Get-ServerListFromCsv.

.PARAMETER Credential
Credential used for remote queries.

.PARAMETER Settings
Effective script settings loaded from configuration and overrides.

.OUTPUTS
System.Management.Automation.PSCustomObject

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-ServerAuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$ServerEntry,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [hashtable]$Settings
    )

    $connectivity = Test-ServerConnectivity -ServerEntry $ServerEntry -Credential $Credential -TimeoutSeconds $Settings.Connection.TimeoutSeconds -UseWinRM $Settings.Connection.UseWinRM
    $notes = New-Object System.Collections.Generic.List[string]
    $records = @()
    $status = 'Success'

    if ($Settings.Connection.TestConnectionFirst -and $connectivity.OverallConnectivityStatus -eq 'Failed') {
        return [pscustomobject]@{
            ServerName   = $ServerEntry.ServerName
            ResolvedFqdn = $ServerEntry.ResolvedFqdn
            Connectivity = $connectivity
            OsInfo       = $null
            Records      = @()
            Status       = 'Failed'
            ErrorMessage = $connectivity.FailureReason
        }
    }

    try {
        $osInfo = Get-ServerOsInfo -ComputerName $ServerEntry.ResolvedFqdn -Credential $Credential -TimeoutSeconds $Settings.Connection.TimeoutSeconds -UseWinRM $Settings.Connection.UseWinRM

        if ($Settings.Query.IncludeHotFix) {
            try {
                $records += @(Get-HotFixUpdateRecords -ServerName $ServerEntry.ServerName -ComputerName $ServerEntry.ResolvedFqdn -Credential $Credential -OsInfo $osInfo -UseWinRM $Settings.Connection.UseWinRM)
            }
            catch {
                $notes.Add('Get-HotFix failed: {0}' -f $_.Exception.Message)
            }
        }

        if ($Settings.Query.IncludeWindowsUpdateHistory) {
            try {
                $records += @(Get-WindowsUpdateHistoryRecords -ServerName $ServerEntry.ServerName -ComputerName $ServerEntry.ResolvedFqdn -Credential $Credential -OsInfo $osInfo -TimeoutSeconds $Settings.Connection.TimeoutSeconds -UseWinRM $Settings.Connection.UseWinRM)
            }
            catch {
                $notes.Add('Windows Update history failed: {0}' -f $_.Exception.Message)
            }
        }

        if ($Settings.Query.HistoryMonthsBack -gt 0) {
            try {
                # Reliability records provide a broader historical view than the
                # currently-installed hotfix list and do not require WinRM.
                $records += @(Get-ReliabilityUpdateRecords -ServerName $ServerEntry.ServerName -ComputerName $ServerEntry.ResolvedFqdn -Credential $Credential -OsInfo $osInfo)
            }
            catch {
                $notes.Add('Reliability update history failed: {0}' -f $_.Exception.Message)
            }
        }

        if ($Settings.Query.IncludeDefenderUpdates) {
            try {
                $records += @(Get-DefenderUpdateRecords -ServerName $ServerEntry.ServerName -ComputerName $ServerEntry.ResolvedFqdn -Credential $Credential -OsInfo $osInfo -TimeoutSeconds $Settings.Connection.TimeoutSeconds -UseWinRM $Settings.Connection.UseWinRM)
            }
            catch {
                $notes.Add('Defender query failed: {0}' -f $_.Exception.Message)
            }
        }

        if ($records.Count -eq 0) {
            try {
                # The registry fallback is intentionally last because it is less
                # descriptive than true update history, but still useful when the
                # richer APIs are unavailable after Patch Tuesday chaos.
                $records += @(Get-RegistryFallbackUpdateRecords -ServerName $ServerEntry.ServerName -ComputerName $ServerEntry.ResolvedFqdn -Credential $Credential -OsInfo $osInfo -TimeoutSeconds $Settings.Connection.TimeoutSeconds -UseWinRM $Settings.Connection.UseWinRM)
            }
            catch {
                $notes.Add('Registry fallback failed: {0}' -f $_.Exception.Message)
            }
        }

        if ($records.Count -eq 0) {
            $status = 'Warning'
            $notes.Add('No update records were returned from any enabled source.')
        }

        $latest = @(Get-LatestCategoryUpdates -Records $records -QuerySettings $Settings.Query -MonthsBack $Settings.Query.HistoryMonthsBack)

        if ($latest.Count -eq 0 -and $status -eq 'Success') {
            $status = 'Warning'
        }

        return [pscustomobject]@{
            ServerName   = $ServerEntry.ServerName
            ResolvedFqdn = $ServerEntry.ResolvedFqdn
            Connectivity = $connectivity
            OsInfo       = $osInfo
            Records      = $latest
            Status       = $status
            ErrorMessage = ($notes -join ' | ')
        }
    }
    catch {
        return [pscustomobject]@{
            ServerName   = $ServerEntry.ServerName
            ResolvedFqdn = $ServerEntry.ResolvedFqdn
            Connectivity = $connectivity
            OsInfo       = $null
            Records      = @()
            Status       = 'Failed'
            ErrorMessage = $_.Exception.Message
        }
    }
}

# ------------------------------------------------------------
# Summary and reporting helpers
# These functions convert raw execution output into structured
# summary rows that the reusable reporting module can export.
# ------------------------------------------------------------

<#
.SYNOPSIS
Builds the summary object for the audit run.

.DESCRIPTION
Aggregates totals used by console output and report metadata. The summary is a
simple object so the reporting module can render it in any format.

.PARAMETER ServerResults
Server-level audit result objects.

.PARAMETER EffectiveSettings
Effective runtime settings object.

.PARAMETER Credential
Credential used for the run.

.OUTPUTS
System.Object[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function New-AuditSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ServerResults,

        [Parameter(Mandatory = $true)]
        [hashtable]$EffectiveSettings,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $ServerResults = @($ServerResults)
    $total = $ServerResults.Count
    $success = @($ServerResults | Where-Object { $_.Status -eq 'Success' }).Count
    $warning = @($ServerResults | Where-Object { $_.Status -eq 'Warning' }).Count
    $failed = @($ServerResults | Where-Object { $_.Status -eq 'Failed' }).Count

    return @(
        [pscustomobject]@{
            RunDateTime          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            UserName             = $Credential.UserName
            TotalServers         = $total
            SuccessfulServers    = $success
            WarningServers       = $warning
            FailedServers        = $failed
            DryRunMode           = $EffectiveSettings.DryRunEnabled
            ConnectivityOnlyMode = $EffectiveSettings.ConnectivityOnly
            WinRMEnabled         = $EffectiveSettings.Connection.UseWinRM
            HistoryMonthsBack    = $EffectiveSettings.Query.HistoryMonthsBack
            ReportMode           = if ($EffectiveSettings.Query.HistoryMonthsBack -gt 0) { 'HistoricalWindow' } else { 'LatestByCategory' }
            OutputPath           = $EffectiveSettings.OutputPath
        }
    )
}

<#
.SYNOPSIS
Builds report metadata for the reporting module.

.DESCRIPTION
Packages common run information into a hashtable that can be embedded into TXT
and HTML reports.

.PARAMETER EffectiveSettings
Effective runtime settings.

.PARAMETER Credential
Credential used for the run.

.PARAMETER ReportName
Logical report name.

.OUTPUTS
System.Collections.Hashtable

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function New-ReportMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$EffectiveSettings,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$ReportName
    )

    return @{
        ReportName     = $ReportName
        RunDate        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        ScriptName     = $MyInvocation.ScriptName
        ConfigPath     = $EffectiveSettings.ConfigPath
        OutputPath     = $EffectiveSettings.OutputPath
        User           = $Credential.UserName
        Formats        = ($EffectiveSettings.Reports -join ', ')
        DryRunEnabled  = [string]$EffectiveSettings.DryRunEnabled
        UseWinRM       = [string]$EffectiveSettings.Connection.UseWinRM
        HistoryMonthsBack = [string]$EffectiveSettings.Query.HistoryMonthsBack
        ReportMode     = if ($EffectiveSettings.Query.HistoryMonthsBack -gt 0) { 'HistoricalWindow' } else { 'LatestByCategory' }
    }
}

# ------------------------------------------------------------
# Main execution workflow
# This is the orchestration layer: load config, prompt for
# credentials, import the reporting module, process servers,
# and export final reports.
# ------------------------------------------------------------

$scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$modulePath = Join-Path -Path $scriptRoot -ChildPath 'ReportingTools.psm1'
$runStart = Get-Date

try {
    $settings = Import-AuditConfiguration -ConfigPath $ConfigPath -ServerCsvPathOverride $ServerCsvPath -OutputPathOverride $OutputPath -ReportFormatOverride $ReportFormat -VerboseLogging:$VerboseLogging -DryRun:$DryRun -ConnectivityOnly:$ConnectivityOnly -NoWinRM:$NoWinRM -MonthsBackOverride $MonthsBack
    $script:VerboseLoggingEnabled = ($settings.VerboseLogging -or $VerboseLogging.IsPresent)

    if ($settings.LoggingEnabled) {
        $logFolder = Ensure-Directory -Path $settings.LogPath
        $script:LogFilePath = Join-Path -Path $logFolder -ChildPath ('ServerUpdateAudit_{0}.log' -f $script:RunTimeStamp)
    }

    Write-Log -Level INFO -Message 'Starting server update audit.'
    Write-Log -Level INFO -Message ('Configuration file: {0}' -f $settings.ConfigPath)
    Write-Log -Level INFO -Message ('Server CSV path: {0}' -f $settings.ServerCsvPath)
    Write-Log -Level INFO -Message ('Output path: {0}' -f $settings.OutputPath)
    Write-Log -Level INFO -Message ('WinRM usage enabled: {0}' -f $settings.Connection.UseWinRM)
    Write-Log -Level INFO -Message ('History months back: {0}' -f $settings.Query.HistoryMonthsBack)

    if (-not (Test-Path -LiteralPath $modulePath)) {
        throw "Reporting module was not found: $modulePath"
    }

    Import-Module -Name $modulePath -Force -ErrorAction Stop
    Write-Log -Level INFO -Message ('Imported reporting module: {0}' -f $modulePath)

    $credentialToUse = Get-AuditCredential -Domain $settings.Domain -Username $settings.Username -Credential $Credential
    $serverEntries = @(Get-ServerListFromCsv -CsvPath $settings.ServerCsvPath -UseFqdn $settings.UseFqdn -FqdnSuffix $settings.FqdnSuffix -ExclusionList $settings.Query.ExclusionList)
    Write-Log -Level INFO -Message ('Loaded {0} server entries for processing.' -f $serverEntries.Count)

    $serverResults = @()
    $connectivityRows = @()
    $updateRows = @()
    $failedRows = @()

    for ($index = 0; $index -lt $serverEntries.Count; $index++) {
        $serverEntry = $serverEntries[$index]
        $percent = [int](($index / [Math]::Max($serverEntries.Count, 1)) * 100)
        Write-Progress -Activity 'Server Update Audit' -Status ("Processing {0}" -f $serverEntry.ResolvedFqdn) -PercentComplete $percent
        Write-Log -Level INFO -Message ('Processing server {0} ({1}/{2}).' -f $serverEntry.ResolvedFqdn, ($index + 1), $serverEntries.Count)

        if ($settings.DryRunEnabled -or $settings.ConnectivityOnly) {
            $connectivity = Test-ServerConnectivity -ServerEntry $serverEntry -Credential $credentialToUse -TimeoutSeconds $settings.Connection.TimeoutSeconds -UseWinRM $settings.Connection.UseWinRM
            $connectivityRows += $connectivity
            $serverResults += [pscustomobject]@{
                ServerName   = $serverEntry.ServerName
                ResolvedFqdn = $serverEntry.ResolvedFqdn
                Connectivity = $connectivity
                Status       = $connectivity.OverallConnectivityStatus
                ErrorMessage = $connectivity.FailureReason
            }

            if ($connectivity.OverallConnectivityStatus -eq 'Failed') {
                $failedRows += [pscustomobject]@{
                    ServerName     = $serverEntry.ServerName
                    ResolvedFqdn   = $serverEntry.ResolvedFqdn
                    Status         = $connectivity.OverallConnectivityStatus
                    FailureReason  = $connectivity.FailureReason
                    ResponseTimeMs = $connectivity.ResponseTimeMs
                }
            }

            continue
        }

        $serverAudit = Get-ServerAuditResult -ServerEntry $serverEntry -Credential $credentialToUse -Settings $settings
        $serverResults += $serverAudit
        $connectivityRows += $serverAudit.Connectivity

        foreach ($record in @($serverAudit.Records)) {
            $updateRows += $record
        }

        if ($serverAudit.Status -eq 'Failed' -or $serverAudit.Status -eq 'Warning') {
            $failedRows += [pscustomobject]@{
                ServerName     = $serverAudit.ServerName
                ResolvedFqdn   = $serverAudit.ResolvedFqdn
                Status         = $serverAudit.Status
                FailureReason  = $serverAudit.ErrorMessage
                Connectivity   = $serverAudit.Connectivity.OverallConnectivityStatus
            }
        }
    }

    Write-Progress -Activity 'Server Update Audit' -Completed

    $summary = New-AuditSummary -ServerResults $serverResults -EffectiveSettings $settings -Credential $credentialToUse

    if ($settings.DryRunEnabled -or $settings.ConnectivityOnly) {
        $metadata = New-ReportMetadata -EffectiveSettings $settings -Credential $credentialToUse -ReportName 'Server Update Audit Dry Run'

        $bundle = Export-ReportBundle -Data $connectivityRows -Title 'Server Update Audit Dry Run' -OutputPath $settings.OutputPath -BaseFileName 'ServerUpdateAudit_DryRun' -Formats $settings.Reports -GroupBy 'OverallConnectivityStatus' -Summary $summary -FailedItems $failedRows -Metadata $metadata -TimeStamp $script:RunTimeStamp

        if (@($failedRows).Count -gt 0) {
            Export-ReportCsv -Data $failedRows -OutputPath $settings.OutputPath -BaseFileName 'ServerUpdateAudit_FailedServers' -TimeStamp $script:RunTimeStamp | Out-Null
        }

        Export-ReportCsv -Data $summary -OutputPath $settings.OutputPath -BaseFileName 'ServerUpdateAudit_Summary' -TimeStamp $script:RunTimeStamp | Out-Null

        Write-Log -Level INFO -Message 'Dry-run connectivity validation completed.'
        foreach ($key in ($bundle.Keys | Sort-Object)) {
            Write-Log -Level INFO -Message ('Generated {0} report: {1}' -f $key, $bundle[$key])
        }
    }
    else {
        $metadata = New-ReportMetadata -EffectiveSettings $settings -Credential $credentialToUse -ReportName 'Server Update Audit Report'

        $bundle = Export-ReportBundle -Data $updateRows -Title 'Server Update Audit Report' -OutputPath $settings.OutputPath -BaseFileName 'ServerUpdateAudit' -Formats $settings.Reports -GroupBy 'ServerName' -Summary $summary -FailedItems $failedRows -Metadata $metadata -TimeStamp $script:RunTimeStamp

        if (@($failedRows).Count -gt 0) {
            Export-ReportCsv -Data $failedRows -OutputPath $settings.OutputPath -BaseFileName 'ServerUpdateAudit_FailedServers' -TimeStamp $script:RunTimeStamp | Out-Null
        }

        Export-ReportCsv -Data $summary -OutputPath $settings.OutputPath -BaseFileName 'ServerUpdateAudit_Summary' -TimeStamp $script:RunTimeStamp | Out-Null

        foreach ($key in ($bundle.Keys | Sort-Object)) {
            Write-Log -Level INFO -Message ('Generated {0} report: {1}' -f $key, $bundle[$key])
        }

        Write-Log -Level INFO -Message ('Collected {0} latest categorized update records.' -f (@($updateRows).Count))
    }

    $runEnd = Get-Date
    $runtime = $runEnd - $runStart
    Write-Host ''
    Write-Host 'Server Update Audit Summary'
    Write-Host '---------------------------'
    Write-Host ('Run started: {0}' -f $runStart.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ('Run completed: {0}' -f $runEnd.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ('Runtime: {0}' -f $runtime.ToString())
    Write-Host ('Servers processed: {0}' -f (@($serverResults).Count))
    Write-Host ('Successful: {0}' -f (@($serverResults | Where-Object { $_.Status -eq 'Success' }).Count))
    Write-Host ('Warnings: {0}' -f (@($serverResults | Where-Object { $_.Status -eq 'Warning' }).Count))
    Write-Host ('Failed: {0}' -f (@($serverResults | Where-Object { $_.Status -eq 'Failed' }).Count))
    Write-Host ('Output path: {0}' -f $settings.OutputPath)

    Write-Log -Level INFO -Message ('Run completed in {0}.' -f $runtime.ToString())
}
catch {
    $errorMessage = Get-ErrorMessageDetail -ErrorRecord $_
    Write-Log -Level ERROR -Message ('Fatal error: {0}' -f $errorMessage)
    throw
}
