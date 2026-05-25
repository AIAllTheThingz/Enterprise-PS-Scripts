[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$ServerCsvPath,
    [string[]]$ServerName,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('CSV','JSON','TXT','HTML')][string[]]$ReportFormat,
    [switch]$VerboseLogging,
    [switch]$ConnectivityOnly,
    [switch]$DryRun,
    [switch]$PreviewRemediation,
    [switch]$Remediate,
    [switch]$ApplyVendorReplacement,
    [switch]$ApplyJndiLookupMitigation,
    [switch]$Localhost,
    [switch]$NoWinRM,
    [switch]$UseDcomWmi,
    [switch]$SkipArchiveInspection,
    [switch]$IncludeNestedArchives,
    [switch]$IncludeHash,
    [int]$TimeoutSeconds,
    [string[]]$SearchPaths,
    [string[]]$ExcludePaths,
    [string]$QuarantinePath,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Script:RunId = [guid]::NewGuid().ToString()
$Script:TranscriptPath = $null
$Script:TempRoot = $null
$Script:Config = $null
$Script:CollectionMode = $null
$Script:ExecutionMode = 'Audit'
$Script:Failures = @()

function Import-Log4jConfiguration {
<#
.SYNOPSIS
Loads and validates the PSD1 configuration file.
.DESCRIPTION
Imports environment-specific settings from Log4jRemediation.config.psd1 and
validates required values, allowed modes, and report formats before any target
processing begins.
.PARAMETER Path
Path to the PSD1 configuration file.
.EXAMPLE
Import-Log4jConfiguration -Path .\Log4jRemediation.config.psd1
.OUTPUTS
System.Collections.Hashtable
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "ConfigPath does not exist: $Path" }
    try { $config = Import-PowerShellDataFile -LiteralPath $Path } catch { throw "Failed to load PSD1 configuration: $($_.Exception.Message)" }
    $required = @(
        'Domain','UserName','OutputPath','LogPath','ReportFormats','IncludeTranscript','TimeoutSeconds','ContinueOnError',
        'AllowManualServerEntry','PromptForAdditionalManualServers','DefaultCollectionMode','AllowWinRM','AllowNoWinRM','AllowLocalhost',
        'LocalhostTargetName','LocalhostBypassCredentialPrompt','LocalhostUseNativePaths',
        'ValidateConnectivityBeforeScan','SearchPaths','ExcludedPaths','SearchFileExtensions','IncludeNestedArchives',
        'MaximumNestedArchiveDepth','MaximumArchiveSizeMB','IncludeFileHash','RemediationEnabled',
        'RequireConfirmationBeforeRemediation','QuarantinePath','CreateRollbackMetadata','AllowVendorReplacement',
        'AllowJndiLookupMitigation','AllowPermanentDeletion','AllowServiceStopStart'
    )
    foreach ($key in $required) { Test-RequiredConfigValue -Config $config -Key $key }
    if (@('WinRM','NoWinRM','Localhost') -notcontains $config.DefaultCollectionMode) { throw "DefaultCollectionMode must be WinRM, NoWinRM, or Localhost." }
    foreach ($format in @($config.ReportFormats)) {
        if (@('CSV','JSON','TXT','HTML') -notcontains $format) { throw "Unsupported ReportFormats value: $format" }
    }
    if ($config.DefaultCollectionMode -eq 'WinRM' -and -not $config.AllowWinRM) { throw "DefaultCollectionMode is WinRM but AllowWinRM is false." }
    if ($config.DefaultCollectionMode -eq 'NoWinRM' -and -not $config.AllowNoWinRM) { throw "DefaultCollectionMode is NoWinRM but AllowNoWinRM is false." }
    if ($config.DefaultCollectionMode -eq 'Localhost' -and -not $config.AllowLocalhost) { throw "DefaultCollectionMode is Localhost but AllowLocalhost is false." }
    return $config
}

function Test-RequiredConfigValue {
<#
.SYNOPSIS
Validates that a required configuration key exists and has a usable value.
.DESCRIPTION
Checks required PSD1 keys without requiring ServerCsvPath, because manual server
entry and -ServerName are supported. Boolean false is accepted as a valid value.
.PARAMETER Config
Configuration hashtable.
.PARAMETER Key
Required key name.
.EXAMPLE
Test-RequiredConfigValue -Config $Config -Key OutputPath
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Config,[Parameter(Mandatory = $true)][string]$Key)
    if (-not $Config.ContainsKey($Key)) { throw "Required configuration key is missing: $Key" }
    $value = $Config[$Key]
    if ($null -eq $value) { throw "Required configuration key is null: $Key" }
    if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) { throw "Required configuration key is blank: $Key" }
    if ($value -is [array] -and $value.Count -eq 0) { throw "Required configuration key has no values: $Key" }
}

function Test-ExecutionMode {
<#
.SYNOPSIS
Validates mode combinations and remediation safety controls.
.DESCRIPTION
Enforces mutually exclusive modes, action dependencies, collection-mode
authorization, remediation gates, rollback requirements, and manifest checks
before scanning or modification is attempted.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Test-ExecutionMode -Config $Config
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    if ($ServerName -and $ServerCsvPath) { throw "Use either -ServerName or -ServerCsvPath, not both." }
    if ($Localhost -and $ServerName) { throw "Use either -Localhost or -ServerName, not both." }
    if ($Localhost -and $ServerCsvPath) { throw "Use either -Localhost or -ServerCsvPath, not both." }
    if ($Localhost -and $NoWinRM) { throw "Use either -Localhost or -NoWinRM, not both." }
    if ($ConnectivityOnly -and $Remediate) { throw "-ConnectivityOnly cannot be used with -Remediate." }
    if ($ConnectivityOnly -and $PreviewRemediation) { throw "-ConnectivityOnly cannot be used with -PreviewRemediation." }
    if ($DryRun -and $Remediate) { throw "-DryRun cannot be used with -Remediate." }
    if ($PreviewRemediation -and $Remediate) { throw "-PreviewRemediation cannot be used with -Remediate." }
    if ($ApplyVendorReplacement -and -not $Remediate) { throw "-ApplyVendorReplacement requires -Remediate." }
    if ($ApplyJndiLookupMitigation -and -not $Remediate) { throw "-ApplyJndiLookupMitigation requires -Remediate." }
    if ($Force -and -not $Remediate) { throw "-Force may be used only with -Remediate." }
    $mode = $Config.DefaultCollectionMode
    if ($Localhost) { $mode = 'Localhost' }
    if ($NoWinRM) { $mode = 'NoWinRM' }
    if ($mode -eq 'WinRM' -and -not $Config.AllowWinRM) { throw "WinRM mode is not allowed by configuration." }
    if ($mode -eq 'NoWinRM' -and -not $Config.AllowNoWinRM) { throw "NoWinRM mode is not allowed by configuration." }
    if ($mode -eq 'Localhost' -and -not $Config.AllowLocalhost) { throw "Localhost mode is not allowed by configuration." }
    if ($mode -eq 'Localhost' -and ($ServerName -or $ServerCsvPath)) { throw "Localhost mode cannot be combined with -ServerName or -ServerCsvPath." }
    if ($UseDcomWmi -and $mode -ne 'NoWinRM') { throw "-UseDcomWmi may be used only in NoWinRM mode." }
    if ($Remediate) {
        if (-not $Config.RemediationEnabled) { throw "Remediation was requested, but RemediationEnabled is false in configuration." }
        if (-not $ApplyVendorReplacement -and -not $ApplyJndiLookupMitigation) { throw "-Remediate requires -ApplyVendorReplacement or -ApplyJndiLookupMitigation." }
        if (-not $Config.CreateRollbackMetadata) { throw "Remediation requires CreateRollbackMetadata to be true." }
        if ($ApplyJndiLookupMitigation -and -not $Config.AllowJndiLookupMitigation) { throw "JndiLookup mitigation is disabled by configuration." }
        if ($ApplyVendorReplacement -and -not $Config.AllowVendorReplacement) { throw "Vendor replacement is disabled by configuration." }
        if ($ApplyVendorReplacement) {
            if ([string]::IsNullOrWhiteSpace($Config.ApprovedReplacementManifestPath)) { throw "ApprovedReplacementManifestPath is required for vendor replacement." }
            if (-not (Test-Path -LiteralPath $Config.ApprovedReplacementManifestPath)) { throw "ApprovedReplacementManifestPath does not exist: $($Config.ApprovedReplacementManifestPath)" }
        }
        if ($Config.AllowServiceStopStart -and -not [string]::IsNullOrWhiteSpace($Config.ApprovedServiceMappingPath)) {
            if (-not (Test-Path -LiteralPath $Config.ApprovedServiceMappingPath)) { throw "ApprovedServiceMappingPath does not exist: $($Config.ApprovedServiceMappingPath)" }
        }
        if ($mode -eq 'NoWinRM') { throw "Remediation in NoWinRM mode is prohibited by this implementation." }
    }
    if ($ConnectivityOnly) { $Script:ExecutionMode = 'ConnectivityOnly' }
    elseif ($DryRun) { $Script:ExecutionMode = 'DryRun' }
    elseif ($PreviewRemediation) { $Script:ExecutionMode = 'PreviewRemediation' }
    elseif ($Remediate) { $Script:ExecutionMode = 'Remediate' }
    else { $Script:ExecutionMode = 'Audit' }
    $Script:CollectionMode = $mode
    return $mode
}

function Initialize-OutputFolders {
<#
.SYNOPSIS
Creates report, log, temporary, and quarantine folders.
.DESCRIPTION
Initializes runtime folders. Quarantine is created only for remediation-capable
runs so audit, dry-run, preview, connectivity, and WhatIf modes do not stage
backup data unnecessarily.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Initialize-OutputFolders -Config $Config
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    foreach ($path in @($Config.OutputPath,$Config.LogPath)) {
        if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
    }
    $Script:TempRoot = Join-Path $Config.LogPath ("Temp_{0}" -f $Script:RunId)
    New-Item -ItemType Directory -Path $Script:TempRoot -Force | Out-Null
    if ($Remediate -and -not $WhatIfPreference) {
        if (-not (Test-Path -LiteralPath $Config.QuarantinePath)) { New-Item -ItemType Directory -Path $Config.QuarantinePath -Force | Out-Null }
    }
    return $Script:TempRoot
}

function Start-SafeTranscript {
<#
.SYNOPSIS
Starts transcript logging when enabled.
.DESCRIPTION
Starts a transcript for non-secret operational evidence. Credentials are never
written by this script; operators should still avoid typing secrets into the
console while transcript logging is enabled.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Start-SafeTranscript -Config $Config
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    if (-not $Config.IncludeTranscript) { return $null }
    $path = Join-Path $Config.LogPath ("Log4j_Remediation_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try { Start-Transcript -Path $path -Force | Out-Null; $Script:TranscriptPath = $path; return $path } catch { Write-Warning "Unable to start transcript: $($_.Exception.Message)"; return $null }
}

function Stop-SafeTranscript {
<#
.SYNOPSIS
Stops transcript logging safely.
.DESCRIPTION
Stops the current transcript if one was started and suppresses harmless errors
that occur when a transcript is not active.
.EXAMPLE
Stop-SafeTranscript
.OUTPUTS
None
#>
    [CmdletBinding()]
    param()
    if ($Script:TranscriptPath) { try { Stop-Transcript | Out-Null } catch { Write-Warning "Unable to stop transcript: $($_.Exception.Message)" } }
}

function Resolve-ServerInputSource {
<#
.SYNOPSIS
Selects the server input source by required priority.
.DESCRIPTION
Uses -ServerName first, then -ServerCsvPath, then configured ServerCsvPath when
valid, then explicit/configured Localhost mode, then interactive manual input if
allowed. All sources are normalized into standard target objects.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Resolve-ServerInputSource -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    if ($Localhost) {
        $localName = $Config.LocalhostTargetName
        if ([string]::IsNullOrWhiteSpace($localName)) { $localName = 'localhost' }
        $target = New-StandardTargetObject -InputSource 'Localhost' -ServerName $localName -FQDN $env:COMPUTERNAME -Config $Config -Notes 'Provided using -Localhost'
        return [pscustomobject]@{ InputSourceMode = 'Localhost'; CsvPath = $null; Targets = @($target) }
    }
    if ($ServerName -and $ServerName.Count -gt 0) {
        $targets = @()
        foreach ($name in $ServerName) {
            if (-not [string]::IsNullOrWhiteSpace($name)) { $targets += New-StandardTargetObject -InputSource 'CommandLineManual' -ServerName $name.Trim() -Config $Config -Notes 'Provided using -ServerName' }
        }
        if ($targets.Count -eq 0) { throw "-ServerName did not contain any usable server names." }
        return [pscustomobject]@{ InputSourceMode = 'CommandLineManual'; CsvPath = $null; Targets = $targets }
    }
    if (-not [string]::IsNullOrWhiteSpace($ServerCsvPath)) {
        return [pscustomobject]@{ InputSourceMode = 'CommandLineCsv'; CsvPath = $ServerCsvPath; Targets = (Import-ServerList -Path $ServerCsvPath -InputSource 'CommandLineCsv' -Config $Config) }
    }
    if ($Config.DefaultCollectionMode -ne 'Localhost' -and $Config.ContainsKey('ServerCsvPath') -and -not [string]::IsNullOrWhiteSpace($Config.ServerCsvPath) -and (Test-Path -LiteralPath $Config.ServerCsvPath)) {
        return [pscustomobject]@{ InputSourceMode = 'ConfigCsv'; CsvPath = $Config.ServerCsvPath; Targets = (Import-ServerList -Path $Config.ServerCsvPath -InputSource 'ConfigCsv' -Config $Config) }
    }
    if ($Config.DefaultCollectionMode -eq 'Localhost') {
        $localName = $Config.LocalhostTargetName
        if ([string]::IsNullOrWhiteSpace($localName)) { $localName = 'localhost' }
        $target = New-StandardTargetObject -InputSource 'Localhost' -ServerName $localName -FQDN $env:COMPUTERNAME -Config $Config -Notes 'Provided by DefaultCollectionMode Localhost'
        return [pscustomobject]@{ InputSourceMode = 'Localhost'; CsvPath = $null; Targets = @($target) }
    }
    if ($Config.AllowManualServerEntry) {
        return [pscustomobject]@{ InputSourceMode = 'InteractiveManual'; CsvPath = $null; Targets = (Read-ManualServerTargets -Config $Config) }
    }
    throw "No server input source is available and AllowManualServerEntry is false."
}

function Import-ServerList {
<#
.SYNOPSIS
Imports and validates CSV server targets.
.DESCRIPTION
Loads a CSV with required ServerName and optional metadata columns, trims values,
skips blank server rows with reported failures, and creates standard target
objects without allowing MaintenanceApproved to authorize remediation.
.PARAMETER Path
CSV path.
.PARAMETER InputSource
Input source label.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Import-ServerList -Path .\Servers.csv -InputSource CommandLineCsv -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path,[Parameter(Mandatory = $true)][string]$InputSource,[Parameter(Mandatory = $true)][hashtable]$Config)
    if (-not (Test-Path -LiteralPath $Path)) { throw "CSV file does not exist: $Path" }
    try { $rows = Import-Csv -LiteralPath $Path } catch { throw "CSV file could not be loaded: $($_.Exception.Message)" }
    if ($rows.Count -gt 0 -and ($rows[0].PSObject.Properties.Name -notcontains 'ServerName')) { throw "CSV file must contain a ServerName column." }
    $targets = @()
    foreach ($row in @($rows)) {
        $server = ([string]$row.ServerName).Trim()
        if ([string]::IsNullOrWhiteSpace($server)) {
            $Script:Failures += [pscustomobject]@{ Timestamp = (Get-Date).ToString('s'); ServerName = ''; Status = 'SkippedBlankServerName'; FailureReason = "Blank ServerName row in $Path" }
            continue
        }
        $targets += New-StandardTargetObject -InputSource $InputSource -ServerName $server -FQDN (Get-OptionalPropertyValue -InputObject $row -Name 'FQDN') -Config $Config -Notes (Get-OptionalPropertyValue -InputObject $row -Name 'Notes') -TicketNumber (Get-OptionalPropertyValue -InputObject $row -Name 'TicketNumber') -ChangeWindow (Get-OptionalPropertyValue -InputObject $row -Name 'ChangeWindow') -ApplicationOwner (Get-OptionalPropertyValue -InputObject $row -Name 'ApplicationOwner') -MaintenanceApproved (Get-OptionalPropertyValue -InputObject $row -Name 'MaintenanceApproved')
    }
    if ($targets.Count -eq 0) { throw "CSV did not contain any usable ServerName values." }
    return $targets
}

function Get-OptionalPropertyValue {
<#
.SYNOPSIS
Reads an optional object property safely.
.DESCRIPTION
Returns a trimmed string value for an optional CSV or manifest property without
violating strict mode when the property is absent.
.PARAMETER InputObject
Object to inspect.
.PARAMETER Name
Property name.
.EXAMPLE
Get-OptionalPropertyValue -InputObject $Row -Name FQDN
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([object]$InputObject,[string]$Name)
    if ($null -eq $InputObject) { return '' }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return ([string]$InputObject.$Name).Trim() }
    return ''
}

function Read-ManualServerTargets {
<#
.SYNOPSIS
Reads interactive manual server targets.
.DESCRIPTION
Prompts with Read-Host for one or more server names according to
AllowManualServerEntry and PromptForAdditionalManualServers. Manual entries are
not written to disk and do not bypass safety validation.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Read-ManualServerTargets -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    $targets = @()
    do {
        $entry = Read-Host 'Enter a target server name'
        if ([string]::IsNullOrWhiteSpace($entry)) {
            if ($targets.Count -gt 0 -and $Config.PromptForAdditionalManualServers) { break }
            throw "Manual server input cannot be blank."
        }
        $targets += New-StandardTargetObject -InputSource 'InteractiveManual' -ServerName $entry.Trim() -Config $Config -Notes 'Entered manually'
        if (-not $Config.PromptForAdditionalManualServers) { break }
    } while ($true)
    return $targets
}

function New-StandardTargetObject {
<#
.SYNOPSIS
Creates a standardized target object.
.DESCRIPTION
Normalizes CSV, command-line, and interactive input so all later connectivity,
scanning, reporting, remediation, quarantine, and rollback behavior is identical.
.PARAMETER InputSource
Input source label.
.PARAMETER ServerName
Server name.
.PARAMETER FQDN
Optional fully qualified domain name.
.PARAMETER Config
Validated configuration.
.PARAMETER Notes
Target notes.
.PARAMETER TicketNumber
Change or ticket number.
.PARAMETER ChangeWindow
Change window.
.PARAMETER ApplicationOwner
Owner value.
.PARAMETER MaintenanceApproved
Informational approval value from CSV.
.EXAMPLE
New-StandardTargetObject -InputSource CommandLineManual -ServerName SERVER01 -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [string]$InputSource,[string]$ServerName,[string]$FQDN,[hashtable]$Config,[string]$Notes = '',
        [string]$TicketNumber = '',[string]$ChangeWindow = '',[string]$ApplicationOwner = '',[string]$MaintenanceApproved = ''
    )
    $resolvedFqdn = Resolve-TargetFqdn -ServerName $ServerName -FQDN $FQDN -Config $Config
    $lookup = $ServerName
    if ($Config.UseFqdn -and -not [string]::IsNullOrWhiteSpace($resolvedFqdn)) { $lookup = $resolvedFqdn }
    [pscustomobject]@{
        InputSource         = $InputSource
        ServerName          = $ServerName
        FQDN                = $resolvedFqdn
        LookupName          = $lookup
        Notes               = $Notes
        TicketNumber        = $TicketNumber
        ChangeWindow        = $ChangeWindow
        ApplicationOwner    = $ApplicationOwner
        MaintenanceApproved = $MaintenanceApproved
    }
}

function Resolve-TargetFqdn {
<#
.SYNOPSIS
Resolves the FQDN for a target.
.DESCRIPTION
Prefers CSV FQDN when UseFqdn is true and supplied; otherwise constructs an FQDN
from ServerName and FqdnSuffix. Returns the supplied FQDN for reporting even when
UseFqdn is false.
.PARAMETER ServerName
Server name.
.PARAMETER FQDN
Optional FQDN.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Resolve-TargetFqdn -ServerName SERVER01 -Config $Config
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([string]$ServerName,[string]$FQDN,[hashtable]$Config)
    if (-not [string]::IsNullOrWhiteSpace($FQDN)) { return $FQDN.Trim() }
    if ($Config.UseFqdn -and -not [string]::IsNullOrWhiteSpace($Config.FqdnSuffix)) { return ("{0}.{1}" -f $ServerName.Trim(), $Config.FqdnSuffix.Trim()) }
    return ''
}

function Test-TargetConnectivity {
<#
.SYNOPSIS
Tests target connectivity for the selected collection mode.
.DESCRIPTION
Uses Test-WSMan in WinRM mode. In NoWinRM mode it validates administrative share
access and optionally DCOM WMI metadata collection. In Localhost mode it validates
that local native paths are usable and does not require WinRM or admin shares.
Failures are reported and do not imply the server is clean.
.PARAMETER Target
Standard target object.
.PARAMETER CollectionMode
WinRM or NoWinRM.
.PARAMETER Credential
Credential for remote operations.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Test-TargetConnectivity -Target $Target -CollectionMode WinRM -Credential $Credential -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Target,[string]$CollectionMode,[System.Management.Automation.PSCredential]$Credential,[hashtable]$Config)
    $status = 'ConnectivityPassed'
    $reason = ''
    try {
        if ($CollectionMode -eq 'Localhost') {
            if (-not $Config.LocalhostUseNativePaths) { throw "LocalhostUseNativePaths must be true for Localhost mode in this implementation." }
            if (-not (Test-Path -LiteralPath $env:SystemRoot)) { throw "Local system root is not reachable." }
        } elseif ($CollectionMode -eq 'WinRM') {
            Test-WSMan -ComputerName $Target.LookupName -ErrorAction Stop | Out-Null
        } else {
            $unc = "\\$($Target.LookupName)\ADMIN$"
            if (-not (Test-Path -LiteralPath $unc)) { throw "Administrative share unavailable: $unc" }
            if ($UseDcomWmi) { Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Target.LookupName -Credential $Credential -ErrorAction Stop | Out-Null }
        }
    } catch {
        $status = 'ConnectivityFailed'
        $reason = $_.Exception.Message
    }
    [pscustomobject]@{ Status = $status; FailureReason = $reason }
}

function Get-EffectiveSearchPaths {
<#
.SYNOPSIS
Resolves effective search and exclusion paths.
.DESCRIPTION
Applies runtime overrides for search paths and excluded paths, validates that
extensions start with a dot, and returns values used consistently by scanner and
reports.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Get-EffectiveSearchPaths -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([hashtable]$Config)
    $paths = @($Config.SearchPaths)
    if ($SearchPaths -and $SearchPaths.Count -gt 0) { $paths = @($SearchPaths) }
    $excludes = @($Config.ExcludedPaths)
    if ($ExcludePaths -and $ExcludePaths.Count -gt 0) { $excludes = @($ExcludePaths) }
    $extensions = @()
    foreach ($extension in @($Config.SearchFileExtensions)) {
        if (-not $extension.StartsWith('.')) { throw "SearchFileExtensions values must start with a dot: $extension" }
        $extensions += $extension.ToLowerInvariant()
    }
    [pscustomobject]@{ SearchPaths = $paths; ExcludedPaths = $excludes; Extensions = $extensions }
}

function ConvertTo-CollectionPath {
<#
.SYNOPSIS
Converts a local path into a collection path.
.DESCRIPTION
For remote NoWinRM and local archive inspection, local drive paths are converted
to administrative-share UNC paths. Localhost targets use native paths.
.PARAMETER Target
Standard target object.
.PARAMETER Path
Local target path.
.PARAMETER CollectionMode
Collection mode.
.EXAMPLE
ConvertTo-CollectionPath -Target $Target -Path 'C:\Program Files' -CollectionMode NoWinRM
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([object]$Target,[string]$Path,[string]$CollectionMode)
    $isLocal = $CollectionMode -eq 'Localhost' -or $Target.LookupName -match '^(localhost|\.|127\.0\.0\.1|::1)$' -or $Target.ServerName -ieq $env:COMPUTERNAME
    if ($isLocal) { return $Path }
    if ($Path -match '^([A-Za-z]):\\(.*)$') {
        return "\\$($Target.LookupName)\$($matches[1])$\" + $matches[2]
    }
    return $Path
}

function Find-Log4jCandidateArtifacts {
<#
.SYNOPSIS
Locates candidate Java archives and Log4j-named files.
.DESCRIPTION
Enumerates configured search paths, respects excluded paths, supports archive
extension filtering and maximum archive size, and records path-level failures
instead of calling incomplete scans clean.
.PARAMETER Target
Standard target object.
.PARAMETER EffectivePaths
Resolved search/exclusion/extension object.
.PARAMETER Config
Validated configuration.
.PARAMETER CollectionMode
Collection mode.
.EXAMPLE
Find-Log4jCandidateArtifacts -Target $Target -EffectivePaths $Paths -Config $Config -CollectionMode WinRM
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object]$Target,[object]$EffectivePaths,[hashtable]$Config,[string]$CollectionMode)
    $results = @()
    $maxBytes = [int64]$Config.MaximumArchiveSizeMB * 1MB
    foreach ($searchPath in @($EffectivePaths.SearchPaths)) {
        $collectionPath = ConvertTo-CollectionPath -Target $Target -Path $searchPath -CollectionMode $CollectionMode
        try {
            if (-not (Test-Path -LiteralPath $collectionPath)) { throw "Search path unavailable: $collectionPath" }
            $files = Get-ChildItem -LiteralPath $collectionPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $full = $_.FullName
                $excluded = $false
                foreach ($exclude in @($EffectivePaths.ExcludedPaths)) {
                    $excludePath = ConvertTo-CollectionPath -Target $Target -Path $exclude -CollectionMode $CollectionMode
                    if ($full.StartsWith($excludePath, [System.StringComparison]::OrdinalIgnoreCase)) { $excluded = $true }
                }
                (-not $excluded) -and ($EffectivePaths.Extensions -contains $_.Extension.ToLowerInvariant()) -and ($_.Length -le $maxBytes) -and (($_.Name -match 'log4j') -or -not $SkipArchiveInspection)
            }
            foreach ($file in @($files)) {
                $results += [pscustomobject]@{ Path = $file.FullName; OriginalPath = (ConvertFrom-CollectionPath -Target $Target -Path $file.FullName); Name = $file.Name; Extension = $file.Extension; Length = $file.Length; LastWriteTime = $file.LastWriteTime; ParentArchivePath = ''; NestedArchiveChain = '' }
            }
        } catch {
            $Script:Failures += [pscustomobject]@{ Timestamp = (Get-Date).ToString('s'); ServerName = $Target.ServerName; Status = 'PartialScan'; FailureReason = $_.Exception.Message; Path = $searchPath }
        }
    }
    return $results
}

function ConvertFrom-CollectionPath {
<#
.SYNOPSIS
Converts a UNC collection path back to a target-local path.
.DESCRIPTION
Used so reports show the production path rather than the administrative-share
path used by the scanner.
.PARAMETER Target
Standard target object.
.PARAMETER Path
Collection path.
.EXAMPLE
ConvertFrom-CollectionPath -Target $Target -Path '\\SERVER\C$\App\a.jar'
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([object]$Target,[string]$Path)
    $pattern = '^\\\\' + [regex]::Escape($Target.LookupName) + '\\([A-Za-z])\$(\\.*)$'
    if ($Path -match $pattern) { return ($matches[1] + ':' + $matches[2]) }
    return $Path
}

function Read-ArchiveEntriesSafely {
<#
.SYNOPSIS
Inspects archive entries without modifying application files.
.DESCRIPTION
Opens JAR, WAR, EAR, and ZIP files read-only through .NET compression APIs,
collects entry names, and reads only small metadata files needed for version
detection. It never extracts content to application directories.
.PARAMETER Path
Archive path.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Read-ArchiveEntriesSafely -Path C:\App\log4j-core-2.14.1.jar -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path,[hashtable]$Config)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $entries = @()
        $metadata = @{}
        foreach ($entry in $archive.Entries) {
            $entries += $entry.FullName
            if ($entry.Length -le 65536 -and ($entry.FullName -match 'META-INF/MANIFEST.MF$|pom.properties$|pom.xml$')) {
                try {
                    $reader = New-Object System.IO.StreamReader($entry.Open())
                    $metadata[$entry.FullName] = $reader.ReadToEnd()
                    $reader.Close()
                } catch { }
            }
        }
        [pscustomobject]@{ Entries = $entries; Metadata = $metadata; ReadStatus = 'ReadSucceeded'; FailureReason = '' }
    } catch {
        [pscustomobject]@{ Entries = @(); Metadata = @{}; ReadStatus = 'ReadFailed'; FailureReason = $_.Exception.Message }
    } finally {
        if ($null -ne $archive) { $archive.Dispose() }
    }
}

function Find-NestedLog4jArtifacts {
<#
.SYNOPSIS
Recursively inspects nested archive entries.
.DESCRIPTION
When enabled, copies nested archive entries to the configured temporary workspace
and inspects them up to MaximumNestedArchiveDepth. Nested remediation is not
performed by this solution.
.PARAMETER ParentPath
Outer archive path.
.PARAMETER ParentDisplayPath
Path displayed in reports.
.PARAMETER ArchiveInfo
Archive entries and metadata.
.PARAMETER Config
Validated configuration.
.PARAMETER Depth
Current nested depth.
.PARAMETER Chain
Current archive chain.
.EXAMPLE
Find-NestedLog4jArtifacts -ParentPath C:\App\a.war -ArchiveInfo $Info -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([string]$ParentPath,[string]$ParentDisplayPath,[object]$ArchiveInfo,[hashtable]$Config,[int]$Depth = 1,[string]$Chain = '')
    $nested = @()
    if (-not $Config.IncludeNestedArchives -or -not $IncludeNestedArchives) { return $nested }
    if ($Depth -gt [int]$Config.MaximumNestedArchiveDepth) { return $nested }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($ParentPath)
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -match '\.(jar|war|ear|zip)$' -and $entry.Length -le ([int64]$Config.MaximumArchiveSizeMB * 1MB)) {
                $safeName = ([guid]::NewGuid().ToString() + '_' + [IO.Path]::GetFileName($entry.FullName))
                $tempPath = Join-Path $Script:TempRoot $safeName
                try {
                    $entryStream = $entry.Open()
                    $fileStream = [System.IO.File]::Create($tempPath)
                    $entryStream.CopyTo($fileStream)
                    $fileStream.Close(); $entryStream.Close()
                    $info = Read-ArchiveEntriesSafely -Path $tempPath -Config $Config
                    if ($entry.FullName -match 'log4j' -or (($info.Entries -join '|') -match 'log4j')) {
                        $newChain = $ParentDisplayPath + ' -> ' + $entry.FullName
                        $nested += [pscustomobject]@{ Path = $tempPath; OriginalPath = $entry.FullName; Name = [IO.Path]::GetFileName($entry.FullName); Extension = [IO.Path]::GetExtension($entry.FullName); Length = $entry.Length; LastWriteTime = $entry.LastWriteTime; ParentArchivePath = $ParentDisplayPath; NestedArchiveChain = $newChain; ArchiveInfo = $info }
                        $nested += Find-NestedLog4jArtifacts -ParentPath $tempPath -ParentDisplayPath $newChain -ArchiveInfo $info -Config $Config -Depth ($Depth + 1) -Chain $newChain
                    }
                } catch {
                    $Script:Failures += [pscustomobject]@{ Timestamp = (Get-Date).ToString('s'); ServerName = ''; Status = 'NestedArchiveInspectionFailed'; FailureReason = $_.Exception.Message; Path = $entry.FullName }
                }
            }
        }
    } finally {
        if ($null -ne $archive) { $archive.Dispose() }
    }
    return $nested
}

function Get-Log4jVersionMetadata {
<#
.SYNOPSIS
Attempts Log4j version identification.
.DESCRIPTION
Uses filename, manifest, Maven pom.properties, pom.xml, and package metadata
signals. Unknown versions are not assumed safe and are classified conservatively.
.PARAMETER FileName
Artifact filename.
.PARAMETER ArchiveInfo
Archive entries and metadata.
.EXAMPLE
Get-Log4jVersionMetadata -FileName log4j-core-2.14.1.jar -ArchiveInfo $Info
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([string]$FileName,[object]$ArchiveInfo)
    $version = ''
    $method = 'Unknown'
    $confidence = 'Low'
    if ($FileName -match 'log4j(?:-core|-api)?[-_ ]([0-9]+(?:\.[0-9]+){1,3}(?:[-.A-Za-z0-9]+)?)') {
        $version = $matches[1]; $method = 'FileName'; $confidence = 'Medium'
    }
    foreach ($key in @($ArchiveInfo.Metadata.Keys)) {
        $text = [string]$ArchiveInfo.Metadata[$key]
        if ($text -match '(?m)^(version|Implementation-Version|Bundle-Version)\s*[:=]\s*([0-9]+(?:\.[0-9]+){1,3}(?:[-.A-Za-z0-9]+)?)') {
            $version = $matches[2]; $method = $key; $confidence = 'High'; break
        }
    }
    [pscustomobject]@{ Version = $version; Method = $method; Confidence = $confidence }
}

function Test-JndiLookupClassPresence {
<#
.SYNOPSIS
Identifies JndiLookup and JndiManager class entries.
.DESCRIPTION
Checks archive entry names for Log4j 2 JNDI classes. Presence or absence is
reported as evidence, not final proof of exploitability or vendor support.
.PARAMETER ArchiveInfo
Archive entries and metadata.
.EXAMPLE
Test-JndiLookupClassPresence -ArchiveInfo $Info
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$ArchiveInfo)
    $entries = @($ArchiveInfo.Entries)
    [pscustomobject]@{
        JndiLookupClassPresent  = ($entries -contains 'org/apache/logging/log4j/core/lookup/JndiLookup.class')
        JndiManagerClassPresent = ($entries -contains 'org/apache/logging/log4j/core/net/JndiManager.class')
    }
}

function Test-Log4j1JmsAppenderIndicator {
<#
.SYNOPSIS
Detects Log4j 1.x JMSAppender indicators.
.DESCRIPTION
Looks for JMSAppender evidence in archive entry names, small metadata files, and
scanned configuration text. Secret values are not exported.
.PARAMETER ArchiveInfo
Archive entries and metadata.
.PARAMETER ConfigIndicators
Configuration indicators found near the artifact.
.EXAMPLE
Test-Log4j1JmsAppenderIndicator -ArchiveInfo $Info
.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param([object]$ArchiveInfo,[string[]]$ConfigIndicators)
    if ((@($ArchiveInfo.Entries) -join '|') -match 'JMSAppender') { return $true }
    foreach ($value in @($ArchiveInfo.Metadata.Values)) { if ([string]$value -match 'JMSAppender') { return $true } }
    foreach ($indicator in @($ConfigIndicators)) { if ($indicator -match 'JMSAppender') { return $true } }
    return $false
}

function Get-RunningJavaProcessContext {
<#
.SYNOPSIS
Collects optional Java process context.
.DESCRIPTION
Collects Java process command lines for correlation only. Absence from the
current process list is never reported as proof that an artifact is unused.
.PARAMETER Target
Standard target object.
.PARAMETER CollectionMode
Collection mode.
.PARAMETER Credential
Credential for remote collection.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Get-RunningJavaProcessContext -Target $Target -CollectionMode WinRM -Credential $Credential -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object]$Target,[string]$CollectionMode,[System.Management.Automation.PSCredential]$Credential,[hashtable]$Config)
    if (-not $Config.IncludeRunningJavaProcessCollection) { return @() }
    try {
        if ($CollectionMode -eq 'Localhost') {
            return Get-WmiObject Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" | Select-Object ProcessId,Name,CommandLine
        }
        if ($CollectionMode -eq 'WinRM') {
            return Invoke-Command -ComputerName $Target.LookupName -Credential $Credential -ScriptBlock { Get-WmiObject Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" | Select-Object ProcessId,Name,CommandLine } -ErrorAction Stop
        }
        if ($UseDcomWmi) { return Get-WmiObject Win32_Process -ComputerName $Target.LookupName -Credential $Credential -Filter "Name='java.exe' OR Name='javaw.exe'" | Select-Object ProcessId,Name,CommandLine }
    } catch { $Script:Failures += [pscustomobject]@{ Timestamp = (Get-Date).ToString('s'); ServerName = $Target.ServerName; Status = 'ProcessCollectionFailed'; FailureReason = $_.Exception.Message } }
    return @()
}

function Get-ServiceCorrelationContext {
<#
.SYNOPSIS
Collects optional service inventory context.
.DESCRIPTION
Collects candidate Java-related Windows services for correlation only. The
script never guesses service ownership and does not stop services unless a
separate approved remediation workflow explicitly allows it.
.PARAMETER Target
Standard target object.
.PARAMETER CollectionMode
Collection mode.
.PARAMETER Credential
Credential for remote collection.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Get-ServiceCorrelationContext -Target $Target -CollectionMode NoWinRM -Credential $Credential -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object]$Target,[string]$CollectionMode,[System.Management.Automation.PSCredential]$Credential,[hashtable]$Config)
    if (-not $Config.IncludeServiceInventory) { return @() }
    try {
        if ($CollectionMode -eq 'Localhost') {
            return Get-WmiObject Win32_Service | Where-Object { $_.PathName -match 'java|tomcat|jetty|jboss|wildfly|log4j' -or $_.DisplayName -match 'java|tomcat|jetty|jboss|wildfly' } | Select-Object Name,DisplayName,State,PathName
        }
        if ($CollectionMode -eq 'WinRM') {
            return Invoke-Command -ComputerName $Target.LookupName -Credential $Credential -ScriptBlock { Get-WmiObject Win32_Service | Where-Object { $_.PathName -match 'java|tomcat|jetty|jboss|wildfly|log4j' -or $_.DisplayName -match 'java|tomcat|jetty|jboss|wildfly' } | Select-Object Name,DisplayName,State,PathName } -ErrorAction Stop
        }
        if ($UseDcomWmi) { return Get-WmiObject Win32_Service -ComputerName $Target.LookupName -Credential $Credential | Where-Object { $_.PathName -match 'java|tomcat|jetty|jboss|wildfly|log4j' -or $_.DisplayName -match 'java|tomcat|jetty|jboss|wildfly' } | Select-Object Name,DisplayName,State,PathName }
    } catch { $Script:Failures += [pscustomobject]@{ Timestamp = (Get-Date).ToString('s'); ServerName = $Target.ServerName; Status = 'ServiceCollectionFailed'; FailureReason = $_.Exception.Message } }
    return @()
}

function Get-ConfigurationIndicators {
<#
.SYNOPSIS
Scans configuration files for non-secret Log4j indicators.
.DESCRIPTION
Searches configured file patterns under approved paths for Log4j, JMSAppender,
and JNDI references. It records only indicator labels and paths, never matched
configuration values that may contain secrets.
.PARAMETER Target
Standard target object.
.PARAMETER EffectivePaths
Resolved search/exclusion/extension object.
.PARAMETER Config
Validated configuration.
.PARAMETER CollectionMode
Collection mode.
.EXAMPLE
Get-ConfigurationIndicators -Target $Target -EffectivePaths $Paths -Config $Config -CollectionMode WinRM
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object]$Target,[object]$EffectivePaths,[hashtable]$Config,[string]$CollectionMode)
    $indicators = @()
    if (-not $Config.IncludeConfigurationFileScan) { return $indicators }
    foreach ($root in @($EffectivePaths.SearchPaths)) {
        $collectionPath = ConvertTo-CollectionPath -Target $Target -Path $root -CollectionMode $CollectionMode
        foreach ($pattern in @($Config.ConfigurationFilePatterns)) {
            try {
                $files = Get-ChildItem -LiteralPath $collectionPath -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue
                foreach ($file in @($files)) {
                    $content = Get-Content -LiteralPath $file.FullName -TotalCount 2000 -ErrorAction SilentlyContinue
                    $joined = $content -join "`n"
                    $labels = @()
                    if ($joined -match 'log4j') { $labels += 'Log4jReference' }
                    if ($joined -match 'JMSAppender') { $labels += 'JMSAppender' }
                    if ($joined -match 'jndi') { $labels += 'JndiReference' }
                    if ($labels.Count -gt 0) { $indicators += [pscustomobject]@{ Path = (ConvertFrom-CollectionPath -Target $Target -Path $file.FullName); Indicators = ($labels -join ';') } }
                }
            } catch { }
        }
    }
    return $indicators
}

function Get-Log4jVulnerabilityClassification {
<#
.SYNOPSIS
Applies conservative Log4j classification rules and CVE mapping.
.DESCRIPTION
Classifies Log4j API-only, Log4j 1.x, Log4j 2 Core vulnerable ranges, unknown
versions, patched versions, and mitigation indicators. It avoids treating
inventory as confirmed exploitability and does not mark JndiLookup removal as a
vendor-supported upgrade.
.PARAMETER FileName
Artifact file name.
.PARAMETER ArchiveInfo
Archive entries and metadata.
.PARAMETER VersionInfo
Detected version metadata.
.PARAMETER JndiInfo
JNDI class presence object.
.PARAMETER JmsAppenderPresent
JMSAppender indicator.
.PARAMETER IsNested
Whether finding is nested inside another archive.
.EXAMPLE
Get-Log4jVulnerabilityClassification -FileName log4j-core-2.14.1.jar -ArchiveInfo $Info -VersionInfo $Version
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([string]$FileName,[object]$ArchiveInfo,[object]$VersionInfo,[object]$JndiInfo,[bool]$JmsAppenderPresent,[bool]$IsNested)
    $entriesText = (@($ArchiveInfo.Entries) -join '|')
    $name = $FileName.ToLowerInvariant()
    $corePresent = ($name -match 'log4j-core') -or ($entriesText -match 'org/apache/logging/log4j/core/')
    $apiPresent = ($name -match 'log4j-api') -and -not $corePresent
    $major = ''
    $classification = 'ManualReviewRequired'
    $detStatus = 'Detected'
    $cves = ''
    $action = 'Manual review required.'
    if ($apiPresent) { $classification = 'Log4jApiOnlyDetected'; $action = 'Inventory only; confirm whether log4j-core exists elsewhere.' }
    elseif ($name -match 'log4j-1|log4j1|log4j[^0-9]*1\.' -or $VersionInfo.Version -match '^1\.') {
        $major = '1'
        if ($JmsAppenderPresent) { $classification = 'Log4j1JMSAppenderReviewRequired'; $cves = 'CVE-2021-4104'; $action = 'Log4j 1.x is end-of-life; review JMSAppender exposure and replace through vendor/application upgrade.' }
        else { $classification = 'Log4j1EndOfLifeDetected'; $action = 'Log4j 1.x is end-of-life; vendor/application replacement review required.' }
    } elseif ($corePresent) {
        $major = '2'
        if ([string]::IsNullOrWhiteSpace($VersionInfo.Version)) {
            $classification = 'PotentiallyVulnerableVersionUnknown'
            $cves = 'CVE-2021-44228;CVE-2021-45046;CVE-2021-45105;CVE-2021-44832'
            $action = 'Version unknown; inspect vendor package and upgrade if affected.'
        } else {
            $ver = New-Object System.Version
            $clean = ($VersionInfo.Version -replace '[^0-9\.].*$','')
            $parsed = [version]::TryParse($clean, [ref]$ver)
            if (-not $parsed) {
                $classification = 'PotentiallyVulnerableVersionUnknown'
                $cves = 'CVE-2021-44228;CVE-2021-45046;CVE-2021-45105;CVE-2021-44832'
            } elseif (($ver.Major -eq 2 -and $ver.Minor -lt 3) -or ($ver.Major -eq 2 -and $ver.Minor -eq 3 -and $ver.Build -lt 2) -or ($ver.Major -eq 2 -and $ver.Minor -eq 12 -and $ver.Build -lt 4) -or ($ver.Major -eq 2 -and $ver.Minor -ge 4 -and $ver -lt ([version]'2.17.1'))) {
                $classification = 'ConfirmedVulnerable'
                $cves = 'CVE-2021-44228;CVE-2021-45046;CVE-2021-45105;CVE-2021-44832'
                $action = 'Vendor-supported upgrade required. Emergency JndiLookup mitigation may be considered only when explicitly approved.'
            } else {
                $classification = 'PatchedVersionDetected'
                $action = 'Patched version detected; validate vendor support and application packaging.'
            }
        }
        if (($classification -eq 'ConfirmedVulnerable' -or $classification -eq 'PotentiallyVulnerableVersionUnknown') -and -not $JndiInfo.JndiLookupClassPresent) {
            $classification = 'MitigationPresentButUpgradeValidationRequired'
            $action = 'JndiLookup.class was not observed; treat as mitigation evidence and validate vendor upgrade state.'
        }
        if ($IsNested -and ($classification -match 'Vulnerable|Mitigation|ManualReview')) { $action = 'Nested archive finding; vendor upgrade or manual review required. Nested remediation is not automatic.' }
    } else {
        $classification = 'ManualReviewRequired'
        $action = 'Log4j indicator detected but component type is ambiguous.'
    }
    [pscustomobject]@{ DetectionStatus = $detStatus; VulnerabilityClassification = $classification; CVEReferences = $cves; RecommendedAction = $action; Log4jMajorVersion = $major; Log4jCorePresent = $corePresent; Log4jApiOnly = $apiPresent }
}

function New-Log4jTargetResultObject {
<#
.SYNOPSIS
Creates a standardized server-level result object.
.DESCRIPTION
Records connectivity, scan status, input source, collection mode, configured
paths, CSV metadata, and failure reason for every target.
.PARAMETER Target
Standard target object.
.PARAMETER ConnectivityStatus
Connectivity status.
.PARAMETER ScanStatus
Scan status.
.PARAMETER EffectivePaths
Resolved paths object.
.PARAMETER FailureReason
Failure reason.
.EXAMPLE
New-Log4jTargetResultObject -Target $Target -ConnectivityStatus ConnectivityPassed -ScanStatus Scanned
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Target,[string]$ConnectivityStatus,[string]$ScanStatus,[object]$EffectivePaths,[string]$FailureReason = '')
    [pscustomobject]@{
        Timestamp          = (Get-Date).ToString('s')
        InputSource        = $Target.InputSource
        ServerName         = $Target.ServerName
        FQDN               = $Target.FQDN
        LookupName         = $Target.LookupName
        ConnectivityStatus = $ConnectivityStatus
        CollectionMode     = $Script:CollectionMode
        ScanStatus         = $ScanStatus
        ScannedPaths       = (@($EffectivePaths.SearchPaths) -join ';')
        ExcludedPaths      = (@($EffectivePaths.ExcludedPaths) -join ';')
        Notes              = $Target.Notes
        TicketNumber       = $Target.TicketNumber
        ChangeWindow       = $Target.ChangeWindow
        ApplicationOwner   = $Target.ApplicationOwner
        FailureReason      = $FailureReason
    }
}

function New-Log4jFindingObject {
<#
.SYNOPSIS
Creates a standardized artifact/finding result object.
.DESCRIPTION
Builds one detailed report row per discovered artifact or nested artifact using
the field names required by the reporting workflow.
.PARAMETER Target
Standard target object.
.PARAMETER Artifact
Artifact metadata.
.PARAMETER ArchiveInfo
Archive inspection data.
.PARAMETER VersionInfo
Version detection result.
.PARAMETER Classification
Classification result.
.PARAMETER JndiInfo
JNDI class result.
.PARAMETER JmsAppenderPresent
JMSAppender indicator.
.PARAMETER SHA256
Optional SHA256.
.PARAMETER FailureReason
Failure reason.
.EXAMPLE
New-Log4jFindingObject -Target $Target -Artifact $Artifact -ArchiveInfo $Info -VersionInfo $Version -Classification $Class
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Target,[object]$Artifact,[object]$ArchiveInfo,[object]$VersionInfo,[object]$Classification,[object]$JndiInfo,[bool]$JmsAppenderPresent,[string]$SHA256 = '',[string]$FailureReason = '')
    [pscustomobject]@{
        Timestamp                    = (Get-Date).ToString('s')
        ServerName                   = $Target.ServerName
        FQDN                         = $Target.FQDN
        CollectionMode               = $Script:CollectionMode
        ScanStatus                   = $ArchiveInfo.ReadStatus
        DetectionStatus              = $Classification.DetectionStatus
        VulnerabilityClassification  = $Classification.VulnerabilityClassification
        CVEReferences                = $Classification.CVEReferences
        ArtifactType                 = 'JavaArchive'
        ArtifactPath                 = $Artifact.OriginalPath
        ParentArchivePath            = $Artifact.ParentArchivePath
        NestedArchiveChain           = $Artifact.NestedArchiveChain
        FileName                     = $Artifact.Name
        FileExtension                = $Artifact.Extension
        FileSize                     = $Artifact.Length
        LastModified                 = $Artifact.LastWriteTime
        SHA256                       = $SHA256
        ProductName                  = 'Apache Log4j'
        DetectedVersion              = $VersionInfo.Version
        VersionDetectionMethod       = $VersionInfo.Method
        VersionDetectionConfidence   = $VersionInfo.Confidence
        Log4jMajorVersion            = $Classification.Log4jMajorVersion
        Log4jCorePresent             = $Classification.Log4jCorePresent
        Log4jApiOnly                 = $Classification.Log4jApiOnly
        JndiLookupClassPresent       = $JndiInfo.JndiLookupClassPresent
        JndiManagerClassPresent      = $JndiInfo.JndiManagerClassPresent
        JMSAppenderIndicatorPresent  = $JmsAppenderPresent
        JavaProcessCorrelation       = ''
        ServiceCorrelation           = ''
        RecommendedAction            = $Classification.RecommendedAction
        QuarantinePath               = ''
        RollbackMetadataPath         = ''
        RemediationStatus            = ''
        RemediationActionTaken       = ''
        FailureReason                = $FailureReason
        Notes                        = $Target.Notes
        TicketNumber                 = $Target.TicketNumber
        ApplicationOwner             = $Target.ApplicationOwner
    }
}

function New-RemediationActionObject {
<#
.SYNOPSIS
Creates standardized remediation action records.
.DESCRIPTION
Records planned, skipped, WhatIf, successful, and failed remediation actions
without storing secrets.
.PARAMETER Target
Standard target object.
.PARAMETER Finding
Finding object.
.PARAMETER ActionType
Action type.
.PARAMETER ResultStatus
Result status.
.PARAMETER Message
Action message.
.PARAMETER QuarantinePath
Quarantine path.
.PARAMETER RollbackMetadataPath
Rollback metadata path.
.EXAMPLE
New-RemediationActionObject -Target $Target -Finding $Finding -ActionType JndiLookupMitigation -ResultStatus Preview
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Target,[object]$Finding,[string]$ActionType,[string]$ResultStatus,[string]$Message,[string]$QuarantinePath = '',[string]$RollbackMetadataPath = '')
    [pscustomobject]@{
        Timestamp            = (Get-Date).ToString('s')
        ServerName           = $Target.ServerName
        FQDN                 = $Target.FQDN
        CollectionMode       = $Script:CollectionMode
        ActionType           = $ActionType
        ArtifactPath         = $Finding.ArtifactPath
        VulnerabilityClassification = $Finding.VulnerabilityClassification
        DetectedVersion      = $Finding.DetectedVersion
        ResultStatus         = $ResultStatus
        Message              = $Message
        QuarantinePath       = $QuarantinePath
        RollbackMetadataPath = $RollbackMetadataPath
        TicketNumber         = $Target.TicketNumber
        ApplicationOwner     = $Target.ApplicationOwner
    }
}

function New-QuarantinePackage {
<#
.SYNOPSIS
Creates quarantine backup and rollback metadata.
.DESCRIPTION
Before any modification, creates a timestamped quarantine folder, copies the
original artifact, validates hashes, and writes rollback metadata. This safety
gate is required for all implemented remediation.
.PARAMETER Target
Standard target object.
.PARAMETER SourcePath
Collection path to source artifact.
.PARAMETER Finding
Finding object.
.PARAMETER Action
Remediation action.
.PARAMETER Config
Validated configuration.
.EXAMPLE
New-QuarantinePackage -Target $Target -SourcePath $Path -Finding $Finding -Action JndiLookupMitigation -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Target,[string]$SourcePath,[object]$Finding,[string]$Action,[hashtable]$Config)
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $root = $Config.QuarantinePath
    $isLocal = $Script:CollectionMode -eq 'Localhost' -or $Target.LookupName -match '^(localhost|\.|127\.0\.0\.1|::1)$' -or $Target.ServerName -ieq $env:COMPUTERNAME
    if (-not $isLocal -and $root -match '^([A-Za-z]):\\(.*)$') { $root = "\\$($Target.LookupName)\$($matches[1])$\" + $matches[2] }
    $base = Join-Path (Join-Path $root $Target.ServerName) $stamp
    $fileDir = Join-Path $base 'Files'
    $metadataDir = Join-Path $base 'Metadata'
    New-Item -ItemType Directory -Path $fileDir,$metadataDir -Force | Out-Null
    $backup = Join-Path $fileDir ([IO.Path]::GetFileName($SourcePath))
    $originalHash = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $SourcePath -Destination $backup -Force
    $backupHash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
    if ($originalHash -ne $backupHash) { throw "Quarantine hash validation failed for $SourcePath" }
    $metadataPath = Join-Path $metadataDir 'RollbackMetadata.json'
    $metadata = [pscustomobject]@{
        ServerName = $Target.ServerName; FQDN = $Target.FQDN; OriginalArtifactPath = $Finding.ArtifactPath
        OriginalArchiveChain = $Finding.NestedArchiveChain; QuarantineArtifactPath = $backup
        OriginalSHA256 = $originalHash; QuarantineSHA256 = $backupHash; ModifiedSHA256 = ''
        ArtifactVersion = $Finding.DetectedVersion; VulnerabilityClassification = $Finding.VulnerabilityClassification
        RemediationAction = $Action; RemediationTimestamp = (Get-Date).ToString('s'); OperatorUserName = [Environment]::UserName
        TicketNumber = $Target.TicketNumber; ApplicationOwner = $Target.ApplicationOwner
        ServicesStopped = @(); ServicesStarted = @()
        RollbackInstructions = 'Manually validate change approval, stop the owning application service if required, verify hashes, copy the quarantined artifact back to OriginalArtifactPath, restart services if required, and validate application functionality.'
        ResultStatus = 'Quarantined'
    }
    $metadata | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $metadataPath -Encoding UTF8
    [pscustomobject]@{ QuarantinePath = $backup; RollbackMetadataPath = $metadataPath; OriginalSHA256 = $originalHash; QuarantineSHA256 = $backupHash }
}

function Import-ApprovedReplacementManifest {
<#
.SYNOPSIS
Loads approved vendor replacement mappings.
.DESCRIPTION
Imports a CSV manifest and validates required columns for controlled vendor
replacement. Replacement files are never downloaded automatically.
.PARAMETER Path
Approved replacement manifest path.
.EXAMPLE
Import-ApprovedReplacementManifest -Path .\ApprovedReplacements.csv
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Approved replacement manifest not found: $Path" }
    $rows = Import-Csv -LiteralPath $Path
    $required = @('ServerName','OriginalArtifactPath','ReplacementArtifactPath','ExpectedOriginalSHA256','ExpectedReplacementSHA256','ApprovedTicketNumber','ApplicationOwner','RequiredServicesToStop','RequiredServicesToStart','Notes')
    foreach ($column in $required) { if ($rows.Count -gt 0 -and ($rows[0].PSObject.Properties.Name -notcontains $column)) { throw "Replacement manifest missing required column: $column" } }
    return $rows
}

function Invoke-VendorReplacementRemediation {
<#
.SYNOPSIS
Applies approved vendor replacement mappings.
.DESCRIPTION
Performs only manifest-matched, hash-validated replacements after quarantine and
rollback metadata creation. Service control is not guessed and is prohibited
unless separately approved in configuration.
.PARAMETER Target
Standard target object.
.PARAMETER Findings
Finding objects.
.PARAMETER Manifest
Approved replacement mappings.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Invoke-VendorReplacementRemediation -Target $Target -Findings $Findings -Manifest $Manifest -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([object]$Target,[object[]]$Findings,[object[]]$Manifest,[hashtable]$Config)
    $actions = @()
    foreach ($finding in @($Findings)) {
        $match = @($Manifest | Where-Object { ($_.ServerName -eq $Target.ServerName -or [string]::IsNullOrWhiteSpace($_.ServerName)) -and $_.OriginalArtifactPath -eq $finding.ArtifactPath } | Select-Object -First 1)
        if ($match.Count -eq 0) { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'VendorReplacement' -ResultStatus 'Skipped' -Message 'No approved manifest match.'; continue }
        $source = ConvertTo-CollectionPath -Target $Target -Path $finding.ArtifactPath -CollectionMode $Script:CollectionMode
        $replacement = $match[0].ReplacementArtifactPath
        if (-not (Test-Path -LiteralPath $replacement)) { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'VendorReplacement' -ResultStatus 'FailedRemediation' -Message 'Replacement file not found.'; continue }
        $replacementHash = (Get-FileHash -LiteralPath $replacement -Algorithm SHA256).Hash
        if ($replacementHash -ne $match[0].ExpectedReplacementSHA256) { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'VendorReplacement' -ResultStatus 'FailedRemediation' -Message 'Replacement hash mismatch.'; continue }
        if (-not [string]::IsNullOrWhiteSpace((Get-OptionalPropertyValue -InputObject $match[0] -Name 'ExpectedOriginalSHA256'))) {
            $originalHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
            if ($originalHash -ne (Get-OptionalPropertyValue -InputObject $match[0] -Name 'ExpectedOriginalSHA256')) { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'VendorReplacement' -ResultStatus 'FailedRemediation' -Message 'Original hash mismatch.'; continue }
        }
        if ($WhatIfPreference) { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'VendorReplacement' -ResultStatus 'WhatIf' -Message 'Would quarantine and replace approved artifact.'; continue }
        if ($PSCmdlet.ShouldProcess($finding.ArtifactPath, 'Replace approved vendor artifact')) {
            try {
                $q = New-QuarantinePackage -Target $Target -SourcePath $source -Finding $finding -Action 'VendorReplacement' -Config $Config
                Copy-Item -LiteralPath $replacement -Destination $source -Force
                $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'VendorReplacement' -ResultStatus 'Replaced' -Message 'Approved vendor replacement completed.' -QuarantinePath $q.QuarantinePath -RollbackMetadataPath $q.RollbackMetadataPath
            } catch { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'VendorReplacement' -ResultStatus 'FailedRemediation' -Message $_.Exception.Message }
        }
    }
    return $actions
}

function Invoke-JndiLookupMitigation {
<#
.SYNOPSIS
Applies emergency JndiLookup.class removal mitigation.
.DESCRIPTION
Removes only org/apache/logging/log4j/core/lookup/JndiLookup.class from eligible
top-level Log4j 2 Core archives after quarantine and rollback metadata creation.
This is mitigation only and reports MitigatedPendingUpgrade.
.PARAMETER Target
Standard target object.
.PARAMETER Findings
Eligible finding objects.
.PARAMETER Config
Validated configuration.
.EXAMPLE
Invoke-JndiLookupMitigation -Target $Target -Findings $Findings -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param([object]$Target,[object[]]$Findings,[hashtable]$Config)
    $actions = @()
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($finding in @($Findings)) {
        $archive = $null
        $eligible = $finding.Log4jCorePresent -and -not $finding.Log4jApiOnly -and $finding.Log4jMajorVersion -ne '1' -and $finding.JndiLookupClassPresent -and [string]::IsNullOrWhiteSpace($finding.ParentArchivePath) -and ($finding.VulnerabilityClassification -match 'ConfirmedVulnerable|PotentiallyVulnerable|MitigationPresent')
        if (-not $eligible) { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'JndiLookupMitigation' -ResultStatus 'Skipped' -Message 'Finding is not eligible for top-level Log4j 2 JndiLookup mitigation.'; continue }
        if ($WhatIfPreference) { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'JndiLookupMitigation' -ResultStatus 'WhatIf' -Message 'Would quarantine archive and remove JndiLookup.class.'; continue }
        if (-not $Force -and $Config.RequireConfirmationBeforeRemediation) {
            $answer = Read-Host "Type YES to mitigate $($finding.ArtifactPath)"
            if ($answer -ne 'YES') { $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'JndiLookupMitigation' -ResultStatus 'Skipped' -Message 'Operator did not approve custom confirmation prompt.'; continue }
        }
        $source = ConvertTo-CollectionPath -Target $Target -Path $finding.ArtifactPath -CollectionMode $Script:CollectionMode
        if ($PSCmdlet.ShouldProcess($finding.ArtifactPath, 'Remove JndiLookup.class from Log4j Core archive')) {
            try {
                $q = New-QuarantinePackage -Target $Target -SourcePath $source -Finding $finding -Action 'JndiLookupMitigation' -Config $Config
                $archive = [System.IO.Compression.ZipFile]::Open($source, [System.IO.Compression.ZipArchiveMode]::Update)
                $entry = $archive.GetEntry('org/apache/logging/log4j/core/lookup/JndiLookup.class')
                if ($null -eq $entry) { throw 'JndiLookup.class was not present when archive was opened for update.' }
                $entry.Delete()
                $archive.Dispose()
                $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'JndiLookupMitigation' -ResultStatus 'MitigatedPendingUpgrade' -Message 'JndiLookup.class removed; vendor upgrade remains required.' -QuarantinePath $q.QuarantinePath -RollbackMetadataPath $q.RollbackMetadataPath
            } catch {
                if ($null -ne $archive) { $archive.Dispose() }
                $actions += New-RemediationActionObject -Target $Target -Finding $finding -ActionType 'JndiLookupMitigation' -ResultStatus 'FailedRemediation' -Message $_.Exception.Message
            }
        }
    }
    return $actions
}

function Get-RemediationSummary {
<#
.SYNOPSIS
Produces summary counts for reporting.
.DESCRIPTION
Calculates the console, TXT, HTML, and JSON summary object using actual target,
finding, remediation, failure, and report path data.
.PARAMETER Metadata
Run metadata.
.PARAMETER Targets
Target result objects.
.PARAMETER Findings
Finding objects.
.PARAMETER RemediationActions
Remediation action objects.
.PARAMETER Failures
Failure objects.
.PARAMETER ReportPaths
Generated report paths.
.EXAMPLE
Get-RemediationSummary -Targets $Targets -Findings $Findings -RemediationActions $Actions
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Metadata,[object[]]$Targets,[object[]]$Findings,[object[]]$RemediationActions,[object[]]$Failures,[object]$ReportPaths)
    [pscustomobject]@{
        InputSourceMode = $Metadata.InputSourceMode; CollectionMode = $Metadata.CollectionMode
        TotalServerTargetsProcessed = @($Targets).Count
        ConnectivityPassed = @($Targets | Where-Object { $_.ConnectivityStatus -eq 'ConnectivityPassed' }).Count
        ConnectivityFailed = @($Targets | Where-Object { $_.ConnectivityStatus -eq 'ConnectivityFailed' }).Count
        SuccessfullyScannedServers = @($Targets | Where-Object { $_.ScanStatus -eq 'Scanned' }).Count
        PartiallyScannedServers = @($Targets | Where-Object { $_.ScanStatus -eq 'PartialScan' }).Count
        FailedScans = @($Targets | Where-Object { $_.ScanStatus -eq 'FailedScan' }).Count
        TotalCandidateArchivesInspected = @($Findings).Count
        ConfirmedVulnerableArtifacts = @($Findings | Where-Object { $_.VulnerabilityClassification -eq 'ConfirmedVulnerable' }).Count
        PotentiallyVulnerableVersionUnknownArtifacts = @($Findings | Where-Object { $_.VulnerabilityClassification -eq 'PotentiallyVulnerableVersionUnknown' }).Count
        Log4j1EndOfLifeFindings = @($Findings | Where-Object { $_.VulnerabilityClassification -eq 'Log4j1EndOfLifeDetected' }).Count
        JMSAppenderReviewFindings = @($Findings | Where-Object { $_.VulnerabilityClassification -eq 'Log4j1JMSAppenderReviewRequired' }).Count
        PatchedLog4jArtifactsIdentified = @($Findings | Where-Object { $_.VulnerabilityClassification -eq 'PatchedVersionDetected' }).Count
        VendorUpgradesRequired = @($Findings | Where-Object { $_.RecommendedAction -match 'upgrade|required|replacement' }).Count
        PreviewRemediationActions = @($RemediationActions | Where-Object { $_.ResultStatus -eq 'Preview' }).Count
        WhatIfRemediationActions = @($RemediationActions | Where-Object { $_.ResultStatus -eq 'WhatIf' }).Count
        QuarantinedArtifacts = @($RemediationActions | Where-Object { $_.QuarantinePath }).Count
        VendorReplacementsCompleted = @($RemediationActions | Where-Object { $_.ResultStatus -eq 'Replaced' }).Count
        JndiLookupMitigationsCompleted = @($RemediationActions | Where-Object { $_.ResultStatus -eq 'MitigatedPendingUpgrade' }).Count
        MitigatedPendingUpgrade = @($RemediationActions | Where-Object { $_.ResultStatus -eq 'MitigatedPendingUpgrade' }).Count
        RemediationFailures = @($RemediationActions | Where-Object { $_.ResultStatus -eq 'FailedRemediation' }).Count
        ManualReviewRequired = @($Findings | Where-Object { $_.VulnerabilityClassification -match 'ManualReview|Log4j1|Potentially' }).Count
        CsvReportPath = $ReportPaths.CsvPath; JsonReportPath = $ReportPaths.JsonPath; TxtReportPath = $ReportPaths.TxtPath; HtmlReportPath = $ReportPaths.HtmlPath
        TranscriptPath = $Script:TranscriptPath
    }
}

function Write-RunSummary {
<#
.SYNOPSIS
Displays final non-secret summary and report paths.
.DESCRIPTION
Writes summary counts and generated report locations to the console without
displaying credentials, passwords, tokens, or secure strings.
.PARAMETER Summary
Summary object.
.EXAMPLE
Write-RunSummary -Summary $Summary
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([object]$Summary)
    Write-Host ''
    Write-Host 'Log4j run summary'
    foreach ($property in $Summary.PSObject.Properties) { Write-Host ("{0}: {1}" -f $property.Name, $property.Value) }
}

function Write-StartupSummary {
<#
.SYNOPSIS
Displays a non-secret configuration summary.
.DESCRIPTION
Shows execution mode, input source, collection mode, configured paths, safety
gates, and reporting settings. Credential values and secrets are not displayed.
.PARAMETER Config
Validated configuration.
.PARAMETER InputSource
Resolved input source object.
.PARAMETER EffectivePaths
Resolved paths object.
.EXAMPLE
Write-StartupSummary -Config $Config -InputSource $Input -EffectivePaths $Paths
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([hashtable]$Config,[object]$InputSource,[object]$EffectivePaths)
    Write-Host 'Log4j Detection and Remediation Solution'
    Write-Host ("Execution mode: {0}" -f $Script:ExecutionMode)
    Write-Host ("Input source mode: {0}" -f $InputSource.InputSourceMode)
    Write-Host ("Config path: {0}" -f $ConfigPath)
    Write-Host ("CSV path: {0}" -f $InputSource.CsvPath)
    Write-Host ("Manual entry: {0}" -f ($InputSource.InputSourceMode -match 'Manual'))
    Write-Host ("Collection mode: {0}" -f $Script:CollectionMode)
    Write-Host ("AllowLocalhost: {0}" -f $Config.AllowLocalhost)
    Write-Host ("Localhost target name: {0}" -f $Config.LocalhostTargetName)
    Write-Host ("Localhost credential bypass: {0}" -f $Config.LocalhostBypassCredentialPrompt)
    Write-Host ("Domain: {0}" -f $Config.Domain)
    Write-Host ("UserName: {0}" -f $Config.UserName)
    Write-Host ("UseFqdn: {0}" -f $Config.UseFqdn)
    Write-Host ("Search paths: {0}" -f (@($EffectivePaths.SearchPaths) -join '; '))
    Write-Host ("Excluded paths: {0}" -f (@($EffectivePaths.ExcludedPaths) -join '; '))
    Write-Host ("Archive extensions: {0}" -f (@($EffectivePaths.Extensions) -join '; '))
    Write-Host ("Nested archive inspection: {0}" -f (($Config.IncludeNestedArchives -and $IncludeNestedArchives) -as [bool]))
    Write-Host ("Hash calculation: {0}" -f (($Config.IncludeFileHash -or $IncludeHash) -as [bool]))
    Write-Host ("RemediationEnabled: {0}" -f $Config.RemediationEnabled)
    Write-Host ("AllowVendorReplacement: {0}" -f $Config.AllowVendorReplacement)
    Write-Host ("AllowJndiLookupMitigation: {0}" -f $Config.AllowJndiLookupMitigation)
    Write-Host ("Quarantine path: {0}" -f $Config.QuarantinePath)
    Write-Host ("Report formats: {0}" -f (@($Config.ReportFormats) -join ', '))
    Write-Host ("Output path: {0}" -f $Config.OutputPath)
    Write-Host ("Log path: {0}" -f $Config.LogPath)
    Write-Host ("WhatIf state: {0}" -f $WhatIfPreference)
}

try {
    $Script:Config = Import-Log4jConfiguration -Path $ConfigPath
    if ($ReportFormat -and $ReportFormat.Count -gt 0) { $Script:Config['ReportFormats'] = $ReportFormat }
    if ($TimeoutSeconds -gt 0) { $Script:Config['TimeoutSeconds'] = $TimeoutSeconds }
    if (-not [string]::IsNullOrWhiteSpace($QuarantinePath)) { $Script:Config['QuarantinePath'] = $QuarantinePath }
    $Script:CollectionMode = Test-ExecutionMode -Config $Script:Config
    Initialize-OutputFolders -Config $Script:Config | Out-Null
    Start-SafeTranscript -Config $Script:Config | Out-Null
    $serverInput = Resolve-ServerInputSource -Config $Script:Config
    $effective = Get-EffectiveSearchPaths -Config $Script:Config
    Write-StartupSummary -Config $Script:Config -InputSource $serverInput -EffectivePaths $effective
    if ($null -eq $Credential -and -not ($Script:CollectionMode -eq 'Localhost' -and $Script:Config.LocalhostBypassCredentialPrompt)) {
        $credentialUser = "$($Script:Config.Domain)\$($Script:Config.UserName)"
        $Credential = Get-Credential -UserName $credentialUser -Message 'Enter credentials for Log4j discovery and remediation operations'
    }

    $targetResults = @()
    $findings = @()
    $remediationActions = @()
    $replacementManifest = @()
    if ($ApplyVendorReplacement -and $Script:Config.AllowVendorReplacement) { $replacementManifest = Import-ApprovedReplacementManifest -Path $Script:Config.ApprovedReplacementManifestPath }

    $index = 0
    foreach ($target in @($serverInput.Targets)) {
        $index++
        Write-Progress -Activity 'Log4j remediation workflow' -Status ("{0}/{1} {2} Connectivity" -f $index, @($serverInput.Targets).Count, $target.ServerName) -PercentComplete (($index / @($serverInput.Targets).Count) * 100)
        Write-Host ("[{0}] Testing connectivity for {1}" -f (Get-Date -Format T), $target.ServerName)
        $conn = Test-TargetConnectivity -Target $target -CollectionMode $Script:CollectionMode -Credential $Credential -Config $Script:Config
        if ($conn.Status -ne 'ConnectivityPassed') {
            Write-Host ("ConnectivityFailed: {0} - {1}" -f $target.ServerName, $conn.FailureReason)
            $targetResults += New-Log4jTargetResultObject -Target $target -ConnectivityStatus $conn.Status -ScanStatus 'FailedScan' -EffectivePaths $effective -FailureReason $conn.FailureReason
            if (-not $Script:Config.ContinueOnError) { throw $conn.FailureReason }
            continue
        }
        if ($ConnectivityOnly) {
            $targetResults += New-Log4jTargetResultObject -Target $target -ConnectivityStatus $conn.Status -ScanStatus 'NotScannedConnectivityOnly' -EffectivePaths $effective
            continue
        }
        Write-Progress -Activity 'Log4j remediation workflow' -Status ("{0}/{1} {2} Scanning" -f $index, @($serverInput.Targets).Count, $target.ServerName) -PercentComplete (($index / @($serverInput.Targets).Count) * 100)
        $javaProcesses = Get-RunningJavaProcessContext -Target $target -CollectionMode $Script:CollectionMode -Credential $Credential -Config $Script:Config
        $services = Get-ServiceCorrelationContext -Target $target -CollectionMode $Script:CollectionMode -Credential $Credential -Config $Script:Config
        $configIndicators = Get-ConfigurationIndicators -Target $target -EffectivePaths $effective -Config $Script:Config -CollectionMode $Script:CollectionMode
        $artifacts = Find-Log4jCandidateArtifacts -Target $target -EffectivePaths $effective -Config $Script:Config -CollectionMode $Script:CollectionMode
        $targetFindings = @()
        foreach ($artifact in @($artifacts)) {
            Write-Progress -Activity 'Inspecting archives' -Status $artifact.OriginalPath
            $archiveInfo = [pscustomobject]@{ Entries = @(); Metadata = @{}; ReadStatus = 'ArchiveInspectionSkipped'; FailureReason = '' }
            if (-not $SkipArchiveInspection) { $archiveInfo = Read-ArchiveEntriesSafely -Path $artifact.Path -Config $Script:Config }
            $versionInfo = Get-Log4jVersionMetadata -FileName $artifact.Name -ArchiveInfo $archiveInfo
            $jndiInfo = Test-JndiLookupClassPresence -ArchiveInfo $archiveInfo
            $indicatorValues = @($configIndicators | ForEach-Object { $_.Indicators })
            $jms = Test-Log4j1JmsAppenderIndicator -ArchiveInfo $archiveInfo -ConfigIndicators $indicatorValues
            $classification = Get-Log4jVulnerabilityClassification -FileName $artifact.Name -ArchiveInfo $archiveInfo -VersionInfo $versionInfo -JndiInfo $jndiInfo -JmsAppenderPresent $jms -IsNested $false
            if ($SkipArchiveInspection -and $classification.VulnerabilityClassification -eq 'ManualReviewRequired') { $classification.VulnerabilityClassification = 'PartialScan'; $classification.RecommendedAction = 'Archive inspection was skipped; do not treat this as clean.' }
            $hash = ''
            if ($Script:Config.IncludeFileHash -or $IncludeHash) { try { $hash = (Get-FileHash -LiteralPath $artifact.Path -Algorithm SHA256).Hash } catch { $hash = '' } }
            $finding = New-Log4jFindingObject -Target $target -Artifact $artifact -ArchiveInfo $archiveInfo -VersionInfo $versionInfo -Classification $classification -JndiInfo $jndiInfo -JmsAppenderPresent $jms -SHA256 $hash -FailureReason $archiveInfo.FailureReason
            if (@($javaProcesses).Count -gt 0) { $finding.JavaProcessCorrelation = 'Java processes observed; review command lines in operational logs.' }
            if (@($services).Count -gt 0) { $finding.ServiceCorrelation = 'Candidate Java services observed; service ownership not assumed.' }
            $targetFindings += $finding
            if (-not $SkipArchiveInspection) {
                $nestedArtifacts = Find-NestedLog4jArtifacts -ParentPath $artifact.Path -ParentDisplayPath $artifact.OriginalPath -ArchiveInfo $archiveInfo -Config $Script:Config
                foreach ($nested in @($nestedArtifacts)) {
                    $nVersion = Get-Log4jVersionMetadata -FileName $nested.Name -ArchiveInfo $nested.ArchiveInfo
                    $nJndi = Test-JndiLookupClassPresence -ArchiveInfo $nested.ArchiveInfo
                    $nJms = Test-Log4j1JmsAppenderIndicator -ArchiveInfo $nested.ArchiveInfo -ConfigIndicators $indicatorValues
                    $nClass = Get-Log4jVulnerabilityClassification -FileName $nested.Name -ArchiveInfo $nested.ArchiveInfo -VersionInfo $nVersion -JndiInfo $nJndi -JmsAppenderPresent $nJms -IsNested $true
                    $targetFindings += New-Log4jFindingObject -Target $target -Artifact $nested -ArchiveInfo $nested.ArchiveInfo -VersionInfo $nVersion -Classification $nClass -JndiInfo $nJndi -JmsAppenderPresent $nJms
                }
            }
        }
        if ($targetFindings.Count -eq 0) {
            $class = [pscustomobject]@{ DetectionStatus = 'NotDetected'; VulnerabilityClassification = 'NotDetected'; CVEReferences = ''; RecommendedAction = 'No Log4j artifacts detected in completed scan scope.'; Log4jMajorVersion = ''; Log4jCorePresent = $false; Log4jApiOnly = $false }
            $emptyArtifact = [pscustomobject]@{ OriginalPath = ''; Name = ''; Extension = ''; Length = 0; LastWriteTime = ''; ParentArchivePath = ''; NestedArchiveChain = '' }
            $emptyArchive = [pscustomobject]@{ Entries = @(); Metadata = @{}; ReadStatus = 'NotDetected'; FailureReason = '' }
            $targetFindings += New-Log4jFindingObject -Target $target -Artifact $emptyArtifact -ArchiveInfo $emptyArchive -VersionInfo ([pscustomobject]@{Version='';Method='';Confidence=''}) -Classification $class -JndiInfo ([pscustomobject]@{JndiLookupClassPresent=$false;JndiManagerClassPresent=$false}) -JmsAppenderPresent $false
        }
        $findings += $targetFindings
        $scanStatus = 'Scanned'
        if (@($Script:Failures | Where-Object { $_.ServerName -eq $target.ServerName -and $_.Status -match 'Partial|Failed' }).Count -gt 0) { $scanStatus = 'PartialScan' }
        $targetResults += New-Log4jTargetResultObject -Target $target -ConnectivityStatus $conn.Status -ScanStatus $scanStatus -EffectivePaths $effective
        $eligible = @($targetFindings | Where-Object { $_.VulnerabilityClassification -match 'ConfirmedVulnerable|PotentiallyVulnerable|MitigationPresentButUpgradeValidationRequired|VendorUpgradeRequired|ManualReviewRequired|Log4j1' })
        if ($DryRun -or $PreviewRemediation) {
            foreach ($finding in $eligible) {
                $status = 'Preview'
                if ($DryRun) { $status = 'DryRun' }
                $remediationActions += New-RemediationActionObject -Target $target -Finding $finding -ActionType 'EligibilityReview' -ResultStatus $status -Message $finding.RecommendedAction -QuarantinePath (Join-Path $Script:Config.QuarantinePath $target.ServerName) -RollbackMetadataPath 'RollbackMetadata.json would be created before modification.'
            }
        }
        if ($Remediate) {
            if ($ApplyVendorReplacement) { $remediationActions += Invoke-VendorReplacementRemediation -Target $target -Findings $eligible -Manifest $replacementManifest -Config $Script:Config }
            if ($ApplyJndiLookupMitigation) { $remediationActions += Invoke-JndiLookupMitigation -Target $target -Findings $eligible -Config $Script:Config }
        }
    }
    Write-Progress -Activity 'Log4j remediation workflow' -Completed

    $metadata = [pscustomobject]@{
        ReportTitle = 'Log4j Detection and Remediation Report'; RunId = $Script:RunId; RunTimestamp = (Get-Date).ToString('s')
        ExecutionMode = $Script:ExecutionMode; InputSourceMode = $serverInput.InputSourceMode; CollectionMode = $Script:CollectionMode
        ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path; ServerCsvPath = $serverInput.CsvPath
        Domain = $Script:Config.Domain; UserName = $Script:Config.UserName; UseFqdn = $Script:Config.UseFqdn; FqdnSuffix = $Script:Config.FqdnSuffix
        ReportFormats = (@($Script:Config.ReportFormats) -join ','); IncludeNestedArchives = ($Script:Config.IncludeNestedArchives -and $IncludeNestedArchives)
        MaximumNestedArchiveDepth = $Script:Config.MaximumNestedArchiveDepth; IncludeFileHash = ($Script:Config.IncludeFileHash -or $IncludeHash)
        RemediationEnabled = $Script:Config.RemediationEnabled; WhatIfEnabled = $WhatIfPreference; TranscriptPath = $Script:TranscriptPath
    }
    $modulePath = Join-Path $PSScriptRoot 'ReportingTools.psm1'
    Import-Module $modulePath -Force
    $emptyPaths = [pscustomobject]@{ CsvPath = $null; JsonPath = $null; TxtPath = $null; HtmlPath = $null }
    $summary = Get-RemediationSummary -Metadata $metadata -Targets $targetResults -Findings $findings -RemediationActions $remediationActions -Failures $Script:Failures -ReportPaths $emptyPaths
    $reportPaths = Export-ReportBundle -Metadata $metadata -Summary $summary -Targets $targetResults -Findings $findings -RemediationActions $remediationActions -Failures $Script:Failures -OutputPath $Script:Config.OutputPath -ReportFormats $Script:Config.ReportFormats
    $summary = Get-RemediationSummary -Metadata $metadata -Targets $targetResults -Findings $findings -RemediationActions $remediationActions -Failures $Script:Failures -ReportPaths $reportPaths
    Write-RunSummary -Summary $summary
} catch {
    Write-Error $_.Exception.Message
    exit 1
} finally {
    if ($Script:TempRoot -and (Test-Path -LiteralPath $Script:TempRoot)) { try { Remove-Item -LiteralPath $Script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
    Stop-SafeTranscript
}
