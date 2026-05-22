<#
.SYNOPSIS
Detects, reports, and optionally remediates Microsoft MSXML 4 exposure.

.DESCRIPTION
Uses CSV-driven server targeting, externalized configuration, reversible
quarantine-first remediation, and reusable reporting exports to support
enterprise MSXML 4 audit and remediation workflows on Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath 'MSXML4Remediation.config.psd1'),
    [string]$ServerCsvPath,
    [string]$OutputPath,
    [System.Management.Automation.PSCredential]$Credential,
    [string[]]$ReportFormat,
    [switch]$VerboseLogging,
    [switch]$DryRun,
    [switch]$ConnectivityOnly,
    [switch]$PreviewRemediation,
    [switch]$Remediate,
    [switch]$NoWinRM,
    [switch]$UseDcomWmi,
    [switch]$SkipFileSearch,
    [switch]$FullFileSearch,
    [switch]$IncludeHash,
    [int]$TimeoutSeconds,
    [string[]]$LocalDrives,
    [switch]$IncludeAllFixedDrives,
    [string[]]$ExcludeDrives,
    [string[]]$ExcludePaths,
    [string]$QuarantinePath,
    [switch]$RemoveRegistryKeys,
    [switch]$UnregisterDll,
    [switch]$Force
)

Set-StrictMode -Version 2.0

$script:SolutionVersion = '1.0.0'
$script:LogFilePath = $null

function Write-Log {
<#
.SYNOPSIS
Writes a timestamped log entry.

.DESCRIPTION
Emits a timestamped message to the console and to the current log file so that
audit activity, remediation activity, and failures are preserved for review.

.PARAMETER Message
The message to write.

.PARAMETER Level
The message severity level.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $entry

    if ($script:LogFilePath) {
        Add-Content -Path $script:LogFilePath -Value $entry
    }
}

function Get-DefaultCredentialUser {
<#
.SYNOPSIS
Builds the default credential user name.

.DESCRIPTION
Uses the configured domain and username to prepopulate Get-Credential so the
operator does not need to type the full account name each time.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    if ($Configuration.Domain -and $Configuration.Username) {
        return '{0}\{1}' -f $Configuration.Domain, $Configuration.Username
    }

    if ($Configuration.Username) {
        return $Configuration.Username
    }

    if ($env:USERDOMAIN -and $env:USERNAME) {
        return '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    }

    return $env:USERNAME
}

function Resolve-AbsolutePath {
<#
.SYNOPSIS
Resolves relative paths against the script root.

.DESCRIPTION
Converts relative paths from the configuration file into absolute paths so that
scheduled runs, interactive runs, and remote launch methods use the same file
locations consistently.

.PARAMETER Path
The input path to resolve.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath $Path))
}

function Resolve-EffectiveConfiguration {
<#
.SYNOPSIS
Builds the final runtime configuration.

.DESCRIPTION
Loads the PSD1 configuration file, applies command-line overrides, resolves
relative paths, and returns one effective configuration object for the run.

.PARAMETER ConfigPath
The path to the configuration file.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Configuration file not found: $ConfigPath"
    }

    $rawConfig = Import-PowerShellDataFile -Path $ConfigPath
    $effective = [ordered]@{
        Domain                = $rawConfig.Domain
        Username              = $rawConfig.Username
        ServerCsvPath         = Resolve-AbsolutePath -Path $rawConfig.ServerCsvPath
        OutputPath            = Resolve-AbsolutePath -Path $rawConfig.OutputPath
        LogPath               = Resolve-AbsolutePath -Path $rawConfig.LogPath
        UseFqdn               = [bool]$rawConfig.UseFqdn
        FqdnSuffix            = $rawConfig.FqdnSuffix
        ReportFormats         = @($rawConfig.ReportFormats)
        DryRun                = [bool]$rawConfig.DryRun
        PreviewRemediation    = [bool]$rawConfig.PreviewRemediation
        NoWinRM               = [bool]$rawConfig.NoWinRM
        UseDcomWmi            = [bool]$rawConfig.UseDcomWmi
        VerboseLogging        = [bool]$rawConfig.VerboseLogging
        TimeoutSeconds        = [int]$rawConfig.TimeoutSeconds
        SkipFileSearch        = [bool]$rawConfig.SkipFileSearch
        FullFileSearch        = [bool]$rawConfig.FullFileSearch
        IncludeHash           = [bool]$rawConfig.IncludeHash
        UseWin32Product       = [bool]$rawConfig.UseWin32Product
        LocalDrives           = @($rawConfig.LocalDrives)
        IncludeAllFixedDrives = [bool]$rawConfig.IncludeAllFixedDrives
        SearchPaths           = @($rawConfig.SearchPaths)
        ExcludedDrives        = @($rawConfig.ExcludedDrives)
        ExcludedPaths         = @($rawConfig.ExcludedPaths)
        EnableRemediation     = [bool]$rawConfig.EnableRemediation
        QuarantinePath        = $rawConfig.QuarantinePath
        RemoveFiles           = [bool]$rawConfig.RemoveFiles
        UnregisterDll         = [bool]$rawConfig.UnregisterDll
        RemoveRegistryKeys    = [bool]$rawConfig.RemoveRegistryKeys
        CreateRestoreMetadata = [bool]$rawConfig.CreateRestoreMetadata
        RequireConfirmation   = [bool]$rawConfig.RequireConfirmation
    }

    if ($PSBoundParameters.ContainsKey('ServerCsvPath')) { $effective.ServerCsvPath = Resolve-AbsolutePath -Path $ServerCsvPath }
    if ($PSBoundParameters.ContainsKey('OutputPath')) { $effective.OutputPath = Resolve-AbsolutePath -Path $OutputPath }
    if ($PSBoundParameters.ContainsKey('ReportFormat')) { $effective.ReportFormats = @($ReportFormat) }
    if ($PSBoundParameters.ContainsKey('VerboseLogging')) { $effective.VerboseLogging = [bool]$VerboseLogging }
    if ($PSBoundParameters.ContainsKey('DryRun')) { $effective.DryRun = [bool]$DryRun }
    if ($PSBoundParameters.ContainsKey('PreviewRemediation')) { $effective.PreviewRemediation = [bool]$PreviewRemediation }
    if ($PSBoundParameters.ContainsKey('NoWinRM')) { $effective.NoWinRM = [bool]$NoWinRM }
    if ($PSBoundParameters.ContainsKey('UseDcomWmi')) { $effective.UseDcomWmi = [bool]$UseDcomWmi }
    if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) { $effective.TimeoutSeconds = [int]$TimeoutSeconds }
    if ($PSBoundParameters.ContainsKey('SkipFileSearch')) { $effective.SkipFileSearch = [bool]$SkipFileSearch }
    if ($PSBoundParameters.ContainsKey('FullFileSearch')) { $effective.FullFileSearch = [bool]$FullFileSearch }
    if ($PSBoundParameters.ContainsKey('IncludeHash')) { $effective.IncludeHash = [bool]$IncludeHash }
    if ($PSBoundParameters.ContainsKey('LocalDrives')) { $effective.LocalDrives = @($LocalDrives) }
    if ($PSBoundParameters.ContainsKey('IncludeAllFixedDrives')) { $effective.IncludeAllFixedDrives = [bool]$IncludeAllFixedDrives }
    if ($PSBoundParameters.ContainsKey('ExcludeDrives')) { $effective.ExcludedDrives = @($ExcludeDrives) }
    if ($PSBoundParameters.ContainsKey('ExcludePaths')) { $effective.ExcludedPaths = @($ExcludePaths) }
    if ($PSBoundParameters.ContainsKey('QuarantinePath')) { $effective.QuarantinePath = $QuarantinePath }
    if ($PSBoundParameters.ContainsKey('RemoveRegistryKeys')) { $effective.RemoveRegistryKeys = [bool]$RemoveRegistryKeys }
    if ($PSBoundParameters.ContainsKey('UnregisterDll')) { $effective.UnregisterDll = [bool]$UnregisterDll }
    if ($PSBoundParameters.ContainsKey('Remediate')) { $effective.EnableRemediation = [bool]$Remediate }

    $effective.QuarantinePath = Resolve-AbsolutePath -Path $effective.QuarantinePath
    $effective.ExcludedPaths = @($effective.ExcludedPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    return [pscustomobject]$effective
}

function Get-ServerList {
<#
.SYNOPSIS
Loads the target server list from CSV.

.DESCRIPTION
Validates the CSV schema and returns the server names from the required
ServerName column.

.PARAMETER CsvPath
The path to the server CSV file.

.OUTPUTS
System.String[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "Server CSV file not found: $CsvPath"
    }

    $rows = Import-Csv -Path $CsvPath
    $servers = @($rows | ForEach-Object { $_.ServerName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if (-not $servers -or $servers.Count -eq 0) {
        throw "No server names were found in $CsvPath. Ensure the CSV contains a ServerName header."
    }

    return $servers
}

function Resolve-TargetName {
<#
.SYNOPSIS
Resolves the scan target host name.

.DESCRIPTION
Applies the FQDN configuration when needed so that short names can be expanded
without changing the CSV input format.

.PARAMETER ServerName
The server name from the CSV file.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    if ($Configuration.UseFqdn -and $ServerName -notmatch '\.') {
        return '{0}.{1}' -f $ServerName, $Configuration.FqdnSuffix
    }

    return $ServerName
}

function New-ResultRecord {
<#
.SYNOPSIS
Creates a normalized report record.

.DESCRIPTION
Initializes all expected report fields so that every export format receives a
consistent schema regardless of whether the record represents a detection, a
failure, or a clean server.

.PARAMETER Values
The report values to overlay on the default schema.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [hashtable]$Values
    )

    $defaults = [ordered]@{
        ServerName                 = ''
        FQDN                       = ''
        OSCaption                  = ''
        OSVersion                  = ''
        BuildNumber                = ''
        ConnectivityStatus         = ''
        ScanStatus                 = ''
        DetectionStatus            = ''
        VulnerabilityClassification = ''
        RemediationStatus          = ''
        RemediationActionTaken     = ''
        ProductName                = ''
        ProductVersion             = ''
        RegistryPath               = ''
        DLLPath                    = ''
        DLLDrive                   = ''
        DLLVersion                 = ''
        DLLLastModified            = ''
        DLLFileSize                = ''
        DLLSHA256Hash              = ''
        QuarantinePath             = ''
        RollbackMetadataPath       = ''
        DetectionMethod            = ''
        CollectionMode             = ''
        ScannedDrives              = ''
        ExcludedDrives             = ''
        ExcludedPaths              = ''
        FailureReason              = ''
        Notes                      = ''
    }

    foreach ($key in $Values.Keys) {
        $defaults[$key] = $Values[$key]
    }

    return [pscustomobject]$defaults
}

function Get-WmiConnectionParameters {
<#
.SYNOPSIS
Builds a reusable WMI parameter set.

.DESCRIPTION
Returns a hashtable containing common Get-WmiObject parameters so the script
uses consistent credential, computer name, and error handling behavior.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for the connection.

.OUTPUTS
System.Collections.Hashtable
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    return @{
        ComputerName = $ComputerName
        Credential   = $Credential
        ErrorAction  = 'Stop'
    }
}

function Test-ServerConnectivity {
<#
.SYNOPSIS
Performs baseline server connectivity checks.

.DESCRIPTION
Checks ICMP, WinRM, and WMI/DCOM connectivity so that the script can explain
why a server failed and which collection path was available.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    $pingStatus = 'Unavailable'
    $winRmStatus = 'Skipped'
    $wmiStatus = 'Unavailable'

    try {
        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop) {
            $pingStatus = 'Available'
        }
    }
    catch {
        $pingStatus = 'Unavailable'
    }

    if (-not $Configuration.NoWinRM) {
        try {
            Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
            $winRmStatus = 'Available'
        }
        catch {
            $winRmStatus = 'Unavailable'
        }
    }

    try {
        $wmiParams = Get-WmiConnectionParameters -ComputerName $ComputerName -Credential $Credential
        Get-WmiObject @wmiParams -Class Win32_OperatingSystem | Out-Null
        $wmiStatus = 'Available'
    }
    catch {
        $wmiStatus = 'Unavailable'
    }

    $overall = if ($pingStatus -eq 'Available' -or $winRmStatus -eq 'Available' -or $wmiStatus -eq 'Available') { 'Reachable' } else { 'Unreachable' }

    return [pscustomobject]@{
        Ping   = $pingStatus
        WinRM  = $winRmStatus
        WmiDcom = $wmiStatus
        Overall = $overall
    }
}

function Get-RemoteOperatingSystem {
<#
.SYNOPSIS
Collects remote operating system information.

.DESCRIPTION
Retrieves OS caption, version, and build data using WMI first and falls back to
WinRM when WMI is not available.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    try {
        $wmiParams = Get-WmiConnectionParameters -ComputerName $ComputerName -Credential $Credential
        $os = Get-WmiObject @wmiParams -Class Win32_OperatingSystem
        return [pscustomobject]@{
            Caption     = $os.Caption
            Version     = $os.Version
            BuildNumber = $os.BuildNumber
        }
    }
    catch {
        if (-not $Configuration.NoWinRM) {
            try {
                $os = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock {
                    Get-WmiObject -Class Win32_OperatingSystem | Select-Object -First 1 Caption, Version, BuildNumber
                }

                return [pscustomobject]@{
                    Caption     = $os.Caption
                    Version     = $os.Version
                    BuildNumber = $os.BuildNumber
                }
            }
            catch {
                Write-Log -Message ("Unable to retrieve OS details from {0}: {1}" -f $ComputerName, $_.Exception.Message) -Level 'WARN'
            }
        }
    }

    return [pscustomobject]@{
        Caption     = ''
        Version     = ''
        BuildNumber = ''
    }
}

function Convert-RegistryPathToRemoteInfo {
<#
.SYNOPSIS
Converts a PowerShell registry path to remote registry components.

.DESCRIPTION
Translates an HKLM PowerShell path into the numeric hive identifier and subkey
components used by the StdRegProv WMI provider.

.PARAMETER RegistryPath
The registry path to convert.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $normalized = $RegistryPath -replace '^HKLM:\\', ''
    $parent = Split-Path -Path $normalized -Parent
    $leaf = Split-Path -Path $normalized -Leaf

    return [pscustomobject]@{
        Hive   = 2147483650
        SubKey = $normalized
        Parent = $parent
        Leaf   = $leaf
    }
}

function Get-RemoteRegistryProvider {
<#
.SYNOPSIS
Retrieves the remote WMI registry provider.

.DESCRIPTION
Connects to the StdRegProv WMI provider for No-WinRM and DCOM-compatible
registry discovery.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.OUTPUTS
System.Management.ManagementClass
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $wmiParams = Get-WmiConnectionParameters -ComputerName $ComputerName -Credential $Credential
    return Get-WmiObject @wmiParams -Namespace root\default -Class StdRegProv
}

function Test-RemoteRegistryKeyExists {
<#
.SYNOPSIS
Checks whether a remote registry key exists.

.DESCRIPTION
Uses the remote StdRegProv provider to determine whether a specific HKLM key is
present without relying on WinRM.

.PARAMETER RegistryProvider
The remote StdRegProv WMI object.

.PARAMETER RegistryPath
The registry path to test.

.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$RegistryProvider,

        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $info = Convert-RegistryPathToRemoteInfo -RegistryPath $RegistryPath
    $result = $RegistryProvider.EnumKey($info.Hive, $info.Parent)

    if ($result.ReturnValue -ne 0 -or -not $result.sNames) {
        return $false
    }

    return @($result.sNames) -contains $info.Leaf
}

function Get-RemoteRegistryValue {
<#
.SYNOPSIS
Retrieves a string value from the remote registry.

.DESCRIPTION
Reads REG_SZ and expandable string values from the remote HKLM hive for use in
product detection and reporting.

.PARAMETER RegistryProvider
The remote StdRegProv WMI object.

.PARAMETER RegistryPath
The registry path to read.

.PARAMETER ValueName
The value name to retrieve.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$RegistryProvider,

        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [string]$ValueName
    )

    $info = Convert-RegistryPathToRemoteInfo -RegistryPath $RegistryPath
    $value = $RegistryProvider.GetStringValue($info.Hive, $info.SubKey, $ValueName)

    if ($value.ReturnValue -eq 0) {
        return $value.sValue
    }

    $expandValue = $RegistryProvider.GetExpandedStringValue($info.Hive, $info.SubKey, $ValueName)
    if ($expandValue.ReturnValue -eq 0) {
        return $expandValue.sValue
    }

    return $null
}

function Get-RemoteRegistryFindingsWmi {
<#
.SYNOPSIS
Collects MSXML 4 registry findings through WMI.

.DESCRIPTION
Checks the required MSXML4 registry locations and uninstall keys by using
StdRegProv so the script can operate when WinRM is unavailable.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $findings = @()
    $provider = Get-RemoteRegistryProvider -ComputerName $ComputerName -Credential $Credential

    $directPaths = @(
        'HKLM:\Software\Microsoft\MSXML4'
        'HKLM:\Software\WOW6432Node\Microsoft\MSXML4'
    )

    foreach ($path in $directPaths) {
        if (Test-RemoteRegistryKeyExists -RegistryProvider $provider -RegistryPath $path) {
            $findings += [pscustomobject]@{
                FindingType    = 'Registry'
                ProductName    = 'MSXML 4 Registry Key'
                ProductVersion = (Get-RemoteRegistryValue -RegistryProvider $provider -RegistryPath $path -ValueName 'Version')
                RegistryPath   = $path
                DLLPath        = ''
                DLLDrive       = ''
                DLLVersion     = ''
                DLLLastModified = ''
                DLLFileSize    = ''
                DLLSHA256Hash  = ''
                DetectionMethod = 'Registry'
                Notes          = 'Direct MSXML4 registry key detected.'
            }
        }
    }

    $uninstallBases = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($basePath in $uninstallBases) {
        $baseInfo = Convert-RegistryPathToRemoteInfo -RegistryPath $basePath
        $subKeys = $provider.EnumKey($baseInfo.Hive, $baseInfo.SubKey)

        if ($subKeys.ReturnValue -ne 0 -or -not $subKeys.sNames) {
            continue
        }

        foreach ($subKeyName in $subKeys.sNames) {
            $fullPath = '{0}\{1}' -f $basePath, $subKeyName
            $displayName = Get-RemoteRegistryValue -RegistryProvider $provider -RegistryPath $fullPath -ValueName 'DisplayName'
            $displayVersion = Get-RemoteRegistryValue -RegistryProvider $provider -RegistryPath $fullPath -ValueName 'DisplayVersion'
            $uninstallString = Get-RemoteRegistryValue -RegistryProvider $provider -RegistryPath $fullPath -ValueName 'UninstallString'

            if ($displayName -like '*MSXML*4*' -or $uninstallString -like '*msxml4*') {
                $findings += [pscustomobject]@{
                    FindingType     = 'Uninstall'
                    ProductName     = $displayName
                    ProductVersion  = $displayVersion
                    RegistryPath    = $fullPath
                    DLLPath         = ''
                    DLLDrive        = ''
                    DLLVersion      = ''
                    DLLLastModified = ''
                    DLLFileSize     = ''
                    DLLSHA256Hash   = ''
                    DetectionMethod = 'Uninstall'
                    Notes           = 'MSXML 4 uninstall entry detected.'
                }
            }
        }
    }

    return $findings
}

function Get-RemoteRegistryFindingsWinRM {
<#
.SYNOPSIS
Collects MSXML 4 registry findings through WinRM.

.DESCRIPTION
Runs the required registry checks on the remote computer by using the local
registry provider inside a PowerShell remoting session.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $scriptBlock = {
        $findings = @()
        $directPaths = @(
            'HKLM:\Software\Microsoft\MSXML4'
            'HKLM:\Software\WOW6432Node\Microsoft\MSXML4'
        )

        foreach ($path in $directPaths) {
            if (Test-Path -LiteralPath $path) {
                $version = ''
                try {
                    $version = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).Version
                }
                catch {
                    $version = ''
                }

                $findings += [pscustomobject]@{
                    FindingType     = 'Registry'
                    ProductName     = 'MSXML 4 Registry Key'
                    ProductVersion  = $version
                    RegistryPath    = $path
                    DLLPath         = ''
                    DLLDrive        = ''
                    DLLVersion      = ''
                    DLLLastModified = ''
                    DLLFileSize     = ''
                    DLLSHA256Hash   = ''
                    DetectionMethod = 'Registry'
                    Notes           = 'Direct MSXML4 registry key detected.'
                }
            }
        }

        $uninstallBases = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        )

        foreach ($basePath in $uninstallBases) {
            if (-not (Test-Path -LiteralPath $basePath)) {
                continue
            }

            foreach ($subKey in Get-ChildItem -LiteralPath $basePath -ErrorAction SilentlyContinue) {
                try {
                    $entry = Get-ItemProperty -LiteralPath $subKey.PSPath -ErrorAction Stop
                    if ($entry.DisplayName -like '*MSXML*4*' -or $entry.UninstallString -like '*msxml4*') {
                        $findings += [pscustomobject]@{
                            FindingType     = 'Uninstall'
                            ProductName     = $entry.DisplayName
                            ProductVersion  = $entry.DisplayVersion
                            RegistryPath    = $subKey.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM:'
                            DLLPath         = ''
                            DLLDrive        = ''
                            DLLVersion      = ''
                            DLLLastModified = ''
                            DLLFileSize     = ''
                            DLLSHA256Hash   = ''
                            DetectionMethod = 'Uninstall'
                            Notes           = 'MSXML 4 uninstall entry detected.'
                        }
                    }
                }
                catch {
                }
            }
        }

        return $findings
    }

    return Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock $scriptBlock
}

function Get-Win32ProductFindings {
<#
.SYNOPSIS
Collects optional Win32_Product findings.

.DESCRIPTION
Performs the optional MSI inventory check only when explicitly enabled because
Win32_Product can trigger MSI self-repair on some systems.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    if (-not $Configuration.UseWin32Product) {
        return @()
    }

    Write-Log -Message ("Running optional Win32_Product query against {0}. This can trigger MSI validation." -f $ComputerName) -Level 'WARN'

    try {
        $wmiParams = Get-WmiConnectionParameters -ComputerName $ComputerName -Credential $Credential
        $products = Get-WmiObject @wmiParams -Class Win32_Product |
            Where-Object { $_.Name -like '*MSXML*4*' }

        $findings = foreach ($product in $products) {
            [pscustomobject]@{
                FindingType     = 'Win32_Product'
                ProductName     = $product.Name
                ProductVersion  = $product.Version
                RegistryPath    = ''
                DLLPath         = ''
                DLLDrive        = ''
                DLLVersion      = ''
                DLLLastModified = ''
                DLLFileSize     = ''
                DLLSHA256Hash   = ''
                DetectionMethod = 'Win32_Product'
                Notes           = 'Optional Win32_Product result.'
            }
        }

        return @($findings)
    }
    catch {
        Write-Log -Message ("Win32_Product query failed on {0}: {1}" -f $ComputerName, $_.Exception.Message) -Level 'WARN'
        return @()
    }
}

function Test-IsExcludedPath {
<#
.SYNOPSIS
Tests whether a path should be excluded from scanning.

.DESCRIPTION
Applies case-insensitive path prefix matching so that known noisy or risky
locations can be skipped during file discovery.

.PARAMETER Path
The path to evaluate.

.PARAMETER ExcludedPaths
The exclusion list.

.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string[]]$ExcludedPaths
    )

    if (-not $ExcludedPaths) {
        return $false
    }

    $normalizedPath = ($Path -replace '/', '\').ToLowerInvariant().TrimEnd('\')

    foreach ($excludedPath in $ExcludedPaths) {
        $normalizedExcluded = ($excludedPath -replace '/', '\').ToLowerInvariant().TrimEnd('\')
        if ($normalizedPath.StartsWith($normalizedExcluded)) {
            return $true
        }
    }

    return $false
}

function Get-SearchRoots {
<#
.SYNOPSIS
Builds the file search root list.

.DESCRIPTION
Calculates search roots from configured drives and search paths while honoring
full-drive scans, drive exclusions, and absolute path entries.

.PARAMETER Drives
The drive letters to scan.

.PARAMETER SearchPaths
The configured search paths.

.PARAMETER FullFileSearch
Indicates whether every selected drive should be searched recursively.

.PARAMETER ExcludedPaths
The path exclusion list.

.OUTPUTS
System.String[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Drives,

        [Parameter(Mandatory = $true)]
        [string[]]$SearchPaths,

        [bool]$FullFileSearch,

        [string[]]$ExcludedPaths
    )

    $roots = New-Object System.Collections.Generic.List[string]

    foreach ($drive in $Drives) {
        $driveRoot = '{0}:\' -f $drive.TrimEnd(':')

        if ($FullFileSearch) {
            if (-not (Test-IsExcludedPath -Path $driveRoot -ExcludedPaths $ExcludedPaths)) {
                [void]$roots.Add($driveRoot)
            }
            continue
        }

        foreach ($searchPath in $SearchPaths) {
            if ([System.IO.Path]::IsPathRooted($searchPath)) {
                $candidate = $searchPath
            }
            else {
                $candidate = Join-Path -Path $driveRoot -ChildPath $searchPath
            }

            if (-not (Test-IsExcludedPath -Path $candidate -ExcludedPaths $ExcludedPaths)) {
                [void]$roots.Add($candidate)
            }
        }
    }

    return @($roots | Sort-Object -Unique)
}

function Get-Sha256Hash {
<#
.SYNOPSIS
Calculates a SHA256 file hash.

.DESCRIPTION
Uses Get-FileHash when available and falls back to .NET hashing so that the
script remains compatible across supported Windows PowerShell 5.1 systems.

.PARAMETER Path
The file path to hash.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Get-Command -Name Get-FileHash -ErrorAction SilentlyContinue) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $algorithm = New-Object System.Security.Cryptography.SHA256Managed
        $hashBytes = $algorithm.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
    }
    finally {
        $stream.Dispose()
    }
}

function Convert-DrivePathToAdminShare {
<#
.SYNOPSIS
Converts a local drive path to an admin-share mapping descriptor.

.DESCRIPTION
Transforms a path such as C:\Windows\System32 into its corresponding remote
admin-share root and relative path for SMB-based collection and quarantine.

.PARAMETER ComputerName
The target computer.

.PARAMETER LocalPath
The local path on the target computer.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath
    )

    if ($LocalPath -notmatch '^[A-Za-z]:\\') {
        throw "Only drive-letter paths are supported for SMB mapping: $LocalPath"
    }

    $driveLetter = $LocalPath.Substring(0, 1).ToUpperInvariant()
    $relativePath = $LocalPath.Substring(3)
    $shareRoot = '\\{0}\{1}$' -f $ComputerName, $driveLetter

    return [pscustomobject]@{
        DriveLetter  = $driveLetter
        RelativePath = $relativePath
        ShareRoot    = $shareRoot
    }
}

function New-TemporaryRemoteDrive {
<#
.SYNOPSIS
Creates a temporary PSDrive to a remote admin share.

.DESCRIPTION
Uses the supplied credential to mount a remote admin share for No-WinRM file
scanning, quarantine, and metadata handling.

The drive must outlive this helper function call, so it is created in script
scope rather than local function scope. Local scope would remove the PSDrive
before the calling function could use it.

.PARAMETER ShareRoot
The remote admin-share root.

.PARAMETER Credential
The credential used for SMB access.

.OUTPUTS
System.Management.Automation.PSDriveInfo
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareRoot,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $driveName = 'MSX{0}' -f ([System.Guid]::NewGuid().ToString('N').Substring(0, 6).ToUpperInvariant())
    return New-PSDrive -Name $driveName -PSProvider FileSystem -Root $ShareRoot -Credential $Credential -Scope Script -ErrorAction Stop
}

function Remove-TemporaryRemoteDrive {
<#
.SYNOPSIS
Removes a temporary remote PSDrive.

.DESCRIPTION
Cleans up temporary SMB drive mappings created for No-WinRM operations.

.PARAMETER Drive
The PSDrive object to remove.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Drive
    )

    Remove-PSDrive -Name $Drive.Name -Scope Script -Force -ErrorAction SilentlyContinue
}

function Get-RemoteFileFindingsWinRM {
<#
.SYNOPSIS
Collects MSXML4 file findings through WinRM.

.DESCRIPTION
Searches the remote file system from inside a remoting session so that hashes,
versions, timestamps, and path filtering occur on the target server.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER SearchRoots
The root paths to search.

.PARAMETER ExcludedPaths
The path exclusion list.

.PARAMETER IncludeHash
Indicates whether SHA256 hashes should be calculated.

.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string[]]$SearchRoots,

        [string[]]$ExcludedPaths,

        [bool]$IncludeHash
    )

    $scriptBlock = {
        param($Roots, $ExcludeList, $UseHash)

        function Test-IsExcludedPathRemote {
            param([string]$Path, [string[]]$Excluded)
            $normalizedPath = ($Path -replace '/', '\').ToLowerInvariant().TrimEnd('\')
            foreach ($entry in $Excluded) {
                $normalizedEntry = ($entry -replace '/', '\').ToLowerInvariant().TrimEnd('\')
                if ($normalizedPath.StartsWith($normalizedEntry)) {
                    return $true
                }
            }
            return $false
        }

        function Get-HashRemote {
            param([string]$Path)
            if (Get-Command -Name Get-FileHash -ErrorAction SilentlyContinue) {
                return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
            }

            $stream = [System.IO.File]::OpenRead($Path)
            try {
                $algorithm = New-Object System.Security.Cryptography.SHA256Managed
                $bytes = $algorithm.ComputeHash($stream)
                return ([System.BitConverter]::ToString($bytes)).Replace('-', '')
            }
            finally {
                $stream.Dispose()
            }
        }

        $findings = @()
        foreach ($root in $Roots) {
            if (-not (Test-Path -LiteralPath $root)) {
                continue
            }

            foreach ($file in Get-ChildItem -LiteralPath $root -Filter 'msxml4.dll' -File -Recurse -Force -ErrorAction SilentlyContinue) {
                if (Test-IsExcludedPathRemote -Path $file.FullName -Excluded $ExcludeList) {
                    continue
                }

                $hash = ''
                if ($UseHash) {
                    try {
                        $hash = Get-HashRemote -Path $file.FullName
                    }
                    catch {
                        $hash = ''
                    }
                }

                $findings += [pscustomobject]@{
                    FindingType     = 'File'
                    ProductName     = 'MSXML4.dll'
                    ProductVersion  = $file.VersionInfo.ProductVersion
                    RegistryPath    = ''
                    DLLPath         = $file.FullName
                    DLLDrive        = $file.Directory.Root.Name.TrimEnd('\')
                    DLLVersion      = $file.VersionInfo.FileVersion
                    DLLLastModified = $file.LastWriteTime.ToString('s')
                    DLLFileSize     = $file.Length
                    DLLSHA256Hash   = $hash
                    DetectionMethod = 'File'
                    Notes           = 'MSXML4.dll located on disk.'
                }
            }
        }

        return $findings
    }

    return Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock $scriptBlock -ArgumentList (,$SearchRoots), (,$ExcludedPaths), $IncludeHash
}

function Get-RemoteFileFindingsNoWinRM {
<#
.SYNOPSIS
Collects MSXML4 file findings without WinRM.

.DESCRIPTION
Searches remote admin shares over SMB so that environments without WinRM can
still locate MSXML4.dll artifacts when file access is permitted.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER SearchRoots
The root paths to search.

.PARAMETER ExcludedPaths
The path exclusion list.

.PARAMETER IncludeHash
Indicates whether SHA256 hashes should be calculated.

.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string[]]$SearchRoots,

        [string[]]$ExcludedPaths,

        [bool]$IncludeHash
    )

    $findings = @()

    foreach ($root in $SearchRoots) {
        try {
            $rootInfo = Convert-DrivePathToAdminShare -ComputerName $ComputerName -LocalPath $root
            $drive = New-TemporaryRemoteDrive -ShareRoot $rootInfo.ShareRoot -Credential $Credential

            try {
                $mappedRoot = if ($rootInfo.RelativePath) {
                    Join-Path -Path ('{0}:\' -f $drive.Name) -ChildPath $rootInfo.RelativePath
                }
                else {
                    '{0}:\' -f $drive.Name
                }

                if (-not (Test-Path -LiteralPath $mappedRoot)) {
                    continue
                }

                foreach ($file in Get-ChildItem -LiteralPath $mappedRoot -Filter 'msxml4.dll' -File -Recurse -Force -ErrorAction SilentlyContinue) {
                    $mappedPrefix = '{0}:\' -f $drive.Name
                    $relativeFilePath = $file.FullName.Substring($mappedPrefix.Length)
                    $localEquivalent = '{0}:\{1}' -f $rootInfo.DriveLetter, $relativeFilePath
                    if (Test-IsExcludedPath -Path $localEquivalent -ExcludedPaths $ExcludedPaths) {
                        continue
                    }

                    $hash = ''
                    if ($IncludeHash) {
                        try {
                            $hash = Get-Sha256Hash -Path $file.FullName
                        }
                        catch {
                            $hash = ''
                        }
                    }

                    $findings += [pscustomobject]@{
                        FindingType     = 'File'
                        ProductName     = 'MSXML4.dll'
                        ProductVersion  = $file.VersionInfo.ProductVersion
                        RegistryPath    = ''
                        DLLPath         = $localEquivalent
                        DLLDrive        = $rootInfo.DriveLetter
                        DLLVersion      = $file.VersionInfo.FileVersion
                        DLLLastModified = $file.LastWriteTime.ToString('s')
                        DLLFileSize     = $file.Length
                        DLLSHA256Hash   = $hash
                        DetectionMethod = 'File'
                        Notes           = 'MSXML4.dll located through SMB/admin share scan.'
                    }
                }
            }
            finally {
                Remove-TemporaryRemoteDrive -Drive $drive
            }
        }
        catch {
            Write-Log -Message ("File search root {0} on {1} could not be scanned: {2}" -f $root, $ComputerName, $_.Exception.Message) -Level 'WARN'
        }
    }

    return $findings
}

function Get-RemoteFixedDrives {
<#
.SYNOPSIS
Retrieves remote fixed drives.

.DESCRIPTION
Collects fixed drive letters for full-drive searches while supporting both WMI
and WinRM collection paths.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.String[]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    try {
        $wmiParams = Get-WmiConnectionParameters -ComputerName $ComputerName -Credential $Credential
        $drives = Get-WmiObject @wmiParams -Class Win32_LogicalDisk -Filter 'DriveType = 3' |
            Select-Object -ExpandProperty DeviceID
    }
    catch {
        if ($Configuration.NoWinRM) {
            throw
        }

        $drives = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock {
            Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType = 3' | Select-Object -ExpandProperty DeviceID
        }
    }

    return @($drives | ForEach-Object { $_.TrimEnd(':') } | Sort-Object -Unique)
}

function Get-MSXML4FindingsForServer {
<#
.SYNOPSIS
Collects all MSXML4 findings for one server.

.DESCRIPTION
Combines connectivity checks, operating system metadata, registry detection,
optional MSI detection, and file search results into report-ready records.

.PARAMETER ServerName
The server name from the CSV.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    $computerName = Resolve-TargetName -ServerName $ServerName -Configuration $Configuration
    $collectionMode = if ($Configuration.NoWinRM) { 'NoWinRM/DCOM/SMB' } else { 'WinRMPreferred' }
    $connectivity = Test-ServerConnectivity -ComputerName $computerName -Credential $Credential -Configuration $Configuration
    $osInfo = Get-RemoteOperatingSystem -ComputerName $computerName -Credential $Credential -Configuration $Configuration

    if ($connectivity.Overall -eq 'Unreachable') {
        return [pscustomobject]@{
            ServerName   = $ServerName
            ComputerName = $computerName
            OSInfo       = $osInfo
            Connectivity = $connectivity
            Findings     = @()
            ReportRecords = @(
                (New-ResultRecord -Values @{
                    ServerName                  = $ServerName
                    FQDN                        = $computerName
                    OSCaption                   = $osInfo.Caption
                    OSVersion                   = $osInfo.Version
                    BuildNumber                 = $osInfo.BuildNumber
                    ConnectivityStatus          = $connectivity.Overall
                    ScanStatus                  = 'Failed'
                    DetectionStatus             = 'Unknown'
                    VulnerabilityClassification = 'ConnectivityFailure'
                    RemediationStatus           = 'NotAttempted'
                    RemediationActionTaken      = 'None'
                    CollectionMode              = $collectionMode
                    FailureReason               = 'Server was unreachable over ping, WinRM, and WMI/DCOM.'
                    Notes                       = ('Ping={0}; WinRM={1}; WMI/DCOM={2}' -f $connectivity.Ping, $connectivity.WinRM, $connectivity.WmiDcom)
                })
            )
            ScannedDrives = @()
        }
    }

    $drives = if ($Configuration.IncludeAllFixedDrives) {
        try {
            Get-RemoteFixedDrives -ComputerName $computerName -Credential $Credential -Configuration $Configuration
        }
        catch {
            Write-Log -Message ("Unable to enumerate fixed drives on {0}. Falling back to configured LocalDrives. {1}" -f $computerName, $_.Exception.Message) -Level 'WARN'
            @($Configuration.LocalDrives)
        }
    }
    else {
        @($Configuration.LocalDrives)
    }

    $drives = @($drives | Where-Object { $_ -and @($Configuration.ExcludedDrives) -notcontains $_ } | Sort-Object -Unique)
    $findings = @()

    try {
        if ($Configuration.NoWinRM -or $Configuration.UseDcomWmi -or $connectivity.WinRM -ne 'Available') {
            $findings += Get-RemoteRegistryFindingsWmi -ComputerName $computerName -Credential $Credential
        }
        else {
            $findings += Get-RemoteRegistryFindingsWinRM -ComputerName $computerName -Credential $Credential
        }
    }
    catch {
        Write-Log -Message ("Registry detection failed on {0}: {1}" -f $computerName, $_.Exception.Message) -Level 'WARN'
    }

    $findings += Get-Win32ProductFindings -ComputerName $computerName -Credential $Credential -Configuration $Configuration

    if (-not $Configuration.SkipFileSearch) {
        $searchRoots = Get-SearchRoots -Drives $drives -SearchPaths $Configuration.SearchPaths -FullFileSearch $Configuration.FullFileSearch -ExcludedPaths $Configuration.ExcludedPaths
        try {
            if ($Configuration.NoWinRM -or $Configuration.UseDcomWmi -or $connectivity.WinRM -ne 'Available') {
                $findings += Get-RemoteFileFindingsNoWinRM -ComputerName $computerName -Credential $Credential -SearchRoots $searchRoots -ExcludedPaths $Configuration.ExcludedPaths -IncludeHash $Configuration.IncludeHash
            }
            else {
                $findings += Get-RemoteFileFindingsWinRM -ComputerName $computerName -Credential $Credential -SearchRoots $searchRoots -ExcludedPaths $Configuration.ExcludedPaths -IncludeHash $Configuration.IncludeHash
            }
        }
        catch {
            Write-Log -Message ("File detection failed on {0}: {1}" -f $computerName, $_.Exception.Message) -Level 'WARN'
        }
    }

    $reportRecords = @()

    if ($ConnectivityOnly) {
        $reportRecords += New-ResultRecord -Values @{
            ServerName                  = $ServerName
            FQDN                        = $computerName
            OSCaption                   = $osInfo.Caption
            OSVersion                   = $osInfo.Version
            BuildNumber                 = $osInfo.BuildNumber
            ConnectivityStatus          = $connectivity.Overall
            ScanStatus                  = 'ConnectivityOnly'
            DetectionStatus             = 'NotScanned'
            VulnerabilityClassification = 'ConnectivityValidationOnly'
            RemediationStatus           = 'NotRequested'
            RemediationActionTaken      = 'None'
            CollectionMode              = $collectionMode
            ScannedDrives               = ($drives -join ';')
            ExcludedDrives              = ($Configuration.ExcludedDrives -join ';')
            ExcludedPaths               = ($Configuration.ExcludedPaths -join ';')
            Notes                       = ('Ping={0}; WinRM={1}; WMI/DCOM={2}' -f $connectivity.Ping, $connectivity.WinRM, $connectivity.WmiDcom)
        }
    }
    elseif ($findings.Count -eq 0) {
        $reportRecords += New-ResultRecord -Values @{
            ServerName                  = $ServerName
            FQDN                        = $computerName
            OSCaption                   = $osInfo.Caption
            OSVersion                   = $osInfo.Version
            BuildNumber                 = $osInfo.BuildNumber
            ConnectivityStatus          = $connectivity.Overall
            ScanStatus                  = 'Completed'
            DetectionStatus             = 'NotDetected'
            VulnerabilityClassification = 'NoExposureDetected'
            RemediationStatus           = 'NotRequested'
            RemediationActionTaken      = 'None'
            CollectionMode              = $collectionMode
            ScannedDrives               = ($drives -join ';')
            ExcludedDrives              = ($Configuration.ExcludedDrives -join ';')
            ExcludedPaths               = ($Configuration.ExcludedPaths -join ';')
            Notes                       = 'No MSXML4 file, uninstall entry, or direct registry key was detected.'
        }
    }
    else {
        foreach ($finding in $findings) {
            $classification = if ($finding.FindingType -eq 'File') { 'ConfirmedExposure' } else { 'ExposureOrRemnantDetected' }

            $reportRecords += New-ResultRecord -Values @{
                ServerName                  = $ServerName
                FQDN                        = $computerName
                OSCaption                   = $osInfo.Caption
                OSVersion                   = $osInfo.Version
                BuildNumber                 = $osInfo.BuildNumber
                ConnectivityStatus          = $connectivity.Overall
                ScanStatus                  = 'Completed'
                DetectionStatus             = 'Detected'
                VulnerabilityClassification = $classification
                RemediationStatus           = 'NotRequested'
                RemediationActionTaken      = 'None'
                ProductName                 = $finding.ProductName
                ProductVersion              = $finding.ProductVersion
                RegistryPath                = $finding.RegistryPath
                DLLPath                     = $finding.DLLPath
                DLLDrive                    = $finding.DLLDrive
                DLLVersion                  = $finding.DLLVersion
                DLLLastModified             = $finding.DLLLastModified
                DLLFileSize                 = $finding.DLLFileSize
                DLLSHA256Hash               = $finding.DLLSHA256Hash
                DetectionMethod             = $finding.DetectionMethod
                CollectionMode              = $collectionMode
                ScannedDrives               = ($drives -join ';')
                ExcludedDrives              = ($Configuration.ExcludedDrives -join ';')
                ExcludedPaths               = ($Configuration.ExcludedPaths -join ';')
                Notes                       = $finding.Notes
            }
        }
    }

    return [pscustomobject]@{
        ServerName    = $ServerName
        ComputerName  = $computerName
        OSInfo        = $osInfo
        Connectivity  = $connectivity
        Findings      = @($findings)
        ReportRecords = @($reportRecords)
        ScannedDrives = @($drives)
    }
}

function Get-RemediationCandidates {
<#
.SYNOPSIS
Builds the remediation candidate list for a server.

.DESCRIPTION
Extracts unique file paths and registry paths from server findings so that
preview and remediation steps operate on a predictable target set.

.PARAMETER Findings
The raw findings collected for a server.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [object[]]$Findings
    )

    return [pscustomobject]@{
        FilePaths     = @($Findings | Where-Object { $_.DLLPath } | Select-Object -ExpandProperty DLLPath -Unique)
        RegistryPaths = @($Findings | Where-Object { $_.RegistryPath } | Select-Object -ExpandProperty RegistryPath -Unique)
    }
}

function Confirm-RemediationStart {
<#
.SYNOPSIS
Prompts for a remediation confirmation.

.DESCRIPTION
Provides an operator confirmation gate before any system-changing action runs
unless the operator explicitly bypasses the prompt with -Force.

.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param()

    $response = Read-Host 'Remediation is enabled and will quarantine files and optionally remove registry keys. Type YES to continue'
    return $response -eq 'YES'
}

function Invoke-RemoteProcessWmi {
<#
.SYNOPSIS
Runs a remote process through WMI.

.DESCRIPTION
Starts a process on the target computer using Win32_Process.Create and polls
for completion. This provides a No-WinRM execution path for registry export,
registry deletion, and DLL unregister operations.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER CommandLine
The command line to execute.

.PARAMETER TimeoutSeconds
The maximum time to wait for completion.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$CommandLine,

        [int]$TimeoutSeconds = 45
    )

    $wmiParams = Get-WmiConnectionParameters -ComputerName $ComputerName -Credential $Credential
    $createResult = Invoke-WmiMethod @wmiParams -Class Win32_Process -Name Create -ArgumentList $CommandLine

    if ($createResult.ReturnValue -ne 0) {
        throw "Remote process creation failed with return value $($createResult.ReturnValue)."
    }

    $processId = $createResult.ProcessId
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    do {
        Start-Sleep -Seconds 1
        $wmiParams = Get-WmiConnectionParameters -ComputerName $ComputerName -Credential $Credential
        $process = Get-WmiObject @wmiParams -Class Win32_Process -Filter ("ProcessId = {0}" -f $processId) -ErrorAction SilentlyContinue
    } while ($process -and $stopWatch.Elapsed.TotalSeconds -lt $TimeoutSeconds)

    return [pscustomobject]@{
        ProcessId = $processId
        TimedOut  = [bool]$process
    }
}

function Ensure-RemoteDirectoryNoWinRM {
<#
.SYNOPSIS
Creates a directory on the target server over SMB.

.DESCRIPTION
Uses an admin-share mapping to create the quarantine and metadata folder
structure when WinRM is not being used.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for SMB access.

.PARAMETER LocalPath
The local path on the target server to create.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath
    )

    $pathInfo = Convert-DrivePathToAdminShare -ComputerName $ComputerName -LocalPath $LocalPath
    $drive = New-TemporaryRemoteDrive -ShareRoot $pathInfo.ShareRoot -Credential $Credential

    try {
        $mappedPath = if ($pathInfo.RelativePath) {
            Join-Path -Path ('{0}:\' -f $drive.Name) -ChildPath $pathInfo.RelativePath
        }
        else {
            '{0}:\' -f $drive.Name
        }

        if (-not (Test-Path -LiteralPath $mappedPath)) {
            New-Item -Path $mappedPath -ItemType Directory -Force | Out-Null
        }
    }
    finally {
        Remove-TemporaryRemoteDrive -Drive $drive
    }
}

function Export-RemoteRegistryKeyNoWinRM {
<#
.SYNOPSIS
Exports a remote registry key without WinRM.

.DESCRIPTION
Uses reg.exe through a WMI-created process so that rollback data is preserved
before registry deletion in DCOM-only environments.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER RegistryPath
The registry path to export.

.PARAMETER DestinationPath
The export file path on the target server.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $nativePath = $RegistryPath -replace '^HKLM:\\', 'HKLM\'
    $command = 'cmd.exe /c reg.exe export "{0}" "{1}" /y' -f $nativePath, $DestinationPath
    Invoke-RemoteProcessWmi -ComputerName $ComputerName -Credential $Credential -CommandLine $command | Out-Null
}

function Remove-RemoteRegistryKeyNoWinRM {
<#
.SYNOPSIS
Deletes a remote registry key without WinRM.

.DESCRIPTION
Runs reg.exe delete through WMI after rollback exports have been captured.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER RegistryPath
The registry path to delete.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    $nativePath = $RegistryPath -replace '^HKLM:\\', 'HKLM\'
    $command = 'cmd.exe /c reg.exe delete "{0}" /f' -f $nativePath
    Invoke-RemoteProcessWmi -ComputerName $ComputerName -Credential $Credential -CommandLine $command | Out-Null
}

function Unregister-RemoteDllNoWinRM {
<#
.SYNOPSIS
Unregisters a DLL without WinRM.

.DESCRIPTION
Invokes regsvr32 silently through WMI so that DCOM-only remediation can attempt
to unregister MSXML4.dll before quarantine.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER DllPath
The DLL path to unregister.

.PARAMETER TimeoutSeconds
The maximum time to wait.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$DllPath,

        [int]$TimeoutSeconds = 45
    )

    $regsvrPath = if ($DllPath -like '*SysWOW64*') {
        'C:\Windows\SysWOW64\regsvr32.exe'
    }
    else {
        'C:\Windows\System32\regsvr32.exe'
    }

    $command = 'cmd.exe /c ""{0}" /u /s "{1}""' -f $regsvrPath, $DllPath
    Invoke-RemoteProcessWmi -ComputerName $ComputerName -Credential $Credential -CommandLine $command -TimeoutSeconds $TimeoutSeconds | Out-Null
}

function Set-RemoteTextFileNoWinRM {
<#
.SYNOPSIS
Writes a text file to the target server over SMB.

.DESCRIPTION
Uses a temporary admin-share mapping to write metadata and rollback artifacts
without requiring WinRM.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for SMB access.

.PARAMETER LocalPath
The target file path on the remote computer.

.PARAMETER Content
The text content to write.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $pathInfo = Convert-DrivePathToAdminShare -ComputerName $ComputerName -LocalPath $LocalPath
    $drive = New-TemporaryRemoteDrive -ShareRoot $pathInfo.ShareRoot -Credential $Credential

    try {
        $mappedPath = Join-Path -Path ('{0}:\' -f $drive.Name) -ChildPath $pathInfo.RelativePath
        $parentPath = Split-Path -Path $mappedPath -Parent
        if (-not (Test-Path -LiteralPath $parentPath)) {
            New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
        }

        Set-Content -Path $mappedPath -Value $Content -Encoding UTF8
    }
    finally {
        Remove-TemporaryRemoteDrive -Drive $drive
    }
}

function Move-RemoteFileToQuarantineNoWinRM {
<#
.SYNOPSIS
Moves a remote file into quarantine without WinRM.

.DESCRIPTION
Copies file metadata, preserves hashes, and moves the original DLL into the
configured quarantine structure by using remote admin shares.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for SMB access.

.PARAMETER FilePath
The original file path on the target server.

.PARAMETER QuarantineFilesPath
The Files quarantine folder on the target server.

.PARAMETER IncludeHash
Indicates whether a SHA256 hash should be calculated.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$QuarantineFilesPath,

        [bool]$IncludeHash
    )

    $sourceInfo = Convert-DrivePathToAdminShare -ComputerName $ComputerName -LocalPath $FilePath
    $destinationName = (($FilePath -replace '[:\\]', '_').Trim('_'))
    $destinationLocalPath = Join-Path -Path $QuarantineFilesPath -ChildPath $destinationName
    $destinationInfo = Convert-DrivePathToAdminShare -ComputerName $ComputerName -LocalPath $destinationLocalPath

    $sourceDrive = New-TemporaryRemoteDrive -ShareRoot $sourceInfo.ShareRoot -Credential $Credential
    $destinationDrive = New-TemporaryRemoteDrive -ShareRoot $destinationInfo.ShareRoot -Credential $Credential

    try {
        $sourceMappedPath = Join-Path -Path ('{0}:\' -f $sourceDrive.Name) -ChildPath $sourceInfo.RelativePath
        $destinationMappedPath = Join-Path -Path ('{0}:\' -f $destinationDrive.Name) -ChildPath $destinationInfo.RelativePath
        $destinationParent = Split-Path -Path $destinationMappedPath -Parent

        if (-not (Test-Path -LiteralPath $destinationParent)) {
            New-Item -Path $destinationParent -ItemType Directory -Force | Out-Null
        }

        $item = Get-Item -LiteralPath $sourceMappedPath -ErrorAction Stop
        $hash = ''
        if ($IncludeHash) {
            try {
                $hash = Get-Sha256Hash -Path $sourceMappedPath
            }
            catch {
                $hash = ''
            }
        }

        Move-Item -LiteralPath $sourceMappedPath -Destination $destinationMappedPath -Force

        return [pscustomobject]@{
            OriginalPath = $FilePath
            QuarantinePath = $destinationLocalPath
            FileVersion  = $item.VersionInfo.FileVersion
            ProductVersion = $item.VersionInfo.ProductVersion
            LastModified = $item.LastWriteTime.ToString('s')
            FileSize     = $item.Length
            SHA256       = $hash
        }
    }
    finally {
        Remove-TemporaryRemoteDrive -Drive $sourceDrive
        Remove-TemporaryRemoteDrive -Drive $destinationDrive
    }
}

function Invoke-WinRMRemediation {
<#
.SYNOPSIS
Performs remediation through WinRM.

.DESCRIPTION
Runs quarantine, registry export, optional registry deletion, optional DLL
unregister, and rollback metadata generation on the remote server inside one
remoting session.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Candidates
The candidate files and registry paths.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Candidates,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    $scriptBlock = {
        param($CandidateData, $ConfigData, $OperatorName)

        function Get-HashLocal {
            param([string]$Path)
            if (Get-Command -Name Get-FileHash -ErrorAction SilentlyContinue) {
                return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
            }

            $stream = [System.IO.File]::OpenRead($Path)
            try {
                $algorithm = New-Object System.Security.Cryptography.SHA256Managed
                $bytes = $algorithm.ComputeHash($stream)
                return ([System.BitConverter]::ToString($bytes)).Replace('-', '')
            }
            finally {
                $stream.Dispose()
            }
        }

        $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $sessionRoot = Join-Path -Path $ConfigData.QuarantinePath -ChildPath $env:COMPUTERNAME
        $sessionRoot = Join-Path -Path $sessionRoot -ChildPath $timestamp
        $filesRoot = Join-Path -Path $sessionRoot -ChildPath 'Files'
        $registryRoot = Join-Path -Path $sessionRoot -ChildPath 'Registry'

        New-Item -Path $filesRoot -ItemType Directory -Force | Out-Null
        New-Item -Path $registryRoot -ItemType Directory -Force | Out-Null

        $actions = New-Object System.Collections.Generic.List[object]

        foreach ($filePath in @($CandidateData.FilePaths | Sort-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $filePath)) {
                $actions.Add([pscustomobject]@{
                    Action = 'QuarantineFile'
                    Target = $filePath
                    Status = 'Skipped'
                    Details = 'File no longer exists.'
                }) | Out-Null
                continue
            }

            try {
                $fileItem = Get-Item -LiteralPath $filePath -ErrorAction Stop
                $hash = ''
                if ($ConfigData.IncludeHash) {
                    try {
                        $hash = Get-HashLocal -Path $filePath
                    }
                    catch {
                        $hash = ''
                    }
                }

                if ($ConfigData.UnregisterDll) {
                    $regsvrPath = if ($filePath -like '*SysWOW64*') { 'C:\Windows\SysWOW64\regsvr32.exe' } else { 'C:\Windows\System32\regsvr32.exe' }
                    Start-Process -FilePath $regsvrPath -ArgumentList ('/u /s "{0}"' -f $filePath) -Wait -WindowStyle Hidden
                }

                $destinationName = (($filePath -replace '[:\\]', '_').Trim('_'))
                $destinationPath = Join-Path -Path $filesRoot -ChildPath $destinationName
                Move-Item -LiteralPath $filePath -Destination $destinationPath -Force

                $actions.Add([pscustomobject]@{
                    Action = 'QuarantineFile'
                    Target = $filePath
                    Status = 'Success'
                    Details = [pscustomobject]@{
                        QuarantinePath = $destinationPath
                        FileVersion = $fileItem.VersionInfo.FileVersion
                        ProductVersion = $fileItem.VersionInfo.ProductVersion
                        LastModified = $fileItem.LastWriteTime.ToString('s')
                        FileSize = $fileItem.Length
                        SHA256 = $hash
                    }
                }) | Out-Null
            }
            catch {
                $actions.Add([pscustomobject]@{
                    Action = 'QuarantineFile'
                    Target = $filePath
                    Status = 'Failed'
                    Details = $_.Exception.Message
                }) | Out-Null
            }
        }

        foreach ($registryPath in @($CandidateData.RegistryPaths | Sort-Object -Unique)) {
            try {
                $nativePath = $registryPath -replace '^HKLM:\\', 'HKLM\'
                $exportName = (($nativePath -replace '[\\/:*?"<>|]', '_').Trim('_')) + '.reg'
                $exportPath = Join-Path -Path $registryRoot -ChildPath $exportName
                & reg.exe export $nativePath $exportPath /y | Out-Null

                if ($ConfigData.RemoveRegistryKeys) {
                    Remove-Item -LiteralPath $registryPath -Recurse -Force -ErrorAction Stop
                }

                $actions.Add([pscustomobject]@{
                    Action = 'RegistryBackup'
                    Target = $registryPath
                    Status = 'Success'
                    Details = [pscustomobject]@{
                        ExportPath = $exportPath
                        Removed = [bool]$ConfigData.RemoveRegistryKeys
                    }
                }) | Out-Null
            }
            catch {
                $actions.Add([pscustomobject]@{
                    Action = 'RegistryBackup'
                    Target = $registryPath
                    Status = 'Failed'
                    Details = $_.Exception.Message
                }) | Out-Null
            }
        }

        $metadataPath = Join-Path -Path $sessionRoot -ChildPath 'Metadata.json'
        if ($ConfigData.CreateRestoreMetadata) {
            $metadata = [pscustomobject]@{
                ServerName           = $env:COMPUTERNAME
                RemediationTimestamp = (Get-Date).ToString('s')
                PerformedBy          = $OperatorName
                QuarantineRoot       = $sessionRoot
                FileActions          = @($actions | Where-Object { $_.Action -eq 'QuarantineFile' })
                RegistryActions      = @($actions | Where-Object { $_.Action -eq 'RegistryBackup' })
            }

            $metadata | ConvertTo-Json -Depth 8 | Set-Content -Path $metadataPath -Encoding UTF8
        }

        return [pscustomobject]@{
            QuarantinePath       = $sessionRoot
            RollbackMetadataPath = $metadataPath
            Actions              = @($actions)
        }
    }

    return Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock $scriptBlock -ArgumentList $Candidates, $Configuration, $Credential.UserName
}

function Invoke-NoWinRMRemediation {
<#
.SYNOPSIS
Performs remediation without WinRM.

.DESCRIPTION
Uses SMB admin shares and WMI remote process execution to quarantine files,
export registry keys, optionally unregister DLLs, optionally delete registry
keys, and write rollback metadata.

.PARAMETER ComputerName
The target computer.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Candidates
The candidate files and registry paths.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Candidates,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $sessionRoot = Join-Path -Path $Configuration.QuarantinePath -ChildPath $ComputerName
    $sessionRoot = Join-Path -Path $sessionRoot -ChildPath $timestamp
    $filesRoot = Join-Path -Path $sessionRoot -ChildPath 'Files'
    $registryRoot = Join-Path -Path $sessionRoot -ChildPath 'Registry'

    Ensure-RemoteDirectoryNoWinRM -ComputerName $ComputerName -Credential $Credential -LocalPath $filesRoot
    Ensure-RemoteDirectoryNoWinRM -ComputerName $ComputerName -Credential $Credential -LocalPath $registryRoot

    $actions = New-Object System.Collections.Generic.List[object]

    foreach ($filePath in @($Candidates.FilePaths | Sort-Object -Unique)) {
        try {
            if ($Configuration.UnregisterDll) {
                Unregister-RemoteDllNoWinRM -ComputerName $ComputerName -Credential $Credential -DllPath $filePath -TimeoutSeconds $Configuration.TimeoutSeconds
            }

            $fileResult = Move-RemoteFileToQuarantineNoWinRM -ComputerName $ComputerName -Credential $Credential -FilePath $filePath -QuarantineFilesPath $filesRoot -IncludeHash $Configuration.IncludeHash
            $actions.Add([pscustomobject]@{
                Action = 'QuarantineFile'
                Target = $filePath
                Status = 'Success'
                Details = $fileResult
            }) | Out-Null
        }
        catch {
            $actions.Add([pscustomobject]@{
                Action = 'QuarantineFile'
                Target = $filePath
                Status = 'Failed'
                Details = $_.Exception.Message
            }) | Out-Null
        }
    }

    foreach ($registryPath in @($Candidates.RegistryPaths | Sort-Object -Unique)) {
        $nativePath = $registryPath -replace '^HKLM:\\', 'HKLM\'
        $exportName = (($nativePath -replace '[\\/:*?"<>|]', '_').Trim('_')) + '.reg'
        $exportPath = Join-Path -Path $registryRoot -ChildPath $exportName

        try {
            Export-RemoteRegistryKeyNoWinRM -ComputerName $ComputerName -Credential $Credential -RegistryPath $registryPath -DestinationPath $exportPath
            if ($Configuration.RemoveRegistryKeys) {
                Remove-RemoteRegistryKeyNoWinRM -ComputerName $ComputerName -Credential $Credential -RegistryPath $registryPath
            }

            $actions.Add([pscustomobject]@{
                Action = 'RegistryBackup'
                Target = $registryPath
                Status = 'Success'
                Details = [pscustomobject]@{
                    ExportPath = $exportPath
                    Removed = [bool]$Configuration.RemoveRegistryKeys
                }
            }) | Out-Null
        }
        catch {
            $actions.Add([pscustomobject]@{
                Action = 'RegistryBackup'
                Target = $registryPath
                Status = 'Failed'
                Details = $_.Exception.Message
            }) | Out-Null
        }
    }

    $metadataPath = Join-Path -Path $sessionRoot -ChildPath 'Metadata.json'
    if ($Configuration.CreateRestoreMetadata) {
        $metadata = [pscustomobject]@{
            ServerName           = $ComputerName
            RemediationTimestamp = (Get-Date).ToString('s')
            PerformedBy          = $Credential.UserName
            QuarantineRoot       = $sessionRoot
            FileActions          = @($actions | Where-Object { $_.Action -eq 'QuarantineFile' })
            RegistryActions      = @($actions | Where-Object { $_.Action -eq 'RegistryBackup' })
        }

        Set-RemoteTextFileNoWinRM -ComputerName $ComputerName -Credential $Credential -LocalPath $metadataPath -Content ($metadata | ConvertTo-Json -Depth 8)
    }

    return [pscustomobject]@{
        QuarantinePath       = $sessionRoot
        RollbackMetadataPath = $metadataPath
        Actions              = @($actions)
    }
}

function Invoke-ServerRemediation {
<#
.SYNOPSIS
Determines and executes the server remediation mode.

.DESCRIPTION
Honors audit-only, dry-run, preview, and approved remediation modes while
ensuring that no changes occur unless remediation is explicitly enabled.

.PARAMETER ServerResult
The server scan result object.

.PARAMETER Credential
The credential used for remote access.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ServerResult,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    $candidates = Get-RemediationCandidates -Findings $ServerResult.Findings

    if (($candidates.FilePaths.Count + $candidates.RegistryPaths.Count) -eq 0) {
        return [pscustomobject]@{
            Status               = 'NotRequired'
            ActionTaken          = 'No remediable artifacts detected.'
            QuarantinePath       = ''
            RollbackMetadataPath = ''
            FailureReason        = ''
            Actions              = @()
        }
    }

    if ($ConnectivityOnly) {
        return [pscustomobject]@{
            Status               = 'NotRequested'
            ActionTaken          = 'Connectivity-only mode did not evaluate remediation.'
            QuarantinePath       = ''
            RollbackMetadataPath = ''
            FailureReason        = ''
            Actions              = @()
        }
    }

    if ($Configuration.DryRun) {
        return [pscustomobject]@{
            Status               = 'DryRun'
            ActionTaken          = ('Would quarantine {0} file(s) and back up {1} registry key(s).' -f $candidates.FilePaths.Count, $candidates.RegistryPaths.Count)
            QuarantinePath       = ''
            RollbackMetadataPath = ''
            FailureReason        = ''
            Actions              = @()
        }
    }

    if ($Configuration.PreviewRemediation) {
        return [pscustomobject]@{
            Status               = 'PreviewOnly'
            ActionTaken          = ('Preview generated for {0} file(s) and {1} registry key(s).' -f $candidates.FilePaths.Count, $candidates.RegistryPaths.Count)
            QuarantinePath       = ''
            RollbackMetadataPath = ''
            FailureReason        = ''
            Actions              = @()
        }
    }

    if (-not $Configuration.EnableRemediation) {
        return [pscustomobject]@{
            Status               = 'NotRequested'
            ActionTaken          = 'Audit-only mode.'
            QuarantinePath       = ''
            RollbackMetadataPath = ''
            FailureReason        = ''
            Actions              = @()
        }
    }

    try {
        $executionResult = if ($Configuration.NoWinRM -or $Configuration.UseDcomWmi -or $ServerResult.Connectivity.WinRM -ne 'Available') {
            Invoke-NoWinRMRemediation -ComputerName $ServerResult.ComputerName -Credential $Credential -Candidates $candidates -Configuration $Configuration
        }
        else {
            Invoke-WinRMRemediation -ComputerName $ServerResult.ComputerName -Credential $Credential -Candidates $candidates -Configuration $Configuration
        }

        $failedActions = @($executionResult.Actions | Where-Object { $_.Status -eq 'Failed' })
        $status = if ($failedActions.Count -eq 0) { 'Remediated' } else { 'Partial' }

        return [pscustomobject]@{
            Status               = $status
            ActionTaken          = ('Quarantined {0} file artifact(s); processed {1} registry artifact(s).' -f $candidates.FilePaths.Count, $candidates.RegistryPaths.Count)
            QuarantinePath       = $executionResult.QuarantinePath
            RollbackMetadataPath = $executionResult.RollbackMetadataPath
            FailureReason        = if ($failedActions.Count -gt 0) { 'One or more remediation steps failed. Review Metadata.json and the log file.' } else { '' }
            Actions              = @($executionResult.Actions)
        }
    }
    catch {
        return [pscustomobject]@{
            Status               = 'Failed'
            ActionTaken          = 'Remediation attempt failed.'
            QuarantinePath       = ''
            RollbackMetadataPath = ''
            FailureReason        = $_.Exception.Message
            Actions              = @()
        }
    }
}

function New-ExecutiveSummary {
<#
.SYNOPSIS
Builds an executive summary object.

.DESCRIPTION
Aggregates scan and remediation totals into a concise object that can be
exported as a dedicated summary report for stakeholders.

.PARAMETER Records
The final report records.

.PARAMETER Configuration
The effective configuration object.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Records,

        [Parameter(Mandatory = $true)]
        [object]$Configuration
    )

    $distinctServers = @($Records | Select-Object -ExpandProperty ServerName -Unique)
    $vulnerableServers = @($Records | Where-Object { $_.DetectionStatus -eq 'Detected' } | Select-Object -ExpandProperty ServerName -Unique)
    $failedServers = @($Records | Where-Object { $_.ScanStatus -eq 'Failed' } | Select-Object -ExpandProperty ServerName -Unique)
    $remediatedServers = @($Records | Where-Object { $_.RemediationStatus -in @('Remediated', 'Partial') } | Select-Object -ExpandProperty ServerName -Unique)

    return [pscustomobject]@{
        SolutionVersion       = $script:SolutionVersion
        GeneratedOn           = (Get-Date).ToString('s')
        TotalServers          = $distinctServers.Count
        VulnerableServers     = $vulnerableServers.Count
        FailedServers         = $failedServers.Count
        RemediatedServers     = $remediatedServers.Count
        DryRunMode            = [bool]$Configuration.DryRun
        PreviewRemediation    = [bool]$Configuration.PreviewRemediation
        RemediationEnabled    = [bool]$Configuration.EnableRemediation
        NoWinRMMode           = [bool]$Configuration.NoWinRM
        FileSearchSkipped     = [bool]$Configuration.SkipFileSearch
        HashingEnabled        = [bool]$Configuration.IncludeHash
    }
}

# Import the reusable reporting module before runtime configuration is resolved.
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'ReportingTools.psm1') -Force

# Resolve configuration and initialize runtime folders before any remote work starts.
$configuration = Resolve-EffectiveConfiguration -ConfigPath (Resolve-AbsolutePath -Path $ConfigPath)

if ($configuration.VerboseLogging) {
    $VerbosePreference = 'Continue'
}

if (-not (Test-Path -LiteralPath $configuration.OutputPath)) {
    New-Item -Path $configuration.OutputPath -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $configuration.LogPath)) {
    New-Item -Path $configuration.LogPath -ItemType Directory -Force | Out-Null
}

$script:LogFilePath = Join-Path -Path $configuration.LogPath -ChildPath ('MSXML4Remediation_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -Path $script:LogFilePath -ItemType File -Force | Out-Null

Write-Log -Message ("Starting Invoke-MSXML4Remediation.ps1 version {0}" -f $script:SolutionVersion)
Write-Log -Message ("Using configuration file {0}" -f $ConfigPath)

if (-not $Credential) {
    $defaultCredentialUser = Get-DefaultCredentialUser -Configuration $configuration
    $Credential = Get-Credential -UserName $defaultCredentialUser -Message 'Enter remote access credentials for MSXML4 detection/remediation.'
}

$servers = Get-ServerList -CsvPath $configuration.ServerCsvPath
Write-Log -Message ("Loaded {0} server(s) from {1}" -f $servers.Count, $configuration.ServerCsvPath)

$runMode = if ($ConnectivityOnly) {
    'ConnectivityOnly'
}
elseif ($configuration.DryRun) {
    'DryRun'
}
elseif ($configuration.PreviewRemediation) {
    'PreviewRemediation'
}
elseif ($configuration.EnableRemediation) {
    'Remediation'
}
else {
    'AuditOnly'
}

function ConvertTo-RecordArray {
<#
.SYNOPSIS
Normalizes report output into an object array.

.DESCRIPTION
Converts null, single-object, and collection inputs into a stable object array
so downstream summary and reporting logic always processes individual records.

.PARAMETER InputObject
The object or collection to normalize.

.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return ,([object[]]@())
    }

    if ($InputObject -is [System.Collections.IList]) {
        return ,([object[]]$InputObject)
    }

    return ,([object[]]@($InputObject))
}

if ($configuration.EnableRemediation -and $configuration.RequireConfirmation -and -not $Force) {
    if (-not (Confirm-RemediationStart)) {
        throw 'Remediation was not confirmed by the operator.'
    }
}

# Scan each server, collect findings, and then apply the selected remediation mode.
$allResults = New-Object System.Collections.Generic.List[object]

foreach ($server in $servers) {
    Write-Log -Message ("Scanning {0}" -f $server)
    $serverResult = Get-MSXML4FindingsForServer -ServerName $server -Credential $Credential -Configuration $configuration
    $remediationResult = Invoke-ServerRemediation -ServerResult $serverResult -Credential $Credential -Configuration $configuration

    foreach ($record in (ConvertTo-RecordArray -InputObject $serverResult.ReportRecords)) {
        $record.RemediationStatus = $remediationResult.Status
        $record.RemediationActionTaken = $remediationResult.ActionTaken
        $record.QuarantinePath = $remediationResult.QuarantinePath
        $record.RollbackMetadataPath = $remediationResult.RollbackMetadataPath

        if ($remediationResult.FailureReason) {
            $record.FailureReason = $remediationResult.FailureReason
        }

        [void]$allResults.Add($record)
    }
}

# Build the final report datasets after scan and remediation processing are complete.
$records = ConvertTo-RecordArray -InputObject $allResults
$summary = New-ExecutiveSummary -Records $records -Configuration $configuration
$metadata = [pscustomobject]@{
    SolutionName      = 'MSXML4 Enterprise Detection and Remediation'
    SolutionVersion   = $script:SolutionVersion
    RunMode           = $runMode
    ConfigurationPath = $ConfigPath
    ServerCsvPath     = $configuration.ServerCsvPath
    LogFilePath       = $script:LogFilePath
    ReportFormats     = ($configuration.ReportFormats -join ',')
}

$vulnerableRecords = @($records | Where-Object { $_.DetectionStatus -eq 'Detected' })
$remediationActionRecords = @($records | Where-Object { $_.RemediationStatus -in @('DryRun', 'PreviewOnly', 'Remediated', 'Partial', 'Failed') -and $_.DetectionStatus -eq 'Detected' })
$remediationFailureRecords = @($records | Where-Object { $_.RemediationStatus -in @('Failed', 'Partial') -or $_.FailureReason })
$notDetectedRecords = @($records | Where-Object { $_.DetectionStatus -eq 'NotDetected' })
$failedServerRecords = @($records | Where-Object { $_.ScanStatus -eq 'Failed' })
$dryRunRecords = @($records | Where-Object { $_.RemediationStatus -in @('DryRun', 'PreviewOnly') })

$reportBundles = @()
$reportBundles += Export-ReportBundle -Data $records -OutputPath $configuration.OutputPath -BaseFileName 'FullInventoryReport' -Title 'MSXML4 Full Inventory Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $failedServerRecords -Metadata $metadata
$reportBundles += Export-ReportBundle -Data $vulnerableRecords -OutputPath $configuration.OutputPath -BaseFileName 'VulnerableServersReport' -Title 'MSXML4 Vulnerable Servers Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $failedServerRecords -Metadata $metadata
$reportBundles += Export-ReportBundle -Data $remediationActionRecords -OutputPath $configuration.OutputPath -BaseFileName 'RemediationActionsReport' -Title 'MSXML4 Remediation Actions Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $remediationFailureRecords -Metadata $metadata
$reportBundles += Export-ReportBundle -Data $remediationFailureRecords -OutputPath $configuration.OutputPath -BaseFileName 'RemediationFailuresReport' -Title 'MSXML4 Remediation Failures Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $remediationFailureRecords -Metadata $metadata
$reportBundles += Export-ReportBundle -Data $notDetectedRecords -OutputPath $configuration.OutputPath -BaseFileName 'NotDetectedReport' -Title 'MSXML4 Not Detected Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $failedServerRecords -Metadata $metadata
$reportBundles += Export-ReportBundle -Data $failedServerRecords -OutputPath $configuration.OutputPath -BaseFileName 'FailedServersReport' -Title 'MSXML4 Failed Servers Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $failedServerRecords -Metadata $metadata
$reportBundles += Export-ReportBundle -Data $dryRunRecords -OutputPath $configuration.OutputPath -BaseFileName 'DryRunReport' -Title 'MSXML4 Dry Run Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $failedServerRecords -Metadata $metadata
$reportBundles += Export-ReportBundle -Data @($summary) -OutputPath $configuration.OutputPath -BaseFileName 'ExecutiveSummaryReport' -Title 'MSXML4 Executive Summary Report' -Formats $configuration.ReportFormats -Summary $summary -FailedItems $failedServerRecords -Metadata $metadata

Write-Log -Message ("Generated {0} report bundle(s)." -f $reportBundles.Count)
Write-Log -Message 'MSXML4 detection/remediation run completed.'

$records
