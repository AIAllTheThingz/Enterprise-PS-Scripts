<#
.SYNOPSIS
Audits SMB share and NTFS folder permissions.
.DESCRIPTION
Enumerates SMB shares, share permissions, NTFS folder permissions, ownership,
inheritance, folder hierarchy, and inaccessible folder errors for local or
remote Windows servers. The script is read-only and never enumerates files.
.PARAMETER ConfigPath
Path to FileSharePermissionsAudit.Config.psd1.
.PARAMETER ServerName
Optional single server override. Local aliases are supported.
.PARAMETER ServerCsvPath
Optional server CSV override.
.PARAMETER ShareName
Optional one or more SMB share names to scan on each target server.
.PARAMETER SharePath
Optional one or more UNC share roots such as \\server\share to scan directly.
.PARAMETER Credential
Optional credential for remote operations.
.PARAMETER OutputDirectory
Overrides both report and log paths.
.PARAMETER ReportPath
Overrides report path only.
.PARAMETER IncludeAdminShares
Includes administrative shares.
.PARAMETER MaxDepth
Overrides maximum folder depth. 0 means unlimited.
.PARAMETER ContinueOnFailure
Continue after server failures.
.PARAMETER SkipPreCheck
Skips ping and WinRM prechecks.
.PARAMETER NonInteractive
Prevents interactive prompts.
.EXAMPLE
.\Get-FileSharePermissionsAudit.ps1 -ConfigPath .\FileSharePermissionsAudit.Config.psd1
.OUTPUTS
None
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ConfigPath,
    [string]$ServerName,
    [string]$ServerCsvPath,
    [string[]]$ShareName,
    [string[]]$SharePath,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputDirectory,
    [string]$ReportPath,
    [switch]$IncludeAdminShares,
    [ValidateRange(0,1000)][int]$MaxDepth,
    [switch]$ContinueOnFailure,
    [switch]$SkipPreCheck,
    [switch]$NonInteractive
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Script:InvocationParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $Script:InvocationParameters[$parameterName] = $PSBoundParameters[$parameterName]
}
$Script:RunTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:Config = $null
$Script:LogPath = $null
$Script:TranscriptPath = $null
$Script:Rows = @()
$Script:Errors = @()
$Script:ServerDurations = @{}
$Script:HadWarningOrError = $false
$Script:Fatal = $false

function Write-Log {
<#
.SYNOPSIS
Writes structured log entries.
.DESCRIPTION
Writes timestamped log lines for configuration, server processing, traversal,
ACL reads, warnings, errors, report generation, and completion.
.PARAMETER Message
Message text.
.PARAMETER Level
Log level.
.EXAMPLE
Write-Log -Message 'Script start'
.OUTPUTS
None
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level='INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'),$Level,$Message
    if ($Script:LogPath) { Add-Content -LiteralPath $Script:LogPath -Value $line -Encoding UTF8 }
    if ($Level -eq 'WARN') { $Script:HadWarningOrError = $true; Write-Warning $Message }
    elseif ($Level -eq 'ERROR') { $Script:HadWarningOrError = $true; Write-Error -Message $Message -ErrorAction Continue }
    elseif ($PSBoundParameters.ContainsKey('Verbose')) { Write-Verbose $Message }
}

function Import-Configuration {
<#
.SYNOPSIS
Imports and validates configuration.
.DESCRIPTION
Loads FileSharePermissionsAudit.Config.psd1 and validates required sections.
Command-line switches override selected configuration values.
.PARAMETER Path
PSD1 configuration path.
.EXAMPLE
Import-Configuration -Path .\FileSharePermissionsAudit.Config.psd1
.OUTPUTS
System.Collections.Hashtable
#>
    [CmdletBinding()]
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "ConfigPath does not exist: $Path" }
    $config = Import-PowerShellDataFile -LiteralPath $Path
    foreach ($section in @('Output','Enumeration','ShareExclusions','HealthChecks','Reporting','Execution','Remote')) {
        if (-not $config.ContainsKey($section)) { throw "Configuration missing section: $section" }
    }
    if (-not $config.ContainsKey('ServerCsvPath')) { throw 'Configuration missing ServerCsvPath.' }
    if (-not $config.ContainsKey('UseCredential')) { $config['UseCredential'] = $false }
    if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $config.Output['ReportPath'] = $OutputDirectory
        $config.Output['LogPath'] = $OutputDirectory
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) { $config.Output['ReportPath'] = $ReportPath }
    if ($Script:InvocationParameters.ContainsKey('IncludeAdminShares')) { $config.Enumeration['IncludeAdminShares'] = [bool]$IncludeAdminShares }
    if ($Script:InvocationParameters.ContainsKey('MaxDepth')) { $config.Enumeration['MaxDepth'] = $MaxDepth }
    if ($Script:InvocationParameters.ContainsKey('ContinueOnFailure')) { $config.Execution['ContinueOnServerFailure'] = [bool]$ContinueOnFailure }
    if ([int]$config.Enumeration.MaxDepth -lt 0) { throw 'MaxDepth must be 0 or greater. 0 means unlimited.' }
    return $config
}

function Test-IsLocalHost {
<#
.SYNOPSIS
Determines whether a server target is local.
.DESCRIPTION
Recognizes localhost, ., 127.0.0.1, the local computer name, and the local FQDN.
.PARAMETER ServerName
Target server name.
.EXAMPLE
Test-IsLocalHost -ServerName localhost
.OUTPUTS
System.Boolean
#>
    [CmdletBinding()]
    param([string]$ServerName)
    if ([string]::IsNullOrWhiteSpace($ServerName)) { return $true }
    $value = $ServerName.Trim()
    if ($value -in @('localhost','.','127.0.0.1','::1')) { return $true }
    if ($value -ieq $env:COMPUTERNAME) { return $true }
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($value -ieq $fqdn) { return $true }
    } catch { }
    return $false
}

function Resolve-TargetServers {
<#
.SYNOPSIS
Resolves target servers.
.DESCRIPTION
Uses -SharePath, -ServerName, -ServerCsvPath, configured CSV, or local
computer. Disabled CSV rows and blanks are ignored. Duplicate
localhost-equivalent entries are normalized and de-duplicated.
.PARAMETER Config
Configuration hashtable.
.EXAMPLE
Resolve-TargetServers -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([hashtable]$Config)
    if ($ServerName -and $ServerCsvPath) { throw 'Use either -ServerName or -ServerCsvPath, not both.' }
    if ($SharePath -and $ServerCsvPath) { throw 'Use either -SharePath or -ServerCsvPath, not both.' }
    if ($SharePath -and $ServerName) { throw 'Use either -SharePath or -ServerName, not both. -SharePath already includes the server name.' }
    if ($SharePath -and $ShareName) { throw 'Use either -SharePath or -ShareName, not both. -SharePath already includes the share name.' }
    $targets = @()
    if ($SharePath) {
        $targets += Resolve-SharePathTargets -Paths $SharePath
    } elseif ($ServerName) {
        $targets += [pscustomobject]@{ ServerName=$ServerName.Trim(); OriginalName=$ServerName.Trim(); Notes='Provided by -ServerName'; IsLocal=(Test-IsLocalHost -ServerName $ServerName) }
    } else {
        $csvPath = $ServerCsvPath
        if ([string]::IsNullOrWhiteSpace($csvPath)) { $csvPath = $Config.ServerCsvPath }
        if (-not [string]::IsNullOrWhiteSpace($csvPath)) {
            if (-not [System.IO.Path]::IsPathRooted($csvPath)) { $csvPath = Join-Path $PSScriptRoot $csvPath }
            if (-not (Test-Path -LiteralPath $csvPath)) { throw "Server CSV does not exist: $csvPath" }
            $rows = Import-Csv -LiteralPath $csvPath
            if (@($rows).Count -gt 0) {
                foreach ($column in @('ServerName','Enabled','Notes')) {
                    if ($rows[0].PSObject.Properties.Name -notcontains $column) { throw "Server CSV missing required column: $column" }
                }
            }
            foreach ($row in @($rows)) {
                $name = ([string]$row.ServerName).Trim()
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                $enabled = $false
                [void][bool]::TryParse(([string]$row.Enabled).Trim(), [ref]$enabled)
                if (-not $enabled) { continue }
                $isLocal = Test-IsLocalHost -ServerName $name
                $normalized = if ($isLocal) { $env:COMPUTERNAME } else { $name }
                $targets += [pscustomobject]@{ ServerName=$normalized; OriginalName=$name; Notes=([string]$row.Notes).Trim(); IsLocal=$isLocal }
            }
        }
    }
    if ($targets.Count -eq 0) { $targets += [pscustomobject]@{ ServerName=$env:COMPUTERNAME; OriginalName=$env:COMPUTERNAME; Notes='Default local computer'; IsLocal=$true } }
    $dedupe = @{}
    $final = @()
    foreach ($target in $targets) {
        $key = if ($target.IsLocal) { 'localhost' } else { $target.ServerName.ToLowerInvariant() }
        if (-not $dedupe.ContainsKey($key)) {
            $dedupe[$key] = $true
            $final += $target
        } else {
            $existing = @($final | Where-Object { (($_.IsLocal -and $key -eq 'localhost') -or ((-not $_.IsLocal) -and $_.ServerName.ToLowerInvariant() -eq $key)) } | Select-Object -First 1)
            if ($existing.Count -gt 0 -and $target.PSObject.Properties.Name -contains 'RequestedShares') {
                $merged = @($existing[0].RequestedShares) + @($target.RequestedShares)
                $existing[0].RequestedShares = @($merged | Sort-Object ShareName,SharePath -Unique)
            }
        }
    }
    return $final
}

function Resolve-SharePathTargets {
<#
.SYNOPSIS
Builds targets from UNC share paths.
.DESCRIPTION
Parses one or more UNC share roots in the form \\server\share, groups them by
server, and creates standard target objects with requested share metadata. This
allows scanning a specific SMB share without enumerating every share first.
.PARAMETER Paths
UNC share root paths.
.EXAMPLE
Resolve-SharePathTargets -Paths '\\FILESERVER01\Finance','\\192.168.1.25\Data'
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([string[]]$Paths)
    $byServer = @{}
    foreach ($pathValue in @($Paths)) {
        $trimmed = ([string]$pathValue).Trim().TrimEnd('\')
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -notmatch '^\\\\([^\\]+)\\([^\\]+)(\\.*)?$') {
            throw "SharePath must be a UNC share root such as \\server\share. Invalid value: $trimmed"
        }
        $server = $matches[1]
        $share = $matches[2]
        $subPath = $matches[3]
        if (-not [string]::IsNullOrWhiteSpace($subPath)) {
            throw "SharePath must target the share root only, not a subfolder. Invalid value: $trimmed"
        }
        $isLocal = Test-IsLocalHost -ServerName $server
        $normalized = if ($isLocal) { $env:COMPUTERNAME } else { $server }
        $key = if ($isLocal) { 'localhost' } else { $normalized.ToLowerInvariant() }
        if (-not $byServer.ContainsKey($key)) {
            $byServer[$key] = [pscustomobject]@{
                ServerName = $normalized
                OriginalName = $server
                Notes = 'Provided by -SharePath'
                IsLocal = $isLocal
                RequestedShares = @()
            }
        }
        $byServer[$key].RequestedShares += [pscustomobject]@{
            ShareName = $share
            SharePath = $trimmed
            Description = 'Provided by -SharePath'
            DirectSharePath = $true
        }
    }
    return @($byServer.Values)
}

function Test-ServerReachable {
<#
.SYNOPSIS
Tests server reachability.
.DESCRIPTION
Validates ping and WinRM according to configuration. Localhost targets avoid
unnecessary WinRM and network round trips.
.PARAMETER Target
Target object.
.PARAMETER Config
Configuration hashtable.
.EXAMPLE
Test-ServerReachable -Target $Target -Config $Config
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Target,[hashtable]$Config)
    if ($SkipPreCheck -or $Target.IsLocal) { return [pscustomobject]@{ Passed=$true; Ping='Skipped'; WinRM='Skipped'; Message='' } }
    $hasDirectSharePath = (($Target.PSObject.Properties.Name -contains 'RequestedShares') -and (@($Target.RequestedShares).Count -gt 0))
    $ping = 'Skipped'
    $winrm = 'Skipped'
    $message = ''
    if ($Config.HealthChecks.Ping) {
        try { if (Test-Connection -ComputerName $Target.ServerName -Count 1 -Quiet -ErrorAction Stop) { $ping='Passed' } else { $ping='Failed' } } catch { $ping='Failed'; $message=$_.Exception.Message }
    }
    if ($Config.HealthChecks.WinRM -and -not $hasDirectSharePath) {
        try { Test-WSMan -ComputerName $Target.ServerName -ErrorAction Stop | Out-Null; $winrm='Passed' } catch { $winrm='Failed'; if ($message) { $message += '; ' }; $message += $_.Exception.Message }
    } elseif ($hasDirectSharePath) {
        $winrm = 'SkippedForDirectSharePath'
    }
    return [pscustomobject]@{ Passed=(($ping -ne 'Failed') -and ($winrm -ne 'Failed')); Ping=$ping; WinRM=$winrm; Message=$message }
}

function ConvertTo-ScanPath {
<#
.SYNOPSIS
Converts share paths for local or remote scanning.
.DESCRIPTION
Local paths are used directly for local targets. Remote paths use UNC fallback
when configured.
.PARAMETER Target
Target object.
.PARAMETER Path
Share path.
.PARAMETER Config
Configuration hashtable.
.EXAMPLE
ConvertTo-ScanPath -Target $Target -Path 'D:\Data' -Config $Config
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([object]$Target,[string]$Path,[hashtable]$Config)
    if ($Target.IsLocal) { return $Path }
    if ($Config.Remote.UseUNCFallback -and $Path -match '^([A-Za-z]):\\(.*)$') { return "\\$($Target.ServerName)\$($matches[1])$\" + $matches[2] }
    return $Path
}

function ConvertFrom-ScanPath {
<#
.SYNOPSIS
Converts scan path to report display path.
.DESCRIPTION
Converts administrative UNC paths back to target-local paths in reports.
.PARAMETER Target
Target object.
.PARAMETER Path
Scan path.
.EXAMPLE
ConvertFrom-ScanPath -Target $Target -Path '\\Server\D$\Data'
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([object]$Target,[string]$Path)
    $pattern = '^\\\\' + [regex]::Escape($Target.ServerName) + '\\([A-Za-z])\$(\\.*)$'
    if ($Path -match $pattern) { return ($matches[1] + ':' + $matches[2]) }
    return $Path
}

function Get-ServerShares {
<#
.SYNOPSIS
Enumerates SMB shares.
.DESCRIPTION
Prefers Get-SmbShare and falls back to Win32_Share. Administrative shares are
excluded by default according to configuration.
.PARAMETER Target
Target object.
.PARAMETER Config
Configuration hashtable.
.EXAMPLE
Get-ServerShares -Target $Target -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object]$Target,[hashtable]$Config)
    $shares = @()
    if (($Target.PSObject.Properties.Name -contains 'RequestedShares') -and (@($Target.RequestedShares).Count -gt 0)) {
        return @($Target.RequestedShares)
    }
    try {
        if ($Target.IsLocal -and (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
            $shares = Get-SmbShare -ErrorAction Stop | Select-Object Name,Path,Description
        } elseif (-not $Target.IsLocal -and (Test-WSMan -ComputerName $Target.ServerName -ErrorAction SilentlyContinue)) {
            $scriptBlock = {
                if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) { Get-SmbShare | Select-Object Name,Path,Description }
                else { Get-WmiObject Win32_Share | Select-Object Name,Path,Description }
            }
            if ($Credential) { $shares = Invoke-Command -ComputerName $Target.ServerName -Credential $Credential -ScriptBlock $scriptBlock -ErrorAction Stop }
            else { $shares = Invoke-Command -ComputerName $Target.ServerName -ScriptBlock $scriptBlock -ErrorAction Stop }
        } else { throw 'SMB cmdlet path unavailable.' }
    } catch {
        Write-Log -Level WARN -Message "Falling back to Win32_Share for $($Target.ServerName). $($_.Exception.Message)"
        try {
            $params = @{ Class='Win32_Share'; ComputerName=$Target.ServerName; ErrorAction='Stop' }
            if ($Credential -and -not $Target.IsLocal) { $params.Credential = $Credential }
            $shares = Get-WmiObject @params | Select-Object Name,Path,Description
        } catch {
            throw "Failed to enumerate shares on $($Target.ServerName). $($_.Exception.Message)"
        }
    }
    $excluded = @($Config.ShareExclusions.Shares)
    $includeAdmin = [bool]$Config.Enumeration.IncludeAdminShares
    $requestedShareNames = @()
    if ($ShareName) {
        foreach ($requestedName in @($ShareName)) {
            if (-not [string]::IsNullOrWhiteSpace($requestedName)) { $requestedShareNames += $requestedName.Trim() }
        }
    }
    $filtered = @()
    foreach ($share in @($shares)) {
        $name = [string]$share.Name
        if ($requestedShareNames.Count -gt 0 -and ($requestedShareNames -notcontains $name)) { continue }
        $isDriveAdmin = $name -match '^[A-Za-z]\$$'
        if (-not $includeAdmin -and (($excluded -contains $name) -or $isDriveAdmin)) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$share.Path)) { continue }
        $filtered += [pscustomobject]@{ ShareName=$name; SharePath=[string]$share.Path; Description=[string]$share.Description }
    }
    return $filtered
}

function Convert-AccessMaskToShareRight {
<#
.SYNOPSIS
Converts WMI share permission access masks.
.DESCRIPTION
Maps common SMB share access masks returned by Win32_LogicalShareSecuritySetting
to readable permission names. Unknown masks are preserved for review.
.PARAMETER AccessMask
Numeric access mask from a WMI ACE.
.EXAMPLE
Convert-AccessMaskToShareRight -AccessMask 2032127
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([int]$AccessMask)
    switch ($AccessMask) { 1179817 { 'Read' } 1245631 { 'Change' } 2032127 { 'Full' } default { "AccessMask:$AccessMask" } }
}

function Get-SharePermissions {
<#
.SYNOPSIS
Gets SMB share permissions.
.DESCRIPTION
Prefers Get-SmbShareAccess and falls back to Win32_LogicalShareSecuritySetting.
.PARAMETER Target
Target object.
.PARAMETER ShareName
Share name.
.EXAMPLE
Get-SharePermissions -Target $Target -ShareName Data
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object]$Target,[string]$ShareName)
    $permissions = @()
    try {
        if ($Target.IsLocal -and (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue)) {
            $permissions = Get-SmbShareAccess -Name $ShareName -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Identity=$_.AccountName; AccessControlType=$_.AccessControlType; Right=$_.AccessRight } }
        } elseif (-not $Target.IsLocal -and (Test-WSMan -ComputerName $Target.ServerName -ErrorAction SilentlyContinue)) {
            $scriptBlock = { param($Name) Get-SmbShareAccess -Name $Name | ForEach-Object { [pscustomobject]@{ Identity=$_.AccountName; AccessControlType=$_.AccessControlType; Right=$_.AccessRight } } }
            if ($Credential) { $permissions = Invoke-Command -ComputerName $Target.ServerName -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $ShareName -ErrorAction Stop }
            else { $permissions = Invoke-Command -ComputerName $Target.ServerName -ScriptBlock $scriptBlock -ArgumentList $ShareName -ErrorAction Stop }
        }
    } catch {
        Write-Log -Level WARN -Message "Share permission cmdlet failed for $($Target.ServerName)\$ShareName. $($_.Exception.Message)"
    }
    if (@($permissions).Count -eq 0) {
        try {
            $params = @{ Class='Win32_LogicalShareSecuritySetting'; ComputerName=$Target.ServerName; Filter="Name='$ShareName'"; ErrorAction='Stop' }
            if ($Credential -and -not $Target.IsLocal) { $params.Credential = $Credential }
            $setting = Get-WmiObject @params
            $descriptor = $setting.GetSecurityDescriptor()
            foreach ($ace in @($descriptor.Descriptor.DACL)) {
                $identity = "$($ace.Trustee.Domain)\$($ace.Trustee.Name)".Trim('\')
                $permissions += [pscustomobject]@{ Identity=$identity; AccessControlType=$(if ($ace.AceType -eq 0) { 'Allow' } else { 'Deny' }); Right=(Convert-AccessMaskToShareRight -AccessMask ([int]$ace.AccessMask)) }
            }
        } catch {
            Write-Log -Level WARN -Message "Failed to read share security descriptor for $($Target.ServerName)\$ShareName. $($_.Exception.Message)"
        }
    }
    if (@($permissions).Count -eq 0) { $permissions += [pscustomobject]@{ Identity=''; AccessControlType=''; Right='' } }
    return $permissions
}

function Get-FolderMetadata {
<#
.SYNOPSIS
Builds folder hierarchy metadata.
.DESCRIPTION
Calculates folder depth, display name, parent path, and indented FolderTree
text relative to the SMB share root.
.PARAMETER Root
Share root scan path.
.PARAMETER Path
Folder path being reported.
.PARAMETER ShareName
Share name used for the root tree label.
.EXAMPLE
Get-FolderMetadata -Root 'D:\Data' -Path 'D:\Data\Finance' -ShareName Data
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([string]$Root,[string]$Path,[string]$ShareName)
    $rootTrim = $Root.TrimEnd('\')
    $pathTrim = $Path.TrimEnd('\')
    $relative = ''
    if ($pathTrim.Length -gt $rootTrim.Length) { $relative = $pathTrim.Substring($rootTrim.Length).TrimStart('\') }
    $parts = @()
    if (-not [string]::IsNullOrWhiteSpace($relative)) { $parts = $relative -split '\\' }
    $depth = $parts.Count
    $name = if ($depth -eq 0) { $ShareName } else { $parts[$parts.Count - 1] }
    $parent = if ($depth -le 1) { $Root } else { Join-Path $Root (($parts[0..($parts.Count - 2)]) -join '\') }
    [pscustomobject]@{ Depth=$depth; Tree=((' ' * ($depth * 4)) + $name); Parent=$parent; Name=$name; IsRoot=($depth -eq 0) }
}

function Get-FolderTree {
<#
.SYNOPSIS
Enumerates folder tree.
.DESCRIPTION
Enumerates directories only using Get-ChildItem -Directory. Files and file ACLs
are never enumerated. Reparse points are skipped when configured.
.PARAMETER Target
Target object.
.PARAMETER Share
Share object.
.PARAMETER Config
Configuration hashtable.
.EXAMPLE
Get-FolderTree -Target $Target -Share $Share -Config $Config
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object]$Target,[object]$Share,[hashtable]$Config)
    $root = ConvertTo-ScanPath -Target $Target -Path $Share.SharePath -Config $Config
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([pscustomobject]@{ Path=$root; Depth=0 })
    $visited = @{}
    $folders = @()
    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $key = $item.Path.ToLowerInvariant()
        if ($visited.ContainsKey($key)) { continue }
        $visited[$key] = $true
        $meta = Get-FolderMetadata -Root $root -Path $item.Path -ShareName $Share.ShareName
        $folders += [pscustomobject]@{ ScanPath=$item.Path; DisplayPath=(ConvertFrom-ScanPath -Target $Target -Path $item.Path); FolderName=$meta.Name; ParentFolder=(ConvertFrom-ScanPath -Target $Target -Path $meta.Parent); FolderDepth=$meta.Depth; FolderTree=$meta.Tree; IsShareRoot=$meta.IsRoot; EnumerationStatus='Success'; ErrorMessage='' }
        if (-not $Config.Enumeration.EnumerateSubFolders) { continue }
        if ([int]$Config.Enumeration.MaxDepth -gt 0 -and $item.Depth -ge [int]$Config.Enumeration.MaxDepth) { continue }
        try {
            $children = Get-ChildItem -LiteralPath $item.Path -Directory -Force -ErrorAction Stop
            foreach ($child in @($children)) {
                if ($Config.Enumeration.ExcludeReparsePoints -and (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) { continue }
                $queue.Enqueue([pscustomobject]@{ Path=$child.FullName; Depth=($item.Depth + 1) })
            }
        } catch {
            $Script:Errors += [pscustomobject]@{ Timestamp=(Get-Date).ToString('s'); ServerName=$Target.ServerName; ShareName=$Share.ShareName; FolderPath=(ConvertFrom-ScanPath -Target $Target -Path $item.Path); Scope='FolderEnumeration'; ErrorMessage=$_.Exception.Message }
            Write-Log -Level WARN -Message "Inaccessible folder $($item.Path). $($_.Exception.Message)"
        }
    }
    return $folders
}

function Get-NTFSPermissions {
<#
.SYNOPSIS
Gets NTFS permissions for a folder.
.DESCRIPTION
Reads folder ACLs only. File ACLs are never read.
.PARAMETER FolderPath
Folder path.
.PARAMETER IncludeInherited
Include inherited ACEs.
.EXAMPLE
Get-NTFSPermissions -FolderPath D:\Data -IncludeInherited $true
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([string]$FolderPath,[bool]$IncludeInherited)
    try {
        $acl = Get-Acl -LiteralPath $FolderPath -ErrorAction Stop
        $rules = @()
        foreach ($ace in @($acl.Access)) {
            if (-not $IncludeInherited -and $ace.IsInherited) { continue }
            $rules += [pscustomobject]@{ Owner=[string]$acl.Owner; Identity=[string]$ace.IdentityReference; AccessControlType=[string]$ace.AccessControlType; Rights=[string]$ace.FileSystemRights; IsInherited=[string]$ace.IsInherited; InheritanceFlags=[string]$ace.InheritanceFlags; PropagationFlags=[string]$ace.PropagationFlags; ErrorMessage='' }
        }
        if ($rules.Count -eq 0) { $rules += [pscustomobject]@{ Owner=[string]$acl.Owner; Identity=''; AccessControlType=''; Rights=''; IsInherited=''; InheritanceFlags=''; PropagationFlags=''; ErrorMessage='' } }
        return $rules
    } catch {
        return @([pscustomobject]@{ Owner=''; Identity=''; AccessControlType=''; Rights=''; IsInherited=''; InheritanceFlags=''; PropagationFlags=''; ErrorMessage=$_.Exception.Message })
    }
}

function New-AuditRow {
<#
.SYNOPSIS
Creates a flattened report row.
.DESCRIPTION
Combines server, share, folder, SMB permission, and NTFS permission data into
the stable CSV/JSON/HTML field set required by the audit reports.
.PARAMETER Target
Standardized server target object.
.PARAMETER Share
SMB share object.
.PARAMETER Folder
Folder tree object.
.PARAMETER SharePermission
SMB share permission object.
.PARAMETER NTFS
NTFS permission object.
.PARAMETER Duration
Current server scan duration in seconds.
.EXAMPLE
New-AuditRow -Target $target -Share $share -Folder $folder -SharePermission $sharePermission -NTFS $ntfs -Duration 12.4
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param([object]$Target,[object]$Share,[object]$Folder,[object]$SharePermission,[object]$NTFS,[double]$Duration)
    [pscustomobject]@{
        ServerName=$Target.ServerName; ShareName=$Share.ShareName; SharePath=$Share.SharePath; FolderPath=$Folder.DisplayPath; FolderName=$Folder.FolderName; ParentFolder=$Folder.ParentFolder; FolderDepth=$Folder.FolderDepth; FolderTree=$Folder.FolderTree; IsShareRoot=$Folder.IsShareRoot; Owner=$NTFS.Owner; ShareDescription=$Share.Description; SharePermissionIdentity=$SharePermission.Identity; SharePermissionAccessControlType=$SharePermission.AccessControlType; SharePermissionRight=$SharePermission.Right; NTFSIdentity=$NTFS.Identity; NTFSAccessControlType=$NTFS.AccessControlType; NTFSRights=$NTFS.Rights; NTFSIsInherited=$NTFS.IsInherited; NTFSInheritanceFlags=$NTFS.InheritanceFlags; NTFSPropagationFlags=$NTFS.PropagationFlags; EnumerationStatus=$Folder.EnumerationStatus; ErrorMessage=(($Folder.ErrorMessage,$NTFS.ErrorMessage) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '; ScanDurationSeconds=$Duration
    }
}

try {
    $Script:Config = Import-Configuration -Path $ConfigPath
    if ($Script:Config.UseCredential -and -not $Credential) {
        if ($NonInteractive) { throw 'UseCredential is true, but -Credential was not supplied and -NonInteractive prevents prompting.' }
        $Credential = Get-Credential -Message 'Enter credentials for remote share and NTFS permission auditing'
    }
    if ($WhatIfPreference) {
        Write-Warning 'WhatIf mode was supplied. This audit is read-only; target systems will not be modified. Local report and log files may still be created.'
    }
    if (-not (Test-Path -LiteralPath $Script:Config.Output.ReportPath)) { New-Item -ItemType Directory -Path $Script:Config.Output.ReportPath -Force -WhatIf:$false | Out-Null }
    if (-not (Test-Path -LiteralPath $Script:Config.Output.LogPath)) { New-Item -ItemType Directory -Path $Script:Config.Output.LogPath -Force -WhatIf:$false | Out-Null }
    $Script:LogPath = Join-Path $Script:Config.Output.LogPath ("{0}_{1}.log" -f $Script:Config.Output.ReportPrefix,$Script:RunTimestamp)
    Write-Log -Message 'Script start.'
    Write-Log -Message "Configuration loaded from $ConfigPath"
    $transcript = Join-Path $Script:Config.Output.LogPath ("{0}_{1}_Transcript.log" -f $Script:Config.Output.ReportPrefix,$Script:RunTimestamp)
    try { Start-Transcript -Path $transcript -Force | Out-Null; $Script:TranscriptPath = $transcript } catch { Write-Log -Level WARN -Message "Transcript start failed. $($_.Exception.Message)" }
    $targets = Resolve-TargetServers -Config $Script:Config
    foreach ($target in @($targets)) {
        $serverStart = Get-Date
        Write-Log -Message "Processing server $($target.ServerName). Local=$($target.IsLocal)"
        try {
            $reach = Test-ServerReachable -Target $target -Config $Script:Config
            if (-not $reach.Passed) { throw "Precheck failed. Ping=$($reach.Ping); WinRM=$($reach.WinRM); $($reach.Message)" }
            $shares = Get-ServerShares -Target $target -Config $Script:Config
            foreach ($share in @($shares)) {
                Write-Log -Message "Processing share $($target.ServerName)\$($share.ShareName)"
                $sharePermissions = @(Get-SharePermissions -Target $target -ShareName $share.ShareName)
                $folders = @(Get-FolderTree -Target $target -Share $share -Config $Script:Config)
                foreach ($folder in @($folders)) {
                    $ntfsPermissions = @(Get-NTFSPermissions -FolderPath $folder.ScanPath -IncludeInherited ([bool]$Script:Config.Enumeration.IncludeInheritedPermissions))
                    foreach ($ntfs in $ntfsPermissions) {
                        if ($ntfs.ErrorMessage) { $Script:Errors += [pscustomobject]@{ Timestamp=(Get-Date).ToString('s'); ServerName=$target.ServerName; ShareName=$share.ShareName; FolderPath=$folder.DisplayPath; Scope='NTFS'; ErrorMessage=$ntfs.ErrorMessage } }
                        foreach ($sharePermission in $sharePermissions) {
                            $duration = [math]::Round(((Get-Date) - $serverStart).TotalSeconds,2)
                            $Script:Rows += New-AuditRow -Target $target -Share $share -Folder $folder -SharePermission $sharePermission -NTFS $ntfs -Duration $duration
                        }
                    }
                }
            }
        } catch {
            $Script:Errors += [pscustomobject]@{ Timestamp=(Get-Date).ToString('s'); ServerName=$target.ServerName; ShareName=''; FolderPath=''; Scope='Server'; ErrorMessage=$_.Exception.Message }
            Write-Log -Level ERROR -Message "Server failure $($target.ServerName). $($_.Exception.Message)"
            if (-not $Script:Config.Execution.ContinueOnServerFailure) { throw }
        } finally {
            $Script:ServerDurations[$target.ServerName] = [math]::Round(((Get-Date) - $serverStart).TotalSeconds,2)
        }
    }
    Import-Module (Join-Path $PSScriptRoot 'ReportingTools.psm1') -Force
    $summary = [pscustomobject]@{
        RunTimestamp=(Get-Date).ToString('s')
        TargetServerCount=@($targets).Count
        SuccessfulServerCount=@($Script:Rows | Select-Object -ExpandProperty ServerName -Unique).Count
        FailedServerCount=@($Script:Errors | Where-Object { $_.Scope -eq 'Server' } | Select-Object -ExpandProperty ServerName -Unique).Count
        TotalSharesFound=@($Script:Rows | Select-Object ServerName,ShareName -Unique).Count
        TotalFoldersScanned=@($Script:Rows | Select-Object ServerName,ShareName,FolderPath -Unique).Count
        TotalPermissionEntries=@($Script:Rows).Count
        TranscriptPath=$Script:TranscriptPath
    }
    $paths = Export-Reports -Rows $Script:Rows -Errors $Script:Errors -Summary $summary -ReportPath $Script:Config.Output.ReportPath -ReportPrefix $Script:Config.Output.ReportPrefix -Timestamp $Script:RunTimestamp -GenerateCSV $Script:Config.Reporting.GenerateCSV -GenerateJSON $Script:Config.Reporting.GenerateJSON -GenerateHTML $Script:Config.Reporting.GenerateHTML
    Write-Log -Message "Reports generated. CSV=$($paths.CsvPath); JSON=$($paths.JsonPath); HTML=$($paths.HtmlPath)"
    Write-Log -Message 'Script completion.'
} catch {
    $Script:Fatal = $true
    if (-not $Script:LogPath) {
        $fallback = Join-Path $env:TEMP 'FileSharePermissionsAudit_Fatal'
        if (-not (Test-Path -LiteralPath $fallback)) { New-Item -ItemType Directory -Path $fallback -Force -WhatIf:$false | Out-Null }
        $Script:LogPath = Join-Path $fallback ("FileSharePermissionsAudit_{0}.log" -f $Script:RunTimestamp)
    }
    Write-Log -Level ERROR -Message "Fatal error. $($_.Exception.Message)"
} finally {
    if ($Script:TranscriptPath) { try { Stop-Transcript | Out-Null } catch { } }
    if ($Script:Fatal) { exit 2 }
    if (@($Script:Errors).Count -gt 0) { exit 1 }
    exit 0
}
