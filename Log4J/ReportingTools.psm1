Set-StrictMode -Version 2.0

function New-ReportDirectory {
<#
.SYNOPSIS
Creates a report output directory when it does not exist.
.DESCRIPTION
Creates the destination folder used by the report exporters. The function uses
standard PowerShell and .NET APIs available in Windows PowerShell 5.1 and does
not require external modules.
.PARAMETER Path
Directory path to create.
.EXAMPLE
New-ReportDirectory -Path 'C:\Reports'
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    (Resolve-Path -LiteralPath $Path).Path
}

function ConvertTo-ReportDataTable {
<#
.SYNOPSIS
Normalizes report objects before CSV export.
.DESCRIPTION
Returns the supplied objects or a single informational object when the input is
empty so CSV reports are still generated for empty result sets.
.PARAMETER Data
Objects to normalize for export.
.EXAMPLE
ConvertTo-ReportDataTable -Data $Findings
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object[]]$Data)
    if ($null -eq $Data -or $Data.Count -eq 0) {
        return @([pscustomobject]@{
            Timestamp = (Get-Date).ToString('s')
            Status    = 'NoRecords'
            Message   = 'No records were produced for this section.'
        })
    }
    return $Data
}

function ConvertTo-HtmlEncodedText {
<#
.SYNOPSIS
HTML-encodes report content.
.DESCRIPTION
Encodes arbitrary text before it is inserted into the self-contained HTML
report. This prevents report data from being interpreted as markup.
.PARAMETER Value
Value to encode.
.EXAMPLE
ConvertTo-HtmlEncodedText -Value '<test>'
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-ReportHtmlTable {
<#
.SYNOPSIS
Converts objects into a simple HTML table.
.DESCRIPTION
Creates a self-contained HTML table fragment with status-aware row classes.
.PARAMETER Title
Section title.
.PARAMETER Data
Objects to render.
.PARAMETER StatusProperty
Optional property used for CSS status class selection.
.EXAMPLE
ConvertTo-ReportHtmlTable -Title 'Findings' -Data $Findings -StatusProperty VulnerabilityClassification
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [object[]]$Data,
        [string]$StatusProperty
    )
    $rows = ConvertTo-ReportDataTable -Data $Data
    $properties = @()
    foreach ($row in $rows) {
        foreach ($property in $row.PSObject.Properties.Name) {
            if ($properties -notcontains $property) { $properties += $property }
        }
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine("<h2>$(ConvertTo-HtmlEncodedText $Title)</h2>")
    [void]$builder.AppendLine('<table>')
    [void]$builder.AppendLine('<thead><tr>')
    foreach ($property in $properties) {
        [void]$builder.AppendLine("<th>$(ConvertTo-HtmlEncodedText $property)</th>")
    }
    [void]$builder.AppendLine('</tr></thead><tbody>')
    foreach ($row in $rows) {
        $class = ''
        if ($StatusProperty -and ($row.PSObject.Properties.Name -contains $StatusProperty)) {
            $class = ' class="status-' + ([string]$row.$StatusProperty -replace '[^A-Za-z0-9_-]', '') + '"'
        }
        [void]$builder.AppendLine("<tr$class>")
        foreach ($property in $properties) {
            $value = ''
            if ($row.PSObject.Properties.Name -contains $property) { $value = $row.$property }
            [void]$builder.AppendLine("<td>$(ConvertTo-HtmlEncodedText $value)</td>")
        }
        [void]$builder.AppendLine('</tr>')
    }
    [void]$builder.AppendLine('</tbody></table>')
    return $builder.ToString()
}

function Export-ReportCsv {
<#
.SYNOPSIS
Exports consolidated report records to CSV.
.DESCRIPTION
Exports detailed findings and remediation action records to a timestamped CSV
file. If no records exist, the function writes a NoRecords placeholder so the
run still has an auditable CSV artifact.
.PARAMETER Findings
Detailed finding objects.
.PARAMETER RemediationActions
Remediation action objects.
.PARAMETER Failures
Failure objects.
.PARAMETER OutputPath
Destination directory.
.PARAMETER RunTimestamp
Shared report timestamp.
.PARAMETER Prefix
File prefix.
.EXAMPLE
Export-ReportCsv -Findings $Findings -OutputPath C:\Reports -RunTimestamp 20260525_120000
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [object[]]$Findings,
        [object[]]$RemediationActions,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$RunTimestamp,
        [string]$Prefix = 'Log4j_Remediation_Results'
    )
    $directory = New-ReportDirectory -Path $OutputPath
    $path = Join-Path $directory ("{0}_{1}.csv" -f $Prefix, $RunTimestamp)
    $records = @()
    foreach ($item in @($Findings)) { if ($null -ne $item) { $records += $item } }
    foreach ($item in @($RemediationActions)) { if ($null -ne $item) { $records += $item } }
    foreach ($item in @($Failures)) { if ($null -ne $item) { $records += $item } }
    ConvertTo-ReportDataTable -Data $records | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    return $path
}

function Export-ReportJson {
<#
.SYNOPSIS
Exports a consolidated JSON report.
.DESCRIPTION
Writes metadata, summary, targets, findings, remediation actions, and failures
as readable JSON using ConvertTo-Json with sufficient depth for nested objects.
.PARAMETER Metadata
Run metadata.
.PARAMETER Summary
Run summary counts.
.PARAMETER Targets
Target result objects.
.PARAMETER Findings
Finding objects.
.PARAMETER RemediationActions
Remediation action objects.
.PARAMETER Failures
Failure objects.
.PARAMETER OutputPath
Destination directory.
.PARAMETER RunTimestamp
Shared report timestamp.
.PARAMETER Prefix
File prefix.
.EXAMPLE
Export-ReportJson -Metadata $Metadata -Summary $Summary -OutputPath C:\Reports -RunTimestamp 20260525_120000
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [object]$Metadata,
        [object]$Summary,
        [object[]]$Targets,
        [object[]]$Findings,
        [object[]]$RemediationActions,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$RunTimestamp,
        [string]$Prefix = 'Log4j_Remediation_Results'
    )
    $directory = New-ReportDirectory -Path $OutputPath
    $path = Join-Path $directory ("{0}_{1}.json" -f $Prefix, $RunTimestamp)
    $payload = [pscustomobject]@{
        Metadata           = $Metadata
        Summary            = $Summary
        Targets            = @($Targets)
        Findings           = @($Findings)
        RemediationActions = @($RemediationActions)
        Failures           = @($Failures)
    }
    $payload | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $path -Encoding UTF8
    return $path
}

function Export-ReportTxt {
<#
.SYNOPSIS
Exports a human-readable text report.
.DESCRIPTION
Writes a text report containing run metadata, summary counts, target list,
vulnerable findings, remediation actions, failures, and generated output paths.
.PARAMETER Metadata
Run metadata.
.PARAMETER Summary
Run summary counts.
.PARAMETER Targets
Target result objects.
.PARAMETER Findings
Finding objects.
.PARAMETER RemediationActions
Remediation action objects.
.PARAMETER Failures
Failure objects.
.PARAMETER OutputPath
Destination directory.
.PARAMETER RunTimestamp
Shared report timestamp.
.PARAMETER GeneratedPaths
Already generated report paths.
.PARAMETER Prefix
File prefix.
.EXAMPLE
Export-ReportTxt -Metadata $Metadata -Summary $Summary -OutputPath C:\Reports -RunTimestamp 20260525_120000
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [object]$Metadata,
        [object]$Summary,
        [object[]]$Targets,
        [object[]]$Findings,
        [object[]]$RemediationActions,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$RunTimestamp,
        [object]$GeneratedPaths,
        [string]$Prefix = 'Log4j_Remediation_Results'
    )
    $directory = New-ReportDirectory -Path $OutputPath
    $path = Join-Path $directory ("{0}_{1}.txt" -f $Prefix, $RunTimestamp)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Log4j Detection and Remediation Report')
    $lines.Add(('Generated: {0}' -f (Get-Date)))
    $lines.Add('')
    $lines.Add('Metadata')
    foreach ($property in $Metadata.PSObject.Properties) { $lines.Add(('{0}: {1}' -f $property.Name, $property.Value)) }
    $lines.Add('')
    $lines.Add('Summary')
    foreach ($property in $Summary.PSObject.Properties) { $lines.Add(('{0}: {1}' -f $property.Name, $property.Value)) }
    $lines.Add('')
    $lines.Add('Targets')
    foreach ($target in @($Targets)) { $lines.Add(('{0} - {1} - {2}' -f $target.ServerName, $target.ConnectivityStatus, $target.ScanStatus)) }
    $lines.Add('')
    $lines.Add('Vulnerable And Review Findings')
    foreach ($finding in @($Findings | Where-Object { $_.VulnerabilityClassification -match 'Vulnerable|ManualReview|VendorUpgrade|Log4j1|Mitigation' })) {
        $lines.Add(('{0} | {1} | {2} | {3}' -f $finding.ServerName, $finding.VulnerabilityClassification, $finding.DetectedVersion, $finding.ArtifactPath))
    }
    $lines.Add('')
    $lines.Add('Remediation Actions')
    foreach ($action in @($RemediationActions)) { $lines.Add(('{0} | {1} | {2} | {3}' -f $action.ServerName, $action.ActionType, $action.ResultStatus, $action.ArtifactPath)) }
    $lines.Add('')
    $lines.Add('Failures')
    foreach ($failure in @($Failures)) { $lines.Add(('{0} | {1} | {2}' -f $failure.ServerName, $failure.Status, $failure.FailureReason)) }
    $lines.Add('')
    $lines.Add('Generated Output Paths')
    if ($null -ne $GeneratedPaths) {
        foreach ($property in $GeneratedPaths.PSObject.Properties) { if ($property.Value) { $lines.Add(('{0}: {1}' -f $property.Name, $property.Value)) } }
    }
    $lines | Out-File -LiteralPath $path -Encoding UTF8
    return $path
}

function Export-ReportHtml {
<#
.SYNOPSIS
Exports a self-contained HTML report.
.DESCRIPTION
Creates a readable, self-contained HTML report with embedded CSS and no
external dependencies. The report includes metadata, summary, target summary,
vulnerable findings, all artifacts, remediation actions, failures, and metadata.
.PARAMETER Metadata
Run metadata.
.PARAMETER Summary
Run summary counts.
.PARAMETER Targets
Target result objects.
.PARAMETER Findings
Finding objects.
.PARAMETER RemediationActions
Remediation action objects.
.PARAMETER Failures
Failure objects.
.PARAMETER OutputPath
Destination directory.
.PARAMETER RunTimestamp
Shared report timestamp.
.PARAMETER Prefix
File prefix.
.EXAMPLE
Export-ReportHtml -Metadata $Metadata -Summary $Summary -OutputPath C:\Reports -RunTimestamp 20260525_120000
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [object]$Metadata,
        [object]$Summary,
        [object[]]$Targets,
        [object[]]$Findings,
        [object[]]$RemediationActions,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$RunTimestamp,
        [string]$Prefix = 'Log4j_Remediation_Results'
    )
    $directory = New-ReportDirectory -Path $OutputPath
    $path = Join-Path $directory ("{0}_{1}.html" -f $Prefix, $RunTimestamp)
    $metadataRows = @()
    foreach ($property in $Metadata.PSObject.Properties) { $metadataRows += [pscustomobject]@{ Name = $property.Name; Value = [string]$property.Value } }
    $summaryRows = @()
    foreach ($property in $Summary.PSObject.Properties) { $summaryRows += [pscustomobject]@{ Metric = $property.Name; Value = [string]$property.Value } }
    $vulnerable = @($Findings | Where-Object { $_.VulnerabilityClassification -match 'ConfirmedVulnerable|PotentiallyVulnerable|VendorUpgradeRequired|ManualReviewRequired|Log4j1|Mitigation' })
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f8fa;color:#1f2937}
h1{margin-bottom:4px} h2{margin-top:28px;border-bottom:1px solid #d1d5db;padding-bottom:4px}
.meta{color:#4b5563;margin-bottom:18px} table{border-collapse:collapse;width:100%;background:#fff;margin:12px 0 22px}
th,td{border:1px solid #d1d5db;padding:7px 9px;text-align:left;vertical-align:top;font-size:12px}
th{background:#eef2f7} tr:nth-child(even){background:#fbfdff}
.status-NotDetected,.status-ConnectivityPassed{background:#ecfdf5}
.status-Detected,.status-Preview,.status-WhatIf{background:#eff6ff}
.status-ConfirmedVulnerable,.status-FailedScan,.status-FailedRemediation,.status-ConnectivityFailed{background:#fef2f2}
.status-PotentiallyVulnerableVersionUnknown,.status-ManualReviewRequired,.status-PartialScan,.status-Log4j1JMSAppenderReviewRequired{background:#fffbeb}
.status-Log4j1EndOfLifeDetected,.status-VendorUpgradeRequired,.status-MitigationPresentButUpgradeValidationRequired{background:#fff7ed}
.status-PatchedVersionDetected,.status-Quarantined,.status-Replaced,.status-MitigatedPendingUpgrade{background:#f0fdf4}
'@
    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<!doctype html><html><head><meta charset="utf-8"><title>Log4j Remediation Report</title>')
    [void]$html.AppendLine("<style>$css</style></head><body>")
    [void]$html.AppendLine('<h1>Log4j Detection and Remediation Report</h1>')
    [void]$html.AppendLine(('<div class="meta">Run ID: {0}<br>Generated: {1}<br>Execution Mode: {2}<br>Input Source: {3}<br>Collection Mode: {4}<br>Config Path: {5}<br>CSV Path: {6}</div>' -f (ConvertTo-HtmlEncodedText $Metadata.RunId),(ConvertTo-HtmlEncodedText $Metadata.RunTimestamp),(ConvertTo-HtmlEncodedText $Metadata.ExecutionMode),(ConvertTo-HtmlEncodedText $Metadata.InputSourceMode),(ConvertTo-HtmlEncodedText $Metadata.CollectionMode),(ConvertTo-HtmlEncodedText $Metadata.ConfigPath),(ConvertTo-HtmlEncodedText $Metadata.ServerCsvPath)))
    [void]$html.AppendLine((ConvertTo-ReportHtmlTable -Title 'Executive Summary' -Data $summaryRows))
    [void]$html.AppendLine((ConvertTo-ReportHtmlTable -Title 'Target Server Summary' -Data $Targets -StatusProperty ConnectivityStatus))
    [void]$html.AppendLine((ConvertTo-ReportHtmlTable -Title 'Vulnerable And Review Findings' -Data $vulnerable -StatusProperty VulnerabilityClassification))
    [void]$html.AppendLine((ConvertTo-ReportHtmlTable -Title 'All Discovered Artifacts' -Data $Findings -StatusProperty VulnerabilityClassification))
    [void]$html.AppendLine((ConvertTo-ReportHtmlTable -Title 'Remediation Actions' -Data $RemediationActions -StatusProperty ResultStatus))
    [void]$html.AppendLine((ConvertTo-ReportHtmlTable -Title 'Failures' -Data $Failures -StatusProperty Status))
    [void]$html.AppendLine((ConvertTo-ReportHtmlTable -Title 'Metadata' -Data $metadataRows))
    [void]$html.AppendLine('</body></html>')
    $html.ToString() | Out-File -LiteralPath $path -Encoding UTF8
    return $path
}

function Export-ReportBundle {
<#
.SYNOPSIS
Exports report data in the enabled formats.
.DESCRIPTION
Creates CSV, JSON, TXT, and/or HTML reports using one shared run timestamp.
Only formats supplied in ReportFormats are generated. The function returns a
single object listing generated report paths.
.PARAMETER Metadata
Run metadata.
.PARAMETER Summary
Run summary counts.
.PARAMETER Targets
Target result objects.
.PARAMETER Findings
Finding objects.
.PARAMETER RemediationActions
Remediation action objects.
.PARAMETER Failures
Failure objects.
.PARAMETER OutputPath
Destination directory.
.PARAMETER ReportFormats
Enabled report formats: CSV, JSON, TXT, HTML.
.PARAMETER Prefix
File prefix.
.EXAMPLE
Export-ReportBundle -Metadata $Metadata -Summary $Summary -OutputPath C:\Reports -ReportFormats CSV,HTML
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [object]$Metadata,
        [object]$Summary,
        [object[]]$Targets,
        [object[]]$Findings,
        [object[]]$RemediationActions,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][ValidateSet('CSV','JSON','TXT','HTML')][string[]]$ReportFormats,
        [string]$Prefix = 'Log4j_Remediation_Results'
    )
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $paths = [ordered]@{ CsvPath = $null; JsonPath = $null; TxtPath = $null; HtmlPath = $null }
    if ($ReportFormats -contains 'CSV') {
        $paths.CsvPath = Export-ReportCsv -Findings $Findings -RemediationActions $RemediationActions -Failures $Failures -OutputPath $OutputPath -RunTimestamp $timestamp -Prefix $Prefix
    }
    if ($ReportFormats -contains 'JSON') {
        $paths.JsonPath = Export-ReportJson -Metadata $Metadata -Summary $Summary -Targets $Targets -Findings $Findings -RemediationActions $RemediationActions -Failures $Failures -OutputPath $OutputPath -RunTimestamp $timestamp -Prefix $Prefix
    }
    if ($ReportFormats -contains 'TXT') {
        $paths.TxtPath = Export-ReportTxt -Metadata $Metadata -Summary $Summary -Targets $Targets -Findings $Findings -RemediationActions $RemediationActions -Failures $Failures -OutputPath $OutputPath -RunTimestamp $timestamp -GeneratedPaths ([pscustomobject]$paths) -Prefix $Prefix
    }
    if ($ReportFormats -contains 'HTML') {
        $paths.HtmlPath = Export-ReportHtml -Metadata $Metadata -Summary $Summary -Targets $Targets -Findings $Findings -RemediationActions $RemediationActions -Failures $Failures -OutputPath $OutputPath -RunTimestamp $timestamp -Prefix $Prefix
    }
    return [pscustomobject]$paths
}

Export-ModuleMember -Function Export-ReportCsv,Export-ReportJson,Export-ReportTxt,Export-ReportHtml,Export-ReportBundle
