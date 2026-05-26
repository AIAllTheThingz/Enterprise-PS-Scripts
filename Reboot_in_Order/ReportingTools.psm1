Set-StrictMode -Version 2.0

function New-ReportOutputDirectory {
<#
.SYNOPSIS
Creates a report output directory.
.DESCRIPTION
Creates the output directory used by the report exporters. Compatible with
Windows PowerShell 5.0 and safe for signed scripts because it does not modify
script content.
.PARAMETER Path
Report output directory.
.EXAMPLE
New-ReportOutputDirectory -Path 'C:\Reports\Reboot_In_Order'
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function ConvertTo-HtmlText {
<#
.SYNOPSIS
Encodes report text for HTML.
.DESCRIPTION
HTML-encodes arbitrary report values before insertion into the self-contained
HTML report.
.PARAMETER Value
Value to encode.
.EXAMPLE
ConvertTo-HtmlText -Value '<value>'
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-ReportTableHtml {
<#
.SYNOPSIS
Converts objects into an HTML table.
.DESCRIPTION
Builds a self-contained HTML table fragment with optional status color classes.
Empty input is rendered as a NoRecords row.
.PARAMETER Title
Section title.
.PARAMETER Data
Objects to render.
.PARAMETER StatusProperty
Optional property used for row status class.
.EXAMPLE
ConvertTo-ReportTableHtml -Title 'Results' -Data $Results -StatusProperty RebootStatus
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [object[]]$Data,
        [string]$StatusProperty
    )
    $rows = @($Data)
    if ($rows.Count -eq 0) {
        $rows = @([pscustomobject]@{ Status = 'NoRecords'; Message = 'No records were generated.' })
        if ([string]::IsNullOrWhiteSpace($StatusProperty)) { $StatusProperty = 'Status' }
    }
    $properties = @()
    foreach ($row in $rows) {
        foreach ($property in $row.PSObject.Properties.Name) {
            if ($properties -notcontains $property) { $properties += $property }
        }
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine("<h2>$(ConvertTo-HtmlText $Title)</h2>")
    [void]$builder.AppendLine('<table>')
    [void]$builder.AppendLine('<thead><tr>')
    foreach ($property in $properties) {
        [void]$builder.AppendLine("<th>$(ConvertTo-HtmlText $property)</th>")
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
            [void]$builder.AppendLine("<td>$(ConvertTo-HtmlText $value)</td>")
        }
        [void]$builder.AppendLine('</tr>')
    }
    [void]$builder.AppendLine('</tbody></table>')
    return $builder.ToString()
}

function Export-RebootReportCsv {
<#
.SYNOPSIS
Exports stack reboot results to CSV.
.DESCRIPTION
Exports the consolidated stack/server results and service check attempts to
timestamped CSV files.
.PARAMETER Results
Per-server reboot results.
.PARAMETER ServiceResults
Per-service check results.
.PARAMETER OutputPath
Report directory.
.PARAMETER RunTimestamp
Shared report timestamp.
.EXAMPLE
Export-RebootReportCsv -Results $Results -ServiceResults $Services -OutputPath C:\Reports -RunTimestamp 20260525_130000
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [object[]]$Results,
        [object[]]$ServiceResults,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$RunTimestamp
    )
    $directory = New-ReportOutputDirectory -Path $OutputPath
    $resultPath = Join-Path $directory ("Reboot_In_Order_Results_{0}.csv" -f $RunTimestamp)
    $servicePath = Join-Path $directory ("Reboot_In_Order_ServiceChecks_{0}.csv" -f $RunTimestamp)
    @($Results) | Export-Csv -LiteralPath $resultPath -NoTypeInformation -Encoding UTF8
    @($ServiceResults) | Export-Csv -LiteralPath $servicePath -NoTypeInformation -Encoding UTF8
    return [pscustomobject]@{ ResultCsvPath = $resultPath; ServiceCsvPath = $servicePath }
}

function Export-RebootReportJson {
<#
.SYNOPSIS
Exports stack reboot results to JSON.
.DESCRIPTION
Writes metadata, summary, per-server results, per-service checks, and failures
to a timestamped JSON file.
.PARAMETER Metadata
Run metadata.
.PARAMETER Summary
Summary object.
.PARAMETER Results
Per-server results.
.PARAMETER ServiceResults
Per-service check results.
.PARAMETER Failures
Failure records.
.PARAMETER OutputPath
Report directory.
.PARAMETER RunTimestamp
Shared report timestamp.
.EXAMPLE
Export-RebootReportJson -Metadata $Metadata -Summary $Summary -Results $Results -OutputPath C:\Reports -RunTimestamp 20260525_130000
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [object]$Metadata,
        [object]$Summary,
        [object[]]$Results,
        [object[]]$ServiceResults,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$RunTimestamp
    )
    $directory = New-ReportOutputDirectory -Path $OutputPath
    $path = Join-Path $directory ("Reboot_In_Order_Results_{0}.json" -f $RunTimestamp)
    [pscustomobject]@{
        Metadata       = $Metadata
        Summary        = $Summary
        Results        = @($Results)
        ServiceResults = @($ServiceResults)
        Failures       = @($Failures)
    } | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $path -Encoding UTF8
    return $path
}

function Export-RebootReportHtml {
<#
.SYNOPSIS
Exports a self-contained HTML stack reboot report.
.DESCRIPTION
Creates a color-coded HTML report grouped by StackName with timeline, service
check status, skipped-service notes, and summary statistics.
.PARAMETER Metadata
Run metadata.
.PARAMETER Summary
Summary object.
.PARAMETER Results
Per-server results.
.PARAMETER ServiceResults
Per-service check results.
.PARAMETER Failures
Failure records.
.PARAMETER OutputPath
Report directory.
.PARAMETER RunTimestamp
Shared report timestamp.
.EXAMPLE
Export-RebootReportHtml -Metadata $Metadata -Summary $Summary -Results $Results -OutputPath C:\Reports -RunTimestamp 20260525_130000
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [object]$Metadata,
        [object]$Summary,
        [object[]]$Results,
        [object[]]$ServiceResults,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$RunTimestamp
    )
    $directory = New-ReportOutputDirectory -Path $OutputPath
    $path = Join-Path $directory ("Reboot_In_Order_Results_{0}.html" -f $RunTimestamp)
    $summaryRows = @()
    foreach ($property in $Summary.PSObject.Properties) { $summaryRows += [pscustomobject]@{ Metric = $property.Name; Value = [string]$property.Value } }
    $metadataRows = @()
    foreach ($property in $Metadata.PSObject.Properties) { $metadataRows += [pscustomobject]@{ Name = $property.Name; Value = [string]$property.Value } }
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;background:#f6f8fb;color:#1f2937;margin:24px}
h1{margin-bottom:4px} h2{margin-top:28px;border-bottom:1px solid #cbd5e1;padding-bottom:4px}
h3{margin-top:22px}.meta{color:#4b5563;margin-bottom:18px}
table{border-collapse:collapse;width:100%;background:#fff;margin:12px 0 24px}
th,td{border:1px solid #cbd5e1;padding:7px 9px;text-align:left;vertical-align:top;font-size:12px}
th{background:#e5edf7} tr:nth-child(even){background:#fbfdff}
.status-Success,.status-Healthy,.status-Passed,.status-WhatIf,.status-SkippedNoServices{background:#ecfdf5}
.status-SkippedBySchedule,.status-SkippedOutsideMaintenanceWindow,.status-SkippedDisabled,.status-ContinueOnFailure,.status-Warning{background:#fffbeb}
.status-Failed,.status-FailedPreCheck,.status-FailedReboot,.status-FailedHealthCheck,.status-FailedServiceValidation,.status-TerminatingFailure{background:#fef2f2}
.status-InProgress,.status-Waiting{background:#eff6ff}
'@
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('<!doctype html><html><head><meta charset="utf-8"><title>Reboot In Order Report</title>')
    [void]$builder.AppendLine("<style>$css</style></head><body>")
    [void]$builder.AppendLine('<h1>Reboot In Order Report</h1>')
    [void]$builder.AppendLine(('<div class="meta">Run ID: {0}<br>Generated: {1}<br>Execution Mode: {2}<br>Stack CSV: {3}</div>' -f (ConvertTo-HtmlText $Metadata.RunId),(ConvertTo-HtmlText $Metadata.RunTimestamp),(ConvertTo-HtmlText $Metadata.ExecutionMode),(ConvertTo-HtmlText $Metadata.StackCsvPath)))
    [void]$builder.AppendLine((ConvertTo-ReportTableHtml -Title 'Summary Statistics' -Data $summaryRows))
    foreach ($stackName in @($Results | Select-Object -ExpandProperty StackName -Unique | Sort-Object)) {
        [void]$builder.AppendLine("<h2>Stack: $(ConvertTo-HtmlText $stackName)</h2>")
        $stackRows = @($Results | Where-Object { $_.StackName -eq $stackName } | Sort-Object RebootOrder)
        [void]$builder.AppendLine((ConvertTo-ReportTableHtml -Title 'Execution Timeline' -Data $stackRows -StatusProperty RebootStatus))
        $stackServices = @($ServiceResults | Where-Object { $_.StackName -eq $stackName })
        [void]$builder.AppendLine((ConvertTo-ReportTableHtml -Title 'Service Checks' -Data $stackServices -StatusProperty ServiceCheckStatus))
    }
    [void]$builder.AppendLine((ConvertTo-ReportTableHtml -Title 'Failures' -Data $Failures -StatusProperty Status))
    [void]$builder.AppendLine((ConvertTo-ReportTableHtml -Title 'Metadata' -Data $metadataRows))
    [void]$builder.AppendLine('</body></html>')
    $builder.ToString() | Out-File -LiteralPath $path -Encoding UTF8
    return $path
}

function Export-RebootReportBundle {
<#
.SYNOPSIS
Exports all enabled report formats.
.DESCRIPTION
Exports CSV, JSON, and HTML reports using one shared timestamp and returns the
generated report paths.
.PARAMETER Metadata
Run metadata.
.PARAMETER Summary
Summary object.
.PARAMETER Results
Per-server results.
.PARAMETER ServiceResults
Per-service results.
.PARAMETER Failures
Failure records.
.PARAMETER OutputPath
Report directory.
.PARAMETER ReportFormats
Enabled report formats.
.EXAMPLE
Export-RebootReportBundle -Metadata $Metadata -Summary $Summary -Results $Results -OutputPath C:\Reports -ReportFormats CSV,JSON,HTML
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [object]$Metadata,
        [object]$Summary,
        [object[]]$Results,
        [object[]]$ServiceResults,
        [object[]]$Failures,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][ValidateSet('CSV','JSON','HTML')][string[]]$ReportFormats
    )
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $paths = [ordered]@{ ResultCsvPath = $null; ServiceCsvPath = $null; JsonPath = $null; HtmlPath = $null }
    if ($ReportFormats -contains 'CSV') {
        $csv = Export-RebootReportCsv -Results $Results -ServiceResults $ServiceResults -OutputPath $OutputPath -RunTimestamp $timestamp
        $paths.ResultCsvPath = $csv.ResultCsvPath
        $paths.ServiceCsvPath = $csv.ServiceCsvPath
    }
    if ($ReportFormats -contains 'JSON') {
        $paths.JsonPath = Export-RebootReportJson -Metadata $Metadata -Summary $Summary -Results $Results -ServiceResults $ServiceResults -Failures $Failures -OutputPath $OutputPath -RunTimestamp $timestamp
    }
    if ($ReportFormats -contains 'HTML') {
        $paths.HtmlPath = Export-RebootReportHtml -Metadata $Metadata -Summary $Summary -Results $Results -ServiceResults $ServiceResults -Failures $Failures -OutputPath $OutputPath -RunTimestamp $timestamp
    }
    return [pscustomobject]$paths
}

Export-ModuleMember -Function Export-RebootReportCsv,Export-RebootReportJson,Export-RebootReportHtml,Export-RebootReportBundle
