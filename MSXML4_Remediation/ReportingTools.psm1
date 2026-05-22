Set-StrictMode -Version 2.0

function ConvertTo-ObjectArray {
<#
.SYNOPSIS
Normalizes pipeline input into a stable object array.

.DESCRIPTION
Returns an empty array for null input and a one-or-more item object array for
single objects or collections so that strict-mode report logic can safely use
Count and index operations.

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

function New-ReportFilePath {
<#
.SYNOPSIS
Builds a timestamped report file path.

.DESCRIPTION
Creates the output directory when needed and returns a timestamped file name
that is safe for repeated report exports.

.PARAMETER OutputPath
The folder that will hold the report file.

.PARAMETER BaseFileName
The base file name without extension.

.PARAMETER Extension
The report file extension without a leading period.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$Extension
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $sanitizedBaseName = $BaseFileName -replace '[^a-zA-Z0-9_\.-]', '_'
    Join-Path -Path $OutputPath -ChildPath ('{0}_{1}.{2}' -f $sanitizedBaseName, $timestamp, $Extension)
}

function Convert-ObjectsToHtmlTable {
<#
.SYNOPSIS
Converts objects into an HTML table fragment.

.DESCRIPTION
Normalizes empty collections and converts a set of PowerShell objects into a
simple HTML table fragment for reusable report rendering.

.PARAMETER InputObject
The objects to render.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$InputObject
    )

    $items = ConvertTo-ObjectArray -InputObject $InputObject

    if ($items.Count -eq 0) {
        return '<p class="empty">No records available.</p>'
    }

    return ($items | ConvertTo-Html -Fragment)
}

function Get-GroupedReportData {
<#
.SYNOPSIS
Builds grouped report data.

.DESCRIPTION
Groups a dataset by a selected property so that text, JSON, and HTML exports
can include grouped summaries without the caller having to pre-process data.

.PARAMETER Data
The records to group.

.PARAMETER GroupProperty
The property name to group by.

.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,

        [string]$GroupProperty
    )

    $items = ConvertTo-ObjectArray -InputObject $Data

    if ($items.Count -eq 0 -or -not $GroupProperty) {
        return ,([object[]]@())
    }

    $groupedResults = @(
        $items |
            Group-Object -Property $GroupProperty |
            ForEach-Object {
                [pscustomobject]@{
                    Name  = $_.Name
                    Count = $_.Count
                    Items = @($_.Group)
                }
            }
    )

    return ,([object[]]$groupedResults)
}

function Export-ReportCsv {
<#
.SYNOPSIS
Exports report records to CSV.

.DESCRIPTION
Writes report records to a timestamped CSV file. The function is generic and
can be reused by other scripts that emit arrays of PowerShell objects.

.PARAMETER Data
The records to export.

.PARAMETER OutputPath
The folder that will hold the report.

.PARAMETER BaseFileName
The base file name without extension.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName
    )

    $path = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'csv'
    $records = ConvertTo-ObjectArray -InputObject $Data

    if ($records.Count -gt 0) {
        $records | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }
    else {
        '' | Set-Content -Path $path -Encoding UTF8
    }

    return $path
}

function Export-ReportJson {
<#
.SYNOPSIS
Exports report data to JSON.

.DESCRIPTION
Builds a structured JSON report that includes report records together with
optional summary, failure, and metadata objects.

.PARAMETER Data
The records to export.

.PARAMETER OutputPath
The folder that will hold the report.

.PARAMETER BaseFileName
The base file name without extension.

.PARAMETER Title
The report title.

.PARAMETER Summary
Optional summary object.

.PARAMETER FailedItems
Optional failed-items object array.

.PARAMETER Metadata
Optional metadata object.

.PARAMETER GroupProperty
Optional property name used to include grouped data in the JSON payload.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [AllowNull()]
        [object]$Summary,

        [AllowNull()]
        [object[]]$FailedItems,

        [AllowNull()]
        [object]$Metadata
        ,
        [string]$GroupProperty
    )

    $path = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'json'

    $records = ConvertTo-ObjectArray -InputObject $Data
    $groupedData = ConvertTo-ObjectArray -InputObject (Get-GroupedReportData -Data $records -GroupProperty $GroupProperty)

    $payload = [pscustomobject]@{
        Title       = $Title
        GeneratedOn = (Get-Date).ToString('s')
        Metadata    = $Metadata
        Summary     = $Summary
        FailedItems = (ConvertTo-ObjectArray -InputObject $FailedItems)
        Groups      = $groupedData
        Records     = $records
    }

    $payload | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
    return $path
}

function Export-ReportTxt {
<#
.SYNOPSIS
Exports a plain-text report.

.DESCRIPTION
Renders metadata, summary, failure details, and the main records as plain text
for easy email attachment, ticket upload, or console review.

.PARAMETER Data
The records to export.

.PARAMETER OutputPath
The folder that will hold the report.

.PARAMETER BaseFileName
The base file name without extension.

.PARAMETER Title
The report title.

.PARAMETER Summary
Optional summary object.

.PARAMETER FailedItems
Optional failed-items object array.

.PARAMETER Metadata
Optional metadata object.

.PARAMETER GroupProperty
Optional property name used to render grouped text output.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [AllowNull()]
        [object]$Summary,

        [AllowNull()]
        [object[]]$FailedItems,

        [AllowNull()]
        [object]$Metadata
        ,
        [string]$GroupProperty
    )

    $path = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'txt'
    $builder = New-Object System.Text.StringBuilder

    [void]$builder.AppendLine($Title)
    [void]$builder.AppendLine(('GeneratedOn: {0}' -f (Get-Date).ToString('s')))
    [void]$builder.AppendLine('')

    if ($Metadata) {
        [void]$builder.AppendLine('Metadata')
        [void]$builder.AppendLine('--------')
        foreach ($property in $Metadata.PSObject.Properties) {
            [void]$builder.AppendLine(('{0}: {1}' -f $property.Name, $property.Value))
        }
        [void]$builder.AppendLine('')
    }

    if ($Summary) {
        [void]$builder.AppendLine('Summary')
        [void]$builder.AppendLine('-------')
        foreach ($property in $Summary.PSObject.Properties) {
            [void]$builder.AppendLine(('{0}: {1}' -f $property.Name, $property.Value))
        }
        [void]$builder.AppendLine('')
    }

    $records = ConvertTo-ObjectArray -InputObject $Data
    $failedRecords = ConvertTo-ObjectArray -InputObject $FailedItems

    if ($failedRecords.Count -gt 0) {
        [void]$builder.AppendLine('FailedItems')
        [void]$builder.AppendLine('-----------')
        [void]$builder.AppendLine(($failedRecords | Format-Table -AutoSize | Out-String))
        [void]$builder.AppendLine('')
    }

    if ($GroupProperty) {
        $groupedData = ConvertTo-ObjectArray -InputObject (Get-GroupedReportData -Data $records -GroupProperty $GroupProperty)
        [void]$builder.AppendLine('Groups')
        [void]$builder.AppendLine('------')
        if ($groupedData.Count -gt 0) {
            foreach ($group in $groupedData) {
                [void]$builder.AppendLine(('{0}: {1}' -f $group.Name, $group.Count))
            }
        }
        else {
            [void]$builder.AppendLine('No grouped records available.')
        }
        [void]$builder.AppendLine('')
    }

    [void]$builder.AppendLine('Records')
    [void]$builder.AppendLine('-------')
    if ($records.Count -gt 0) {
        [void]$builder.AppendLine(($records | Format-Table -AutoSize | Out-String))
    }
    else {
        [void]$builder.AppendLine('No records available.')
    }

    $builder.ToString() | Set-Content -Path $path -Encoding UTF8
    return $path
}

function Export-ReportHtml {
<#
.SYNOPSIS
Exports an HTML report.

.DESCRIPTION
Creates a self-contained HTML report with embedded CSS, report metadata,
summary details, optional failure records, and the main dataset.

.PARAMETER Data
The records to export.

.PARAMETER OutputPath
The folder that will hold the report.

.PARAMETER BaseFileName
The base file name without extension.

.PARAMETER Title
The report title.

.PARAMETER Summary
Optional summary object.

.PARAMETER FailedItems
Optional failed-items object array.

.PARAMETER Metadata
Optional metadata object.

.PARAMETER GroupProperty
Optional property name used to render grouped sections in HTML.

.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [AllowNull()]
        [object]$Summary,

        [AllowNull()]
        [object[]]$FailedItems,

        [AllowNull()]
        [object]$Metadata
        ,
        [string]$GroupProperty
    )

    $path = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'html'

    $css = @'
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #202124; background: #f7f9fb; }
h1, h2 { color: #183153; }
.panel { background: #ffffff; border: 1px solid #d8e1ea; border-radius: 6px; padding: 16px; margin-bottom: 20px; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #183153; color: #ffffff; text-align: left; padding: 8px; }
td { border: 1px solid #d8e1ea; padding: 6px; vertical-align: top; }
tr:nth-child(even) { background: #f5f8fc; }
.empty { color: #5f6368; font-style: italic; }
'@

    $records = ConvertTo-ObjectArray -InputObject $Data
    $groupedData = ConvertTo-ObjectArray -InputObject (Get-GroupedReportData -Data $records -GroupProperty $GroupProperty)
    $metadataHtml = Convert-ObjectsToHtmlTable -InputObject (ConvertTo-ObjectArray -InputObject $Metadata)
    $summaryHtml = Convert-ObjectsToHtmlTable -InputObject (ConvertTo-ObjectArray -InputObject $Summary)
    $failedHtml = Convert-ObjectsToHtmlTable -InputObject (ConvertTo-ObjectArray -InputObject $FailedItems)
    $recordsHtml = Convert-ObjectsToHtmlTable -InputObject $records
    $groupedHtml = ''

    if ($groupedData.Count -gt 0) {
        foreach ($group in $groupedData) {
            $groupedHtml += "<div class=""panel""><h2>Group: $($group.Name) ($($group.Count))</h2>$((Convert-ObjectsToHtmlTable -InputObject $group.Items))</div>`n"
        }
    }
    else {
        $groupedHtml = '<div class="panel"><h2>Groups</h2><p class="empty">No grouped records available.</p></div>'
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>$Title</title>
<style>$css</style>
</head>
<body>
<h1>$Title</h1>
<div class="panel">
<strong>GeneratedOn:</strong> $(Get-Date -Format s)
</div>
<div class="panel">
<h2>Metadata</h2>
$metadataHtml
</div>
<div class="panel">
<h2>Summary</h2>
$summaryHtml
</div>
<div class="panel">
<h2>Failed Items</h2>
$failedHtml
</div>
<div class="panel">
<h2>Records</h2>
$recordsHtml
</div>
$groupedHtml
</body>
</html>
"@

    $html | Set-Content -Path $path -Encoding UTF8
    return $path
}

function Export-ReportBundle {
<#
.SYNOPSIS
Exports one dataset to multiple report formats.

.DESCRIPTION
Coordinates reusable CSV, JSON, TXT, and HTML report exports and returns a
summary object that lists every generated artifact path.

.PARAMETER Data
The records to export.

.PARAMETER OutputPath
The folder that will hold the reports.

.PARAMETER BaseFileName
The base file name without extension.

.PARAMETER Title
The report title.

.PARAMETER Formats
The requested report formats.

.PARAMETER Summary
Optional summary object.

.PARAMETER FailedItems
Optional failed-items object array.

.PARAMETER Metadata
Optional metadata object.

.PARAMETER GroupProperty
Optional property name used for grouped exports.

.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [string[]]$Formats = @('Csv', 'Json', 'Html', 'Txt'),

        [AllowNull()]
        [object]$Summary,

        [AllowNull()]
        [object[]]$FailedItems,

        [AllowNull()]
        [object]$Metadata,

        [string]$GroupProperty
    )

    $paths = [ordered]@{}

    foreach ($format in $Formats) {
        switch ($format.ToLowerInvariant()) {
            'csv' {
                $paths.Csv = Export-ReportCsv -Data $Data -OutputPath $OutputPath -BaseFileName $BaseFileName
            }
            'json' {
                $paths.Json = Export-ReportJson -Data $Data -OutputPath $OutputPath -BaseFileName $BaseFileName -Title $Title -Summary $Summary -FailedItems $FailedItems -Metadata $Metadata -GroupProperty $GroupProperty
            }
            'txt' {
                $paths.Txt = Export-ReportTxt -Data $Data -OutputPath $OutputPath -BaseFileName $BaseFileName -Title $Title -Summary $Summary -FailedItems $FailedItems -Metadata $Metadata -GroupProperty $GroupProperty
            }
            'html' {
                $paths.Html = Export-ReportHtml -Data $Data -OutputPath $OutputPath -BaseFileName $BaseFileName -Title $Title -Summary $Summary -FailedItems $FailedItems -Metadata $Metadata -GroupProperty $GroupProperty
            }
        }
    }

    return [pscustomobject]@{
        Title       = $Title
        BaseName    = $BaseFileName
        Formats     = $Formats
        OutputFiles = [pscustomobject]$paths
    }
}

Export-ModuleMember -Function Export-ReportCsv, Export-ReportJson, Export-ReportTxt, Export-ReportHtml, Export-ReportBundle
