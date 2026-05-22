Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Builds a timestamped output file path for report exports.

.DESCRIPTION
Creates a consistent, timestamped report file name using a base file name and
extension. This keeps the reporting module generic and reusable across scripts.

.PARAMETER OutputPath
Directory where the file should be created.

.PARAMETER BaseFileName
Logical report name without an extension.

.PARAMETER Extension
File extension without a leading period.

.PARAMETER TimeStamp
Timestamp string that should be embedded in the file name.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function New-ReportFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Extension,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TimeStamp
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $fileName = '{0}_{1}.{2}' -f $BaseFileName, $TimeStamp, $Extension
    return (Join-Path -Path $OutputPath -ChildPath $fileName)
}

<#
.SYNOPSIS
Converts an object collection into a readable plain-text block.

.DESCRIPTION
Formats object data as a list-style text section that can be embedded in TXT
reports. The function favors readability over compactness so support staff can
quickly inspect report content without opening a structured format.

.PARAMETER Data
Objects to format.

.PARAMETER Heading
Heading to display above the data block.

.OUTPUTS
System.String[]

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function ConvertTo-ReportTextBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Heading
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($Heading)
    $lines.Add(('-' * $Heading.Length))

    if ($null -eq $Data -or $Data.Count -eq 0) {
        $lines.Add('No data available.')
        $lines.Add('')
        return $lines.ToArray()
    }

    $formatted = $Data | Format-List * | Out-String
    foreach ($line in ($formatted -split "(`r`n|`n)")) {
        $lines.Add($line)
    }

    $lines.Add('')
    return $lines.ToArray()
}

<#
.SYNOPSIS
Returns default HTML styling used by report exports.

.DESCRIPTION
Provides an embedded CSS stylesheet when the caller does not supply custom CSS.
The default style is intentionally neutral and uses color coding for status
values commonly seen in operational reports.

.PARAMETER CustomCss
Optional CSS string supplied by the caller.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Get-ReportCss {
    [CmdletBinding()]
    param(
        [string]$CustomCss
    )

    if (-not [string]::IsNullOrWhiteSpace($CustomCss)) {
        return $CustomCss
    }

    return @'
body {
    font-family: Segoe UI, Arial, sans-serif;
    font-size: 13px;
    color: #1f2937;
    margin: 20px;
    background-color: #f8fafc;
}
h1, h2, h3 {
    color: #0f172a;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 20px;
    background-color: #ffffff;
}
th, td {
    border: 1px solid #cbd5e1;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}
th {
    background-color: #e2e8f0;
}
tr:nth-child(even) {
    background-color: #f8fafc;
}
.status-success {
    background-color: #dcfce7;
    color: #166534;
    font-weight: 600;
}
.status-warning {
    background-color: #fef3c7;
    color: #92400e;
    font-weight: 600;
}
.status-failed {
    background-color: #fee2e2;
    color: #991b1b;
    font-weight: 600;
}
.meta-table td:first-child {
    font-weight: 600;
    width: 220px;
}
.section {
    margin-top: 24px;
}
'@
}

<#
.SYNOPSIS
Builds HTML markup for a collection of report objects.

.DESCRIPTION
Creates a standalone HTML document containing report metadata, optional
summary and failed-item sections, and one or more data tables. Data can be
grouped by a chosen property to make large reports easier to navigate.

.PARAMETER Data
Objects to include in the main report table or grouped tables.

.PARAMETER Title
Report title displayed in the HTML output.

.PARAMETER GroupBy
Optional property name used to group the main data.

.PARAMETER Summary
Optional summary objects to render near the top of the report.

.PARAMETER FailedItems
Optional failed-item objects to render in a separate table.

.PARAMETER Metadata
Optional metadata hashtable displayed near the top of the report.

.PARAMETER Css
CSS to embed in the HTML output.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function ConvertTo-ReportHtmlDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [string]$GroupBy,

        [object[]]$Summary,

        [object[]]$FailedItems,

        [hashtable]$Metadata,

        [Parameter(Mandatory = $true)]
        [string]$Css
    )

    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<!DOCTYPE html>')
    [void]$html.AppendLine('<html>')
    [void]$html.AppendLine('<head>')
    [void]$html.AppendLine('<meta charset="utf-8" />')
    [void]$html.AppendLine('<title>' + [System.Web.HttpUtility]::HtmlEncode($Title) + '</title>')
    [void]$html.AppendLine('<style>')
    [void]$html.AppendLine($Css)
    [void]$html.AppendLine('</style>')
    [void]$html.AppendLine('</head>')
    [void]$html.AppendLine('<body>')
    [void]$html.AppendLine('<h1>' + [System.Web.HttpUtility]::HtmlEncode($Title) + '</h1>')

    if ($Metadata -and $Metadata.Count -gt 0) {
        [void]$html.AppendLine('<div class="section">')
        [void]$html.AppendLine('<h2>Metadata</h2>')
        [void]$html.AppendLine('<table class="meta-table">')
        foreach ($key in ($Metadata.Keys | Sort-Object)) {
            $value = [string]$Metadata[$key]
            [void]$html.AppendLine('<tr><td>' + [System.Web.HttpUtility]::HtmlEncode([string]$key) + '</td><td>' + [System.Web.HttpUtility]::HtmlEncode($value) + '</td></tr>')
        }
        [void]$html.AppendLine('</table>')
        [void]$html.AppendLine('</div>')
    }

    if ($Summary -and $Summary.Count -gt 0) {
        [void]$html.AppendLine('<div class="section">')
        [void]$html.AppendLine('<h2>Summary</h2>')
        [void]$html.AppendLine(($Summary | ConvertTo-Html -Fragment))
        [void]$html.AppendLine('</div>')
    }

    if ($FailedItems -and $FailedItems.Count -gt 0) {
        [void]$html.AppendLine('<div class="section">')
        [void]$html.AppendLine('<h2>Failed Items</h2>')
        [void]$html.AppendLine(($FailedItems | ConvertTo-Html -Fragment))
        [void]$html.AppendLine('</div>')
    }

    [void]$html.AppendLine('<div class="section">')
    [void]$html.AppendLine('<h2>Data</h2>')

    if ($null -eq $Data -or $Data.Count -eq 0) {
        [void]$html.AppendLine('<p>No data available.</p>')
    }
    elseif (-not [string]::IsNullOrWhiteSpace($GroupBy) -and ($Data | Get-Member -MemberType NoteProperty,Property | Select-Object -ExpandProperty Name -Unique) -contains $GroupBy) {
        $groups = $Data | Group-Object -Property $GroupBy | Sort-Object -Property Name
        foreach ($group in $groups) {
            [void]$html.AppendLine('<h3>' + [System.Web.HttpUtility]::HtmlEncode([string]$group.Name) + '</h3>')
            [void]$html.AppendLine(($group.Group | ConvertTo-Html -Fragment))
        }
    }
    else {
        [void]$html.AppendLine(($Data | ConvertTo-Html -Fragment))
    }

    [void]$html.AppendLine('</div>')
    [void]$html.AppendLine('</body>')
    [void]$html.AppendLine('</html>')

    $document = $html.ToString()
    $document = $document -replace '(?i)<td>(Success|True|Online-Compliant|Reachable)</td>', '<td class="status-success">$1</td>'
    $document = $document -replace '(?i)<td>(Warning|Skipped|Partial|Unknown|Offline|QueryFailed|Online-NonCompliant)</td>', '<td class="status-warning">$1</td>'
    $document = $document -replace '(?i)<td>(Failed|False|Error|AccessDenied|AuthenticationFailed)</td>', '<td class="status-failed">$1</td>'

    return $document
}

<#
.SYNOPSIS
Exports structured data to a CSV report.

.DESCRIPTION
Writes the provided objects to a timestamped CSV file in the selected output
directory.

.PARAMETER Data
Objects to export.

.PARAMETER OutputPath
Directory where the report should be written.

.PARAMETER BaseFileName
Base file name used to build the final output file path.

.PARAMETER TimeStamp
Timestamp string embedded in the file name.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Export-ReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$TimeStamp
    )

    $filePath = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'csv' -TimeStamp $TimeStamp
    $Data | Export-Csv -LiteralPath $filePath -NoTypeInformation -Encoding UTF8
    return $filePath
}

<#
.SYNOPSIS
Exports structured data to a JSON report.

.DESCRIPTION
Serializes the provided objects to JSON and writes them to a timestamped file.

.PARAMETER Data
Objects to export.

.PARAMETER OutputPath
Directory where the report should be written.

.PARAMETER BaseFileName
Base file name used to build the final output file path.

.PARAMETER TimeStamp
Timestamp string embedded in the file name.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Export-ReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$TimeStamp
    )

    $filePath = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'json' -TimeStamp $TimeStamp
    $json = $Data | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $filePath -Value $json -Encoding UTF8
    return $filePath
}

<#
.SYNOPSIS
Exports structured data to a plain-text report.

.DESCRIPTION
Creates a readable text report containing metadata, summary information, failed
items, and the main data section.

.PARAMETER Data
Objects to include in the main report body.

.PARAMETER Title
Title shown at the top of the text report.

.PARAMETER OutputPath
Directory where the report should be written.

.PARAMETER BaseFileName
Base file name used to build the final output file path.

.PARAMETER TimeStamp
Timestamp string embedded in the file name.

.PARAMETER Summary
Optional summary objects.

.PARAMETER FailedItems
Optional failed-item objects.

.PARAMETER Metadata
Optional metadata hashtable.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Export-ReportTxt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$TimeStamp,

        [object[]]$Summary,

        [object[]]$FailedItems,

        [hashtable]$Metadata
    )

    $filePath = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'txt' -TimeStamp $TimeStamp
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($Title)
    $lines.Add(('=' * $Title.Length))
    $lines.Add('')

    if ($Metadata -and $Metadata.Count -gt 0) {
        $lines.Add('Metadata')
        $lines.Add('--------')
        foreach ($key in ($Metadata.Keys | Sort-Object)) {
            $metadataLine = '{0}: {1}' -f $key, [string]$Metadata[$key]
            $lines.Add($metadataLine)
        }
        $lines.Add('')
    }

    if ($Summary) {
        foreach ($line in (ConvertTo-ReportTextBlock -Data $Summary -Heading 'Summary')) {
            $lines.Add($line)
        }
    }

    if ($FailedItems) {
        foreach ($line in (ConvertTo-ReportTextBlock -Data $FailedItems -Heading 'Failed Items')) {
            $lines.Add($line)
        }
    }

    foreach ($line in (ConvertTo-ReportTextBlock -Data $Data -Heading 'Data')) {
        $lines.Add($line)
    }

    Set-Content -LiteralPath $filePath -Value $lines -Encoding UTF8
    return $filePath
}

<#
.SYNOPSIS
Exports structured data to an HTML report.

.DESCRIPTION
Creates a standalone HTML report with embedded CSS, metadata, summary content,
optional failed-item details, and main data tables.

.PARAMETER Data
Objects to include in the main report body.

.PARAMETER Title
Title shown at the top of the HTML report.

.PARAMETER OutputPath
Directory where the report should be written.

.PARAMETER BaseFileName
Base file name used to build the final output file path.

.PARAMETER TimeStamp
Timestamp string embedded in the file name.

.PARAMETER GroupBy
Optional property name used to group the main data.

.PARAMETER Summary
Optional summary objects.

.PARAMETER FailedItems
Optional failed-item objects.

.PARAMETER Metadata
Optional metadata hashtable.

.PARAMETER Css
Optional custom CSS.

.OUTPUTS
System.String

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Export-ReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [string]$TimeStamp,

        [string]$GroupBy,

        [object[]]$Summary,

        [object[]]$FailedItems,

        [hashtable]$Metadata,

        [string]$Css
    )

    Add-Type -AssemblyName System.Web
    $filePath = New-ReportFilePath -OutputPath $OutputPath -BaseFileName $BaseFileName -Extension 'html' -TimeStamp $TimeStamp
    $style = Get-ReportCss -CustomCss $Css
    $document = ConvertTo-ReportHtmlDocument -Data $Data -Title $Title -GroupBy $GroupBy -Summary $Summary -FailedItems $FailedItems -Metadata $Metadata -Css $style
    Set-Content -LiteralPath $filePath -Value $document -Encoding UTF8
    return $filePath
}

<#
.SYNOPSIS
Exports one or more reports from the same object collection.

.DESCRIPTION
Generates a bundle of CSV, JSON, TXT, and/or HTML reports using a shared
timestamp and common metadata. This is the main entry point intended for reuse
by other scripts.

.PARAMETER Data
Objects to export.

.PARAMETER Title
Title used by TXT and HTML output.

.PARAMETER OutputPath
Directory where reports should be written.

.PARAMETER BaseFileName
Base file name used to build report file names.

.PARAMETER Formats
One or more report formats. Supported values are Csv, Json, Txt, and Html.

.PARAMETER GroupBy
Optional property used to group the main data in HTML output.

.PARAMETER Summary
Optional summary objects.

.PARAMETER FailedItems
Optional failed-item objects.

.PARAMETER Metadata
Optional metadata hashtable.

.PARAMETER Css
Optional custom CSS for HTML output.

.PARAMETER TimeStamp
Optional timestamp override. When omitted, the current date/time is used.

.OUTPUTS
System.Collections.Hashtable

.NOTES
Compatible with Windows PowerShell 5.1.
#>
function Export-ReportBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseFileName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Csv', 'Json', 'Txt', 'Html')]
        [string[]]$Formats,

        [string]$GroupBy,

        [object[]]$Summary,

        [object[]]$FailedItems,

        [hashtable]$Metadata,

        [string]$Css,

        [string]$TimeStamp
    )

    if ([string]::IsNullOrWhiteSpace($TimeStamp)) {
        $TimeStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    }

    $outputFiles = @{}
    foreach ($format in $Formats | Select-Object -Unique) {
        switch ($format) {
            'Csv' {
                $outputFiles['Csv'] = Export-ReportCsv -Data $Data -OutputPath $OutputPath -BaseFileName $BaseFileName -TimeStamp $TimeStamp
            }
            'Json' {
                $outputFiles['Json'] = Export-ReportJson -Data $Data -OutputPath $OutputPath -BaseFileName $BaseFileName -TimeStamp $TimeStamp
            }
            'Txt' {
                $outputFiles['Txt'] = Export-ReportTxt -Data $Data -Title $Title -OutputPath $OutputPath -BaseFileName $BaseFileName -TimeStamp $TimeStamp -Summary $Summary -FailedItems $FailedItems -Metadata $Metadata
            }
            'Html' {
                $outputFiles['Html'] = Export-ReportHtml -Data $Data -Title $Title -OutputPath $OutputPath -BaseFileName $BaseFileName -TimeStamp $TimeStamp -GroupBy $GroupBy -Summary $Summary -FailedItems $FailedItems -Metadata $Metadata -Css $Css
            }
        }
    }

    return $outputFiles
}

Export-ModuleMember -Function Export-ReportCsv, Export-ReportJson, Export-ReportTxt, Export-ReportHtml, Export-ReportBundle
