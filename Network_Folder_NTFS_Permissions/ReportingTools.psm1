Set-StrictMode -Version 2.0

function ConvertTo-HtmlSafeText {
<#
.SYNOPSIS
HTML-encodes report text.
.DESCRIPTION
Encodes values before inserting them into the self-contained HTML report.
.PARAMETER Value
Value to encode.
.EXAMPLE
ConvertTo-HtmlSafeText -Value '<folder>'
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-StructuredAuditJson {
<#
.SYNOPSIS
Converts flat audit rows to structured JSON data.
.DESCRIPTION
Groups flat permission rows into server, share, and folder objects so hierarchy
is preserved in JSON reports.
.PARAMETER Rows
Flat report rows.
.PARAMETER Errors
Error records.
.EXAMPLE
ConvertTo-StructuredAuditJson -Rows $Rows -Errors $Errors
.OUTPUTS
System.Object[]
#>
    [CmdletBinding()]
    param([object[]]$Rows,[object[]]$Errors)
    $servers = @()
    foreach ($serverGroup in @($Rows | Group-Object ServerName)) {
        $shares = @()
        foreach ($shareGroup in @($serverGroup.Group | Group-Object ShareName)) {
            $folders = @()
            foreach ($folderGroup in @($shareGroup.Group | Group-Object FolderPath)) {
                $first = $folderGroup.Group[0]
                $folders += [pscustomobject]@{
                    FolderPath = $first.FolderPath
                    FolderName = $first.FolderName
                    ParentFolder = $first.ParentFolder
                    FolderDepth = $first.FolderDepth
                    FolderTree = $first.FolderTree
                    IsShareRoot = $first.IsShareRoot
                    Owner = $first.Owner
                    EnumerationStatus = $first.EnumerationStatus
                    Permissions = @($folderGroup.Group | Select-Object SharePermissionIdentity,SharePermissionAccessControlType,SharePermissionRight,NTFSIdentity,NTFSAccessControlType,NTFSRights,NTFSIsInherited,NTFSInheritanceFlags,NTFSPropagationFlags,ErrorMessage)
                }
            }
            $shareFirst = $shareGroup.Group[0]
            $shares += [pscustomobject]@{
                ShareName = $shareFirst.ShareName
                SharePath = $shareFirst.SharePath
                ShareDescription = $shareFirst.ShareDescription
                Folders = $folders
            }
        }
        $servers += [pscustomobject]@{
            ServerName = $serverGroup.Name
            Shares = $shares
            Errors = @($Errors | Where-Object { $_.ServerName -eq $serverGroup.Name })
        }
    }
    return $servers
}

function New-HtmlReport {
<#
.SYNOPSIS
Builds a self-contained HTML report.
.DESCRIPTION
Creates an HTML report with embedded CSS and embedded JavaScript for collapsible
folder tree sections. No internet access is required.
.PARAMETER Rows
Flat report rows.
.PARAMETER Errors
Error records.
.PARAMETER Summary
Summary object.
.EXAMPLE
New-HtmlReport -Rows $Rows -Errors $Errors -Summary $Summary
.OUTPUTS
System.String
#>
    [CmdletBinding()]
    param([object[]]$Rows,[object[]]$Errors,[object]$Summary)
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f8fb;color:#1f2937}
h1{margin-bottom:4px} h2{margin-top:28px;border-bottom:1px solid #cbd5e1;padding-bottom:4px}
h3{margin-top:18px}.meta{color:#4b5563;margin-bottom:18px}
table{border-collapse:collapse;width:100%;background:#fff;margin:12px 0 24px}
th,td{border:1px solid #cbd5e1;padding:7px 9px;text-align:left;vertical-align:top;font-size:12px}
th{background:#e5edf7} tr:nth-child(even){background:#fbfdff}
.tree{font-family:Consolas,monospace;white-space:pre;background:#fff;border:1px solid #cbd5e1;padding:12px;margin-bottom:18px}
.ok{background:#ecfdf5}.warn{background:#fffbeb}.err{background:#fef2f2}
button{font-size:12px;padding:4px 8px;margin:4px 0;border:1px solid #94a3b8;background:#f8fafc}
'@
    $js = @'
function toggleSection(id){var e=document.getElementById(id);if(e.style.display==="none"){e.style.display="block";}else{e.style.display="none";}}
'@
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('<!doctype html><html><head><meta charset="utf-8"><title>File Share Permissions Audit</title>')
    [void]$builder.AppendLine("<style>$css</style><script>$js</script></head><body>")
    [void]$builder.AppendLine('<h1>File Share Permissions Audit</h1>')
    [void]$builder.AppendLine(('<div class="meta">Run timestamp: {0}<br>Target servers: {1}<br>Successful servers: {2}<br>Failed servers: {3}<br>Total shares: {4}<br>Total folders: {5}<br>Total permission entries: {6}</div>' -f $Summary.RunTimestamp,$Summary.TargetServerCount,$Summary.SuccessfulServerCount,$Summary.FailedServerCount,$Summary.TotalSharesFound,$Summary.TotalFoldersScanned,$Summary.TotalPermissionEntries))

    [void]$builder.AppendLine('<h2>Server Summary</h2><table><thead><tr><th>Server</th><th>Shares</th><th>Folders</th><th>Permission Entries</th><th>Errors</th><th>Duration Seconds</th></tr></thead><tbody>')
    foreach ($server in @($Rows | Group-Object ServerName)) {
        $serverErrors = @($Errors | Where-Object { $_.ServerName -eq $server.Name }).Count
        $duration = (@($server.Group | Measure-Object ScanDurationSeconds -Maximum).Maximum)
        [void]$builder.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (ConvertTo-HtmlSafeText $server.Name),@($server.Group | Select-Object -ExpandProperty ShareName -Unique).Count,@($server.Group | Select-Object -ExpandProperty FolderPath -Unique).Count,$server.Group.Count,$serverErrors,$duration))
    }
    [void]$builder.AppendLine('</tbody></table>')

    [void]$builder.AppendLine('<h2>Folder Tree By Server And Share</h2>')
    $section = 0
    foreach ($serverGroup in @($Rows | Sort-Object ServerName,ShareName,FolderDepth,FolderPath | Group-Object ServerName)) {
        [void]$builder.AppendLine(('<h3>Server: {0}</h3>' -f (ConvertTo-HtmlSafeText $serverGroup.Name)))
        foreach ($shareGroup in @($serverGroup.Group | Group-Object ShareName)) {
            $section++
            $id = "tree$section"
            [void]$builder.AppendLine(('<button onclick="toggleSection(''{0}'')">Toggle {1}</button>' -f $id,(ConvertTo-HtmlSafeText $shareGroup.Name)))
            [void]$builder.AppendLine(('<div id="{0}" class="tree">' -f $id))
            foreach ($folder in @($shareGroup.Group | Sort-Object FolderDepth,FolderPath | Group-Object FolderPath | ForEach-Object { $_.Group[0] })) {
                [void]$builder.AppendLine((ConvertTo-HtmlSafeText $folder.FolderTree))
            }
            [void]$builder.AppendLine('</div>')
        }
    }

    [void]$builder.AppendLine('<h2>Detailed Permission Entries</h2>')
    if (@($Rows).Count -gt 0) { [void]$builder.AppendLine(($Rows | ConvertTo-Html -Fragment)) } else { [void]$builder.AppendLine('<p>No permission entries were generated.</p>') }
    [void]$builder.AppendLine('<h2>Errors And Inaccessible Folders</h2>')
    if (@($Errors).Count -gt 0) { [void]$builder.AppendLine(($Errors | ConvertTo-Html -Fragment)) } else { [void]$builder.AppendLine('<p>No errors recorded.</p>') }
    [void]$builder.AppendLine('</body></html>')
    return $builder.ToString()
}

function Export-Reports {
<#
.SYNOPSIS
Exports CSV, JSON, and HTML reports.
.DESCRIPTION
Writes enabled enterprise report formats to the configured report path.
.PARAMETER Rows
Flat report rows.
.PARAMETER Errors
Error records.
.PARAMETER Summary
Summary object.
.PARAMETER ReportPath
Report directory.
.PARAMETER ReportPrefix
Report filename prefix.
.PARAMETER Timestamp
Shared timestamp.
.PARAMETER GenerateCSV
Generate CSV.
.PARAMETER GenerateJSON
Generate JSON.
.PARAMETER GenerateHTML
Generate HTML.
.EXAMPLE
Export-Reports -Rows $Rows -Errors $Errors -Summary $Summary -ReportPath C:\Reports -ReportPrefix Audit -Timestamp 20260526_010000 -GenerateCSV -GenerateJSON -GenerateHTML
.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        [object[]]$Errors,
        [object]$Summary,
        [string]$ReportPath,
        [string]$ReportPrefix,
        [string]$Timestamp,
        [bool]$GenerateCSV,
        [bool]$GenerateJSON,
        [bool]$GenerateHTML
    )
    if (-not (Test-Path -LiteralPath $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force -WhatIf:$false | Out-Null }
    $paths = [ordered]@{ CsvPath = $null; JsonPath = $null; HtmlPath = $null }
    $csvRows = @($Rows)
    if ($csvRows.Count -eq 0) { $csvRows = @([pscustomobject]@{ ServerName=''; ShareName=''; SharePath=''; FolderPath=''; FolderName=''; ParentFolder=''; FolderDepth=''; FolderTree=''; IsShareRoot=''; Owner=''; ShareDescription=''; SharePermissionIdentity=''; SharePermissionAccessControlType=''; SharePermissionRight=''; NTFSIdentity=''; NTFSAccessControlType=''; NTFSRights=''; NTFSIsInherited=''; NTFSInheritanceFlags=''; NTFSPropagationFlags=''; EnumerationStatus='NoData'; ErrorMessage='No permission rows generated.'; ScanDurationSeconds='' }) }
    if ($GenerateCSV) {
        $paths.CsvPath = Join-Path $ReportPath ("{0}_{1}.csv" -f $ReportPrefix,$Timestamp)
        $csvRows | Export-Csv -LiteralPath $paths.CsvPath -NoTypeInformation -Encoding UTF8
    }
    if ($GenerateJSON) {
        $paths.JsonPath = Join-Path $ReportPath ("{0}_{1}.json" -f $ReportPrefix,$Timestamp)
        [pscustomobject]@{ Summary=$Summary; Servers=(ConvertTo-StructuredAuditJson -Rows $Rows -Errors $Errors); Errors=@($Errors) } | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $paths.JsonPath -Encoding UTF8
    }
    if ($GenerateHTML) {
        $paths.HtmlPath = Join-Path $ReportPath ("{0}_{1}.html" -f $ReportPrefix,$Timestamp)
        New-HtmlReport -Rows $Rows -Errors $Errors -Summary $Summary | Out-File -LiteralPath $paths.HtmlPath -Encoding UTF8
    }
    return [pscustomobject]$paths
}

Export-ModuleMember -Function New-HtmlReport,Export-Reports
