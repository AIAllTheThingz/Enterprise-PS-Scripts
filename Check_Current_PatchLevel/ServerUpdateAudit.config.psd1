@{
    Domain = "contoso"
    Username = "Domain Username / Username"

    ServerCsvPath = ".\ServerList.csv"
    OutputPath = ".\Reports"

    UseFqdn = $true
    FqdnSuffix = "contoso.local"

    Reports = @{
        Csv  = $true
        Json = $true
        Txt  = $true
        Html = $true
    }

    Logging = @{
        Enabled = $true
        LogPath = ".\Logs"
    }

    Query = @{
        IncludeHotFix = $true
        IncludeWindowsUpdateHistory = $true
        IncludeDefenderUpdates = $false
        IncludeDotNetUpdates = $true
        IncludeSecurityUpdates = $true
        IncludeCumulativeUpdates = $true
        IncludeGeneralWindowsUpdates = $true
        IncludeServicingStackUpdates = $true

        # Report noise controls.
        # These categories are collected when source collection is enabled, but
        # they only appear in CSV/JSON/TXT/HTML reports when set to $true.
        IncludeSecurityIntelligenceUpdatesInReports = $false
        IncludeSecurityUpdatesInReports = $false

        HistoryMonthsBack = 6
        CategoryFilters = @()
        ExclusionList = @()
    }

    Connection = @{
        TimeoutSeconds = 30
        TestConnectionFirst = $true
        DryRunEnabled = $false
        UseWinRM = $true
    }
}
