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
        IncludeDefenderUpdates = $true
        IncludeDotNetUpdates = $true
        IncludeSecurityUpdates = $true
        IncludeCumulativeUpdates = $true
        IncludeGeneralWindowsUpdates = $true
        IncludeServicingStackUpdates = $true
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
