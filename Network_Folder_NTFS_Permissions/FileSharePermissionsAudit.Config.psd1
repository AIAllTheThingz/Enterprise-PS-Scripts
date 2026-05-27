@{
    ServerCsvPath = "C:\Scripts\FileSharePermissionsAudit\FileSharePermissionsAudit.Servers.csv"

    Output = @{
        ReportPath   = "C:\Reports\FileSharePermissionsAudit"
        LogPath      = "C:\Logs\FileSharePermissionsAudit"
        ReportPrefix = "FileSharePermissionsAudit"
    }

    Enumeration = @{
        EnumerateSubFolders          = $true
        FolderOnlyEnumeration        = $true
        SkipFiles                    = $true
        IncludeInheritedPermissions  = $true
        IncludeAdminShares           = $false
        ExcludeReparsePoints         = $true
        MaxDepth                     = 0
    }

    ShareExclusions = @{
        Shares = @(
            'ADMIN$',
            'C$',
            'D$',
            'IPC$',
            'PRINT$'
        )
    }

    HealthChecks = @{
        Ping  = $true
        WinRM = $true
    }

    Reporting = @{
        GenerateCSV       = $true
        GenerateJSON      = $true
        GenerateHTML      = $true
        IncludeFolderTree = $true
    }

    Execution = @{
        RetryIntervalSeconds           = 15
        FolderEnumerationThrottleLimit = 5
        ContinueOnServerFailure        = $true
    }

    Remote = @{
        UseCimSessions = $true
        UseUNCFallback = $true
    }

    UseCredential = $false
}
