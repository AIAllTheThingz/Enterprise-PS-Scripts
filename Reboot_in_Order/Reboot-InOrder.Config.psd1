@{
    StackCsvPath = "C:\Scripts\Reboot_In_Order\Reboot-InOrder.Stacks.csv"

    AllowParallelStacks = $false
    MaxParallelStacks   = 1

    WaitTimeoutMinutes    = 30
    MaxServiceWaitMinutes = 20
    RetryIntervalSeconds  = 30

    EnforceMaintenanceWindow          = $true
    SkipStacksOutsideMaintenanceWindow = $true

    HealthChecks = @{
        Ping          = $true
        WinRM         = $true
        RemoteCommand = $false
        Services      = $true
    }

    RemoteCommandScriptBlock = "hostname"

    ReportPath = "C:\Reports\Reboot_In_Order"
    LogPath    = "C:\Logs\Reboot_In_Order"

    IncludeTranscript = $true
    ReportFormats     = @("CSV", "JSON", "HTML")

    UseCredential      = $false
    CredentialUserName = "DOMAIN\service.account"

    OfflineDetectionGraceSeconds = 15
    RequiredOfflineObservations  = 2
    RequiredOnlineObservations   = 2
}
