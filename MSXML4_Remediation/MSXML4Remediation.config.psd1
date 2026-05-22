@{
    Domain = 'CONTOSO'
    Username = 'svc-msxml4-remediation'

    ServerCsvPath = '.\Servers.csv'
    OutputPath = '.\Output'
    LogPath = '.\Logs'

    UseFqdn = $false
    FqdnSuffix = 'contoso.local'

    ReportFormats = @(
        'Csv'
        'Json'
        'Html'
        'Txt'
    )

    DryRun = $true
    PreviewRemediation = $false
    NoWinRM = $false
    UseDcomWmi = $false
    VerboseLogging = $false
    TimeoutSeconds = 45

    SkipFileSearch = $false
    FullFileSearch = $false
    IncludeHash = $true
    UseWin32Product = $false

    LocalDrives = @(
        'C'
    )

    IncludeAllFixedDrives = $false

    SearchPaths = @(
        'Windows\System32'
        'Windows\SysWOW64'
        'Program Files'
        'Program Files (x86)'
        'Inetpub'
    )

    ExcludedDrives = @(
        'A'
        'B'
    )

    ExcludedPaths = @(
        'C:\Windows\WinSxS'
        'C:\Windows\SoftwareDistribution'
        'C:\Windows\Temp'
    )

    EnableRemediation = $false
    QuarantinePath = 'C:\MSXML4_Remediation_Quarantine'
    RemoveFiles = $false
    UnregisterDll = $true
    RemoveRegistryKeys = $false
    CreateRestoreMetadata = $true
    RequireConfirmation = $true
}
