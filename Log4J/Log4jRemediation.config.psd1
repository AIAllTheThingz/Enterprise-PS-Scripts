@{
    Domain                              = "DOMAIN"
    UserName                            = "service.account"

    # Optional default CSV path.
    # Leave blank to use -ServerName or interactive manual entry.
    ServerCsvPath                       = "C:\PSScripts\Log4j_Remediation\Servers.csv"

    OutputPath                          = "C:\PSScripts\Log4j_Remediation\Reports"
    LogPath                             = "C:\PSScripts\Log4j_Remediation\Logs"

    UseFqdn                             = $false
    FqdnSuffix                          = "domain.local"

    ReportFormats                       = @("CSV", "JSON", "TXT", "HTML")
    IncludeTranscript                   = $true
    TimeoutSeconds                      = 300
    ContinueOnError                     = $true

    AllowManualServerEntry              = $true
    PromptForAdditionalManualServers    = $false

    # Allowed values: WinRM, NoWinRM, Localhost
    DefaultCollectionMode               = "WinRM"
    AllowWinRM                          = $true
    AllowNoWinRM                        = $true
    AllowLocalhost                      = $true
    LocalhostTargetName                 = "localhost"
    LocalhostBypassCredentialPrompt     = $true
    LocalhostUseNativePaths             = $true
    UseDcomWmi                          = $false
    ValidateConnectivityBeforeScan      = $true

    # Search configuration.
    SearchPaths                         = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData",
        "C:\Applications",
        "D:\Applications"
    )

    ExcludedPaths                       = @(
        "C:\Windows\WinSxS",
        "C:\Windows\SoftwareDistribution",
        "C:\Recycle.Bin",
        "C:\System Volume Information"
    )

    SearchFileExtensions                = @(".jar", ".war", ".ear", ".zip")
    IncludeNestedArchives               = $true
    MaximumNestedArchiveDepth           = 3
    MaximumArchiveSizeMB                = 2048
    IncludeFileHash                     = $true
    IncludeRunningJavaProcessCollection = $true
    IncludeServiceInventory             = $true
    IncludeConfigurationFileScan        = $true

    ConfigurationFilePatterns           = @(
        "*.properties",
        "*.xml",
        "*.yaml",
        "*.yml",
        "*.conf",
        "*.config"
    )

    # Remediation is disabled by default.
    RemediationEnabled                  = $false
    RequireConfirmationBeforeRemediation = $true

    QuarantinePath                      = "C:\Log4j_Remediation_Quarantine"
    CreateRollbackMetadata              = $true

    # Vendor replacement is preferred over emergency JAR modification.
    AllowVendorReplacement              = $false
    ApprovedReplacementManifestPath     = ""

    # Emergency mitigation is disabled by default.
    AllowJndiLookupMitigation           = $false

    # Permanent deletion must remain disabled by default.
    AllowPermanentDeletion              = $false

    # Service control is disabled by default and requires approved mappings.
    AllowServiceStopStart               = $false
    ApprovedServiceMappingPath          = ""

    PreserveOriginalTimestampsWherePossible = $true
}
