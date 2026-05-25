# Log4j Detection and Remediation Solution

## Overview

This solution scans one or more Windows servers for Apache Log4j Java archive exposure, identifies vulnerable or potentially vulnerable Log4j components, and supports guarded remediation workflows. It is written for Windows PowerShell 5.1 and uses enterprise-safe defaults.

The default mode is audit/report-only. It loads configuration, resolves target servers, validates connectivity, scans configured paths, inspects supported archives, classifies findings, and writes reports without modifying files, services, registry values, or applications.

## Important Scope Clarification

- The script detects Log4j artifacts and possible Log4Shell-family exposure in Java application artifacts.
- Vendor-supported application or library upgrades are preferred remediation.
- Emergency `JndiLookup.class` removal is a mitigation only and does not prove a supported upgrade has occurred.
- Log4j 1.x is end-of-life and requires separate replacement review.
- `log4j-api` alone is not treated as confirmed Log4Shell exposure when `log4j-core` is not present.
- The script does not permanently delete application components by default.
- Nested archive findings are reported for vendor upgrade or manual review; nested archive rewriting is not automatic.

## Files Included

- `Invoke-Log4jRemediation.ps1` - Main discovery, reporting, preview, and guarded remediation script.
- `ReportingTools.psm1` - Reusable CSV, JSON, TXT, and HTML report exporter module.
- `Log4jRemediation.config.psd1` - Environment and safety configuration.
- `Servers.csv` - Sample server list.
- `README.md` - Operational documentation.

## Prerequisites

- Windows PowerShell 5.1.
- Administrative permissions appropriate for the configured scan or remediation mode.
- Network access to target servers.
- WinRM configured and reachable when WinRM mode is selected.
- SMB administrative shares for file scanning. No-WinRM mode uses administrative-share path translation.
- RPC/DCOM access only when No-WinRM mode is used with `-UseDcomWmi` for process and service metadata.
- Local administrator rights when Localhost mode is used to inspect protected local application paths.
- Properly formatted PSD1 configuration.
- CSV server list only when CSV mode is used.
- Approved change record, replacement artifacts, and hash-validated manifest before remediation.

## Log4j Vulnerability Background

The solution focuses on Apache Log4j / Log4Shell-family exposure:

- CVE-2021-44228
- CVE-2021-45046
- CVE-2021-45105
- CVE-2021-44832

`log4j-core` is the central Log4j 2 component evaluated for these issues. `log4j-api` alone is inventoried but is not classified as confirmed Log4Shell exposure. Log4j 1.x is end-of-life; JMSAppender-related indicators are separately reported for CVE-2021-4104 review.

Java compatibility guidance must be validated with the application vendor:

- Java 8 and later applications should generally use a vendor-supported patched Log4j 2 release, with 2.17.0 or later addressing the principal 2021 Log4j Core vulnerability sequence and 2.17.1 or later covering CVE-2021-44832 guidance.
- Java 7 compatibility uses the patched 2.12.x line identified by Apache guidance.
- Java 6 compatibility uses the patched 2.3.x line identified by Apache guidance.
- The script does not automatically determine that a replacement version is appropriate without vendor/application approval.

## Configuration File

All environment-specific settings are stored in `Log4jRemediation.config.psd1`. Do not store passwords, tokens, secrets, or secure strings in this file.

```powershell
@{
    Domain                              = "DOMAIN"
    UserName                            = "service.account"
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
    DefaultCollectionMode               = "WinRM"
    AllowWinRM                          = $true
    AllowNoWinRM                        = $true
    AllowLocalhost                      = $true
    LocalhostTargetName                 = "localhost"
    LocalhostBypassCredentialPrompt     = $true
    LocalhostUseNativePaths             = $true
    UseDcomWmi                          = $false
    ValidateConnectivityBeforeScan      = $true
    SearchPaths                         = @("C:\Program Files", "C:\Program Files (x86)", "C:\ProgramData", "C:\Applications", "D:\Applications")
    ExcludedPaths                       = @("C:\Windows\WinSxS", "C:\Windows\SoftwareDistribution", "C:\Recycle.Bin", "C:\System Volume Information")
    SearchFileExtensions                = @(".jar", ".war", ".ear", ".zip")
    IncludeNestedArchives               = $true
    MaximumNestedArchiveDepth           = 3
    MaximumArchiveSizeMB                = 2048
    IncludeFileHash                     = $true
    IncludeRunningJavaProcessCollection = $true
    IncludeServiceInventory             = $true
    IncludeConfigurationFileScan        = $true
    ConfigurationFilePatterns           = @("*.properties", "*.xml", "*.yaml", "*.yml", "*.conf", "*.config")
    RemediationEnabled                  = $false
    RequireConfirmationBeforeRemediation = $true
    QuarantinePath                      = "C:\Log4j_Remediation_Quarantine"
    CreateRollbackMetadata              = $true
    AllowVendorReplacement              = $false
    ApprovedReplacementManifestPath     = ""
    AllowJndiLookupMitigation           = $false
    AllowPermanentDeletion              = $false
    AllowServiceStopStart               = $false
    ApprovedServiceMappingPath          = ""
    PreserveOriginalTimestampsWherePossible = $true
}
```

Key safety settings:

- `RemediationEnabled = $false` disables all modifications by default.
- `AllowLocalhost = $true` permits `-Localhost` or `DefaultCollectionMode = "Localhost"` runs.
- `LocalhostBypassCredentialPrompt = $true` avoids prompting for credentials during localhost-only runs.
- `AllowVendorReplacement = $false` requires explicit enablement before approved replacements.
- `AllowJndiLookupMitigation = $false` requires explicit enablement before emergency mitigation.
- `AllowPermanentDeletion = $false`; permanent deletion is not implemented.
- `AllowServiceStopStart = $false`; service stop/start is not implemented by default and the script does not guess service ownership.

## Server Input Methods

Input source priority is:

1. `-Localhost` for the local machine. Reports `InputSource` as `Localhost`.
2. `-ServerName` for one or more direct server names. Reports `InputSource` as `CommandLineManual`.
3. `-ServerCsvPath` for an explicit CSV. Reports `InputSource` as `CommandLineCsv`.
4. `ServerCsvPath` from configuration when non-blank and valid, unless `DefaultCollectionMode = "Localhost"`. Reports `InputSource` as `ConfigCsv`.
5. `DefaultCollectionMode = "Localhost"` creates a localhost target when no explicit server input was supplied.
6. Interactive `Read-Host` entry when no CSV and no server-name or localhost mode are available and `AllowManualServerEntry` is true. Reports `InputSource` as `InteractiveManual`.
7. Termination with a clear error when no source is available.

`-ServerName`, `-ServerCsvPath`, and `-Localhost` are mutually exclusive.

## CSV Server List

Required column:

- `ServerName`

Optional columns:

- `FQDN`
- `Notes`
- `TicketNumber`
- `ChangeWindow`
- `ApplicationOwner`
- `MaintenanceApproved`

Sample:

```csv
ServerName,FQDN,Notes,TicketNumber,ChangeWindow,ApplicationOwner,MaintenanceApproved
SERVER01,server01.domain.local,Application server scan,CHG000001,2026-05-25,Application Team,$false
SERVER02,server02.domain.local,Approved remediation candidate,CHG000002,2026-05-25,Middleware Team,$true
SERVER03,,Use constructed FQDN when configured,CHG000003,2026-05-25,Infrastructure,$false
```

`MaintenanceApproved` is informational only. Actual remediation still requires configuration enablement plus `-Remediate` and an action switch.

## Collection Modes

### WinRM Mode

WinRM mode validates targets with `Test-WSMan` and uses `Invoke-Command` for optional Java process and service metadata collection. File discovery and archive inspection use administrative-share path translation so the reporting and mitigation logic can inspect archive contents safely from the operator workstation.

### No-WinRM Mode

No-WinRM mode does not use PowerShell remoting cmdlets. It validates administrative-share access and can optionally collect process/service metadata using `Get-WmiObject` over DCOM when `-UseDcomWmi` is supplied.

No-WinRM remediation is prohibited by this implementation. No-WinRM mode may have reduced process, service, configuration, archive, or remediation capabilities. Partial scans must not be interpreted as clean findings.

### Localhost Mode

Localhost mode is selected with `-Localhost` or by setting `DefaultCollectionMode = "Localhost"` in the PSD1 configuration. It scans the local machine using native local paths and does not require WinRM, SMB administrative shares, or a credential prompt when `LocalhostBypassCredentialPrompt = $true`.

Localhost mode still honors all search paths, excluded paths, archive limits, report formats, remediation gates, `ShouldProcess`, `-WhatIf`, and rollback requirements. It is useful for validating the script locally, scanning a workstation/server directly, or running from an approved maintenance console on the target server itself.

## Detection Logic

The script scans only configured `SearchPaths`, respects `ExcludedPaths`, and inspects configured archive extensions:

- `.jar`
- `.war`
- `.ear`
- `.zip`

It detects:

- Filenames containing `log4j`
- `log4j-core-*`
- `log4j-api-*`
- Log4j 1.x naming
- Embedded Log4j entries inside Java archives
- Nested archive chains when `-IncludeNestedArchives` and configuration allow it
- `org/apache/logging/log4j/core/lookup/JndiLookup.class`
- `org/apache/logging/log4j/core/net/JndiManager.class`
- Maven and manifest metadata
- JMSAppender indicators in archive metadata or scanned configuration files

Version detection attempts filename, `META-INF/MANIFEST.MF`, Maven `pom.properties`, and safe metadata. Unknown versions are reported conservatively.

Process and service correlation are supporting context only. The script never claims an archive is unused because it does not appear in a current command line.

## Operational Modes

- Audit/report-only: default. Scans and reports without changes.
- Connectivity-only: `-ConnectivityOnly`. Tests access and reports; no scanning or remediation.
- Dry run: `-DryRun`. Scans and reports eligible actions; no changes.
- Preview remediation: `-PreviewRemediation`. Shows planned action/quarantine/rollback information; no changes.
- Approved remediation: `-Remediate` plus `-ApplyVendorReplacement` or `-ApplyJndiLookupMitigation`, with configuration gates enabled.
- WhatIf: built-in `-WhatIf`. Reports actions that would be taken and prevents mutation.

## Remediation Methods

### Vendor Replacement

`-ApplyVendorReplacement` may be used only with `-Remediate` and `AllowVendorReplacement = $true`.

The approved manifest must include:

- `ServerName`
- `OriginalArtifactPath`
- `ReplacementArtifactPath`
- `ExpectedOriginalSHA256` when known
- `ExpectedReplacementSHA256`
- `ApprovedTicketNumber`
- `ApplicationOwner`
- `RequiredServicesToStop`
- `RequiredServicesToStart`
- `Notes`

The script validates replacement file existence and SHA256 before replacement, validates original SHA256 when supplied, quarantines the original file, writes rollback metadata, and then replaces the artifact through `ShouldProcess`.

### Emergency JndiLookup Mitigation

`-ApplyJndiLookupMitigation` may be used only with `-Remediate` and `AllowJndiLookupMitigation = $true`.

It applies only to eligible top-level Log4j 2 Core artifacts with `JndiLookup.class` present. It does not modify Log4j 1.x artifacts, `log4j-api` only artifacts, ambiguous archives, or nested archives. Successful class removal is reported as `MitigatedPendingUpgrade`.

### Permanent Deletion And Services

Permanent deletion is not implemented. Service stop/start is not implemented by default, and this script does not guess which service owns an artifact. Approved service mappings are validated when configured, but automatic service control is intentionally not performed by this version.

## Rollback Process

Before any implemented modification, the script creates:

```text
C:\Log4j_Remediation_Quarantine\
  SERVER01\
    yyyy-MM-dd_HHmmss\
      Files\
      Metadata\
        RollbackMetadata.json
```

Rollback metadata includes server, FQDN, original artifact path, archive chain, quarantine path, SHA256 hashes, detected version, classification, action, operator username, timestamp, ticket/application owner, service state placeholders, instructions, and result status.

Manual restoration guidance:

1. Validate rollback approval and change window.
2. Stop the owning application service if required by the application owner.
3. Validate the quarantine artifact SHA256 against `RollbackMetadata.json`.
4. Copy the quarantined artifact back to `OriginalArtifactPath`.
5. Restart services if required.
6. Validate application functionality and logging.

No automatic rollback script is generated.

## Command-Line Switches

| Switch | Required | Description |
|---|---:|---|
| `-ConfigPath` | Yes | Path to `Log4jRemediation.config.psd1`. |
| `-ServerCsvPath` | No | Overrides the configured CSV server-list path. |
| `-ServerName` | No | Provides one or more server names directly without using CSV. |
| `-Credential` | No | Provides an existing `PSCredential` object. |
| `-ReportFormat` | No | Limits generated report formats for the current run. |
| `-VerboseLogging` | No | Enables expanded non-secret operational logging. |
| `-ConnectivityOnly` | No | Tests connectivity without performing remediation. |
| `-DryRun` | No | Scans and reports possible actions without changes. |
| `-PreviewRemediation` | No | Produces an action and rollback preview without changes. |
| `-Remediate` | No | Enables approved remediation mode when configuration permits it. |
| `-ApplyVendorReplacement` | No | Applies approved vendor replacement mappings only with `-Remediate`. |
| `-ApplyJndiLookupMitigation` | No | Applies emergency class-removal mitigation only with `-Remediate`. |
| `-Localhost` | No | Selects Localhost collection mode and scans the local machine using native paths. |
| `-NoWinRM` | No | Selects non-WinRM collection mode. |
| `-UseDcomWmi` | No | Uses supported DCOM WMI metadata collection in No-WinRM mode. |
| `-SkipArchiveInspection` | No | Performs file-level discovery only and cannot produce clean classification. |
| `-IncludeNestedArchives` | No | Enables supported nested archive inspection. |
| `-IncludeHash` | No | Calculates SHA256 hashes for findings. |
| `-TimeoutSeconds` | No | Overrides configured timeout for the current run. |
| `-SearchPaths` | No | Overrides approved search paths for the current run. |
| `-ExcludePaths` | No | Overrides configured excluded paths for the current run. |
| `-QuarantinePath` | No | Overrides configured quarantine root for approved remediation. |
| `-Force` | No | Suppresses custom prompts only; does not bypass safety validation or `ShouldProcess`. |
| `-WhatIf` | No | Reports actions without changing systems. |
| `-Confirm` | No | Uses `ShouldProcess` confirmation behavior. |

## Usage Examples

Audit using configured CSV:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1"
```

Audit a single manually specified server:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01"
```

Audit multiple manually specified servers:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01","SERVER02"
```

Use an alternate CSV file:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerCsvPath ".\Servers.csv"
```

Audit localhost without WinRM or admin shares:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -Localhost
```

Audit localhost by configuration:

```powershell
# Set DefaultCollectionMode = "Localhost" in Log4jRemediation.config.psd1.
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1"
```

Validate connectivity only:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01" -ConnectivityOnly
```

Preview remediation:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01" -PreviewRemediation
```

Preview an approved emergency mitigation with WhatIf:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01" -Remediate -ApplyJndiLookupMitigation -WhatIf
```

Apply an approved vendor replacement:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerCsvPath ".\Servers.csv" -Remediate -ApplyVendorReplacement
```

Apply an explicitly approved emergency JndiLookup mitigation:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01" -Remediate -ApplyJndiLookupMitigation
```

Run audit in No-WinRM mode:

```powershell
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01" -NoWinRM
```

Securely pass a credential object:

```powershell
$Credential = Get-Credential
.\Invoke-Log4jRemediation.ps1 -ConfigPath ".\Log4jRemediation.config.psd1" -ServerName "SERVER01" -Credential $Credential
```

## Reports Generated

Enabled formats create consolidated reports:

- CSV: Excel, filtering, ticket attachment, and administrative review.
- JSON: automation, API ingestion, dashboards, and security tooling.
- TXT: readable archival evidence and quick change-ticket attachment.
- HTML: human-readable audit and remediation evidence.

Filename examples:

```text
Log4j_Remediation_Results_yyyyMMdd_HHmmss.csv
Log4j_Remediation_Results_yyyyMMdd_HHmmss.json
Log4j_Remediation_Results_yyyyMMdd_HHmmss.txt
Log4j_Remediation_Results_yyyyMMdd_HHmmss.html
```

## Report Fields And Status Values

Metadata fields include `ReportTitle`, `RunId`, `RunTimestamp`, `ExecutionMode`, `InputSourceMode`, `CollectionMode`, `ConfigPath`, `ServerCsvPath`, `Domain`, `UserName`, `UseFqdn`, `FqdnSuffix`, `ReportFormats`, `IncludeNestedArchives`, `MaximumNestedArchiveDepth`, `IncludeFileHash`, `RemediationEnabled`, `WhatIfEnabled`, and `TranscriptPath`.

Target fields include `Timestamp`, `InputSource`, `ServerName`, `FQDN`, `LookupName`, `ConnectivityStatus`, `CollectionMode`, `ScanStatus`, `ScannedPaths`, `ExcludedPaths`, `Notes`, `TicketNumber`, `ChangeWindow`, `ApplicationOwner`, and `FailureReason`.

Finding fields include `Timestamp`, `ServerName`, `FQDN`, `CollectionMode`, `ScanStatus`, `DetectionStatus`, `VulnerabilityClassification`, `CVEReferences`, `ArtifactType`, `ArtifactPath`, `ParentArchivePath`, `NestedArchiveChain`, `FileName`, `FileExtension`, `FileSize`, `LastModified`, `SHA256`, `ProductName`, `DetectedVersion`, `VersionDetectionMethod`, `VersionDetectionConfidence`, `Log4jMajorVersion`, `Log4jCorePresent`, `Log4jApiOnly`, `JndiLookupClassPresent`, `JndiManagerClassPresent`, `JMSAppenderIndicatorPresent`, `JavaProcessCorrelation`, `ServiceCorrelation`, `RecommendedAction`, `QuarantinePath`, `RollbackMetadataPath`, `RemediationStatus`, `RemediationActionTaken`, `FailureReason`, `Notes`, `TicketNumber`, and `ApplicationOwner`.

Status values emitted by the implementation include `NotDetected`, `Log4jApiOnlyDetected`, `Log4j1EndOfLifeDetected`, `Log4j1JMSAppenderReviewRequired`, `ConfirmedVulnerable`, `PotentiallyVulnerableVersionUnknown`, `PatchedVersionDetected`, `MitigationPresentButUpgradeValidationRequired`, `ManualReviewRequired`, `PartialScan`, `FailedScan`, `ConnectivityPassed`, `ConnectivityFailed`, `Preview`, `DryRun`, `WhatIf`, `Skipped`, `Quarantined`, `Replaced`, `MitigatedPendingUpgrade`, and `FailedRemediation`.

## Code Signing

Scripts and modules are compatible with Authenticode signing. They do not modify their own source at runtime.

The signing certificate must include the Code Signing EKU. Keep the private key only on the authorized signing/admin workstation or approved signing service.

```powershell
$CodeSigningCert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

Set-AuthenticodeSignature -FilePath ".\Invoke-Log4jRemediation.ps1" -Certificate $CodeSigningCert -TimestampServer "<approved timestamp service URL>"
Set-AuthenticodeSignature -FilePath ".\ReportingTools.psm1" -Certificate $CodeSigningCert -TimestampServer "<approved timestamp service URL>"

Get-AuthenticodeSignature -FilePath ".\Invoke-Log4jRemediation.ps1"
Get-AuthenticodeSignature -FilePath ".\ReportingTools.psm1"
```

Use the organization-approved timestamp service. Timestamping helps signatures remain verifiable after signing-certificate expiration where policy permits.

Code signing does not enable WinRM, SMB administrative shares, RPC/DCOM, firewall access, or remote permissions.

## Execution Policy

- `AllSigned` requires trusted signatures on all scripts.
- `RemoteSigned` requires trusted signatures for downloaded scripts.

Execution policy does not grant administrative rights or remote access.

## WinRM Validation

```powershell
Test-WSMan -ComputerName "SERVER01"
Invoke-Command -ComputerName "SERVER01" -ScriptBlock { $env:COMPUTERNAME }
```

## Troubleshooting

- Configuration validation failure: confirm required PSD1 keys and allowed values.
- Credentials rejected: verify account, domain, permissions, and lockout status.
- WinRM connectivity failure: validate `Test-WSMan`, firewall, listener, SPN, and remoting policy.
- Localhost scan cannot access paths: run from an elevated PowerShell session and verify local search paths exist.
- No-WinRM access denied: confirm administrative shares and permissions.
- SMB/admin-share unavailable: verify `\\SERVER\ADMIN$` and `\\SERVER\C$`.
- Server list invalid: ensure CSV exists and includes `ServerName`.
- No CSV supplied and manual entry disabled: provide `-ServerName`, `-ServerCsvPath`, or enable `AllowManualServerEntry`.
- Both `-ServerName` and `-ServerCsvPath` supplied: use one input mode.
- Archive cannot be read: review file permissions, corruption, or archive size limit.
- Nested archive inspection skipped or limited: enable `-IncludeNestedArchives` and confirm maximum depth.
- Unknown Log4j version: treat as manual review or potentially vulnerable when `log4j-core` is present.
- Log4j API found without Log4j Core: inventory finding only; search for `log4j-core` elsewhere.
- Log4j 1.x detection: plan vendor/application replacement.
- JMSAppender review finding: review possible CVE-2021-4104 exposure.
- Vendor replacement manifest invalid: confirm required columns and hashes.
- Replacement hash mismatch: do not proceed; validate package source.
- Quarantine failure: do not modify; fix permissions or storage.
- Rollback metadata failure: do not modify; rollback evidence is required.
- JndiLookup mitigation prohibited by configuration: set `AllowJndiLookupMitigation = $true` only with approved change control.
- Service-control action prohibited: this implementation does not guess or automatically control services.
- Report export failure: verify output path permissions and disk space.
- Code-signing trust errors: check unknown publisher, untrusted root CA, expired certificate, missing timestamp, or modified script after signing.
- Execution policy errors: validate policy, signatures, and certificate trust.
