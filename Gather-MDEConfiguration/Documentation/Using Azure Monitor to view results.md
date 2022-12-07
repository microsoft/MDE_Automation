<- <a href="Readme.md">Back to ReadMe</a>

## Using Azure Monitor to view results

### Azure Monitor Log Mappings

When the Gather-MDEConfiguration.ps1 uploads data to Azure Monitor, it stores the data in Logs.

The following list shows the Dataset name and Azure Monitor Log name it would be stored in:

| Script Dataset | Azure Monitor Log Name |
|:--------------- |:----------------------|
|DeviceInfo| MDE_DeviceInfo_CL |
|Configuration| MDE_Configuration_CL |
|Status| MDE_Status_CL |
|AVExclusions| MDE_AVExclusions_CL |
|SignatureShares| MDE_SignatureShares_CL |
|ProcessCPU| MDE_ProcessCPU_CL |
|CAResults| MDE_CAResults_CL |
|RootCerts| MDE_RootCerts_CL |


### Data structure

Each time the script uploads results to Azure Monitor, it is appended to the existing data.

When correlating data across logs, keep the following in mind:

- All devices will update MDE_DeviceInfo_CL each time they upload results.

- All data from a specific execution of the script on a specific machine will have a unique "RecordGUID".  This will be the same across all Logs, for that device, and that execution.

- All Logs have the following common fields:

  - **DeviceNameKey:** Name of the computer
  - **DeviceDomainKey:** Name of the Windows Domain the device is joined to
  - **DeviceDomainSIDKey:** Security Identifier of the Device on its domain
  - **RecordGUID:** GUID that is unique for each device per script execution.  Can be used to match records across Custom Logs
  - **GatherScriptVersion:** Version of Gather-MDEConfiguration.ps1 that was run
  - **TimeGenerated:** Timestamp indicating when the data was ingested into Azure Monitor.

### Data Schema

Below is a list of fields for each Log.  Common fields are defined above and will not be listed below.

#### MDE_DeviceInfo_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|Architecture|64-bit|Indicates 32-bit or 64-bit||
|AzureADJoined|YES|Indicates whether the device is joined to Azure AD|https://learn.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd|
|deviceName|ToddsPC01|Name of the computer||
|DomainJoined|YES|Indicates whether the device is joined to a Windows domain|https://learn.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd|
|OSBuild|22621|Build number of Windows OS|Should match HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild|
|OSName|Microsoft Windows 11 Enterprise|Full Name of the Operating System||
|OSVersion|10.0.0|Major, Minor, and Minor revision of Operating System ||
|WorkplaceJoined|YES|Indicates whether the device is "Workplace joined"|https://learn.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd|

#### MDE_ASRRulesStatus_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|RuleGUID|d3e037e1-3eb8-44c8-a917-57927947596d|MS GUID of the ASR Rule|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide|
|RuleName|Block JavaScript or VBScript from launching downloaded executable content|MS Name of the ASR Rule|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide|
|RuleStatus|Block|Current Rule Mode|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide|


#### MDE_AVExclusions_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|DefinedExclusion|C:\Temp|Folder name, process name, etc for the exclusion|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus?view=o365-worldwide|
|ExclusionType|Path|Type of exclusion|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus?view=o365-worldwide|




#### MDE_CAResults_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|id|122008|ID provided by the Client Analyzer|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/analyzer-report?view=o365-worldwide|
|Severity|Error|Severity provided by the Client Analyzer|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/analyzer-report?view=o365-worldwide|
|Category|Configuration|Category provided by the Client Analyzer|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/analyzer-report?view=o365-worldwide|
|Test_Name|SCEPAgentVersion|Name of the Test provided by the Client Analyzer|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/analyzer-report?view=o365-worldwide|
|Results|Device is running an older version of System Center Endpoint Protection:|Results provided by the Client Analyzer|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/analyzer-report?view=o365-worldwide|
|Guidance|You should upgrade to latest available version to ensure compatbility and allow malware detections to be logged in Defender for Endpoint security portal.|Guidance provided by the Client Analyzer|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/analyzer-report?view=o365-worldwide|
|CAOutputDate|10/17/2022  9:22:45 AM|Last Modified date of the MDEClientAnalyzer.htm file||



#### MDE_SignatureShares_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|FileShare|\\Server01\SigShare$|Name of the share to used as a signature share|https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-protection-updates-microsoft-defender-antivirus?view=o365-worldwide#create-a-unc-share-for-security-intelligence-and-platform-updates|


#### MDE_RootCerts_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|Subject|CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US|Subject of the Certificate||
|Issuer|CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US|Issuer of the Certificate||
|ExpirationDate|6/23/2035|Expiration Date of the Certificate||
|FriendlyName|Microsoft Root Certificate Authority 2010|Friendly name of the Certificate||
|CertStore|TrustedRoot|Certificate store the certificate is located in||



#### MDE_Status_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|AMEngineVersion|1.1.19800.4|||
|AMProductVersion|4.18.2210.4|||
|AMServiceEnabled|Yes|||
|AMServiceVersion|4.18.2210.4|||
|AntispywareSignatureAge|0|||
|AntispywareSignatureLastUpdated|20221110124458.000000+000|||
|AntispywareSignatureVersion|1.379.145.0|||
|AntivirusRunningMode|Normal|||
|AntivirusSignatureAge|0|||
|AntivirusSignatureLastUpdated|20221110124458.000000+000|||
|AntivirusSignatureVersion|Running|||
|DefenderServiceStatus|Running|||
|DefenderSignaturesOutOfDate|FALSE|||
|DeviceControlPoliciesLastUpdated|20221110120349.922000+000|||
|FullScanAge|663|||
|FullScanEndTime|20210116110724.489000+000|||
|FullScanOverdue|FALSE|||
|FullScanRequired|FALSE|||
|FullScanSignatureVersion|1.329.2263.0|||
|FullScanStartTime|20210116105021.231000+000|||
|LastFullScanSource|User|||
|LastQuickScanSource|System|||
|MPCompStatWMIClassExists|TRUE|||
|MPPrefCmdletExists|TRUE|||
|MPPrefWMIClassExists|TRUE|||
|MPStatCmdletExists|TRUE|||
|NISEngineVersion|1.1.19800.4|||
|NISSignatureAge|0|||
|NISSignatureLastUpdated|20221110124458.000000+000|||
|NISSignatureVersion|1.379.145.0|||
|OnboardingState|1|||
|QuickScanAge|0|||
|QuickScanEndTime|20221110091713.145000+000|||
|QuickScanOverdue|FALSE|||
|QuickScanSignatureVersion|1.379.122.0|||
|QuickScanStartTime|20221110085746.226000+000|||
|SecurityHealthService|Running|||
|SenseLocation|C:\Program Files\Windows Defender Advanced Threat Protection\|||
|SenseServiceStatus|Running|||
|SenseVersion|10.8210.22621.608|||
|TamperProtectionSource|Other|||
|TelemetryServiceStatus|Running|||
|UTCServiceStatus|Running|Current Status of the "Connected User Experiences and Telemetry" service||
|WindowsImageState|IMAGE_STATE_COMPLETE|||
|WindowsSecurityCenter|Running|||





#### MDE_Configuration_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|Fallback||||
|NetWorkProtectionEnabled||||
|SubmitSamplesConsent||||
|TurnOnCloudDeliveredProtection||||
|DisableAntivirus||||
|DeviceDomainKey||||
|CheckForSignatureUpdatesBeforeRunningScan||||
|HighThreatDefaultAction||||
|SevereThreatDefaultAction||||
|ScanScriptsThatAreUsedInMicrosoftBrowsers||||
|DeviceControlState||||
|DisableCatchupFullScan||||
|ScanType||||
|SignatureUpdateInterval||||
|EnableOnAccessProtection||||
|TurnOnBehaviorMonitoring||||
|RunDailyQuickScanAt||||
|DeviceDomainSIDKey||||
|DefenderCloudExtendedTimeoutInSeconds||||
|ScanMappedNetworkDrivesDuringFullScan||||
|MonitoringForIncomingAndOutgoingFiles||||
|MachineAuthId||||
|ScannNetworkFiles||||
|LowThreatDefaultAction||||
|IsTamperProtected||||
|EDRGroupID||||
|DisableCatchupQuickScan||||
|RecordGUID||||
|CPUUsageLimitPerScan||||
|RunDailyScanAt||||
|ScanAllDownloadedFilesAndAttachments||||
|ScanArchiveFiles||||
|DisableAntiSpyware||||
|TurnOnRealTimeProtection||||
|AntispywareEnabled||||
|ActionToTakeOnPotentiallyUnwantedApps||||
|ModerateThreatDefaultAction||||
|OrgId||||
|CloudDeliveredProtectionLevel||||
|DeviceNameKey||||
|AllowUserAccessToMicrosoftDefenderApp||||
|AntivirusEnabled||||
|SenseID||||
|TurnOnNetworkProtection||||
|DayOfWeekToRunAScheduledScan||||
|ComputerID||||
|UseLowPriorityForScheduledScans||||
|ScanEmails||||
|NumberofDaysToKeepQuarantinedMalware||||
|WLIDServiceStartType||||
|DeviceControlDefaultEnforcement||||



#### MDE_ProcessCPU_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|AVServiceCPU||||
|SenseServiceCPU||||
|SecurityHealthServiceCPU||||
|Rank1Name||||
|Rank1CPU||||
|Rank2Name||||
|Rank2CPU||||
|Rank3Name||||
|Rank3CPU||||
|Rank4Name||||
|Rank4CPU||||
|Rank5Name||||
|Rank5CPU||||
|Rank6Name||||
|Rank6CPU||||
|Rank7Name||||
|Rank7CPU||||
|Rank8Name||||
|Rank8CPU||||
|Rank9Name||||
|Rank9CPU||||
|Rank10Name||||
|Rank10CPU||||
|CaptureTime||||




#### MDE_InstalledSoftware_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|DisplayName|Microsoft Azure Compute Emulator - v2.9.7|Display name of the Installed Software||
|DisplayVersion|2.9.8999.43|Display Version of the Installed Software||
|Publisher|Microsoft Corporation|Publisher of the Installed Software||
|InstallDate|20220825|Install Date of the Installed Software||
