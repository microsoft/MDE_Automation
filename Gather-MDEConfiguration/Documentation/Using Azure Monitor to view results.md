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
|AMEngineVersion|1.1.19800.4|The AM Engine version (major, minor, build, revision)|https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus|
|AMProductVersion|4.18.2210.4|Product version (major, minor, build, revision)||
|AMServiceEnabled|Yes|If the AM Engine is enabled||
|AMServiceVersion|4.18.2210.4|Service version (major, minor, build, revision)||
|AntispywareSignatureAge|0|Antispyware Signature age in days - if signatures have never been updated you will see an age of 65535 days||
|AntispywareSignatureLastUpdated|20221110124458.000000+000|Antispyware Last updated local time. If this has never updated you will see a null value in this property||
|AntispywareSignatureVersion|1.379.145.0|The Antispyware Signature version (major, minor, build, revision)||
|AntivirusRunningMode|Normal|Shows the mode of Defender AV: Normal, Passive, EDR Block Mode||
|AntivirusSignatureAge|0|Antispyware Signature age in days - if signatures have never been updated you will see an age of 65535 days||
|AntivirusSignatureLastUpdated|20221110124458.000000+000|Antispyware Last updated local time. If this has never updated you will see a null value in this property||
|AntivirusSignatureVersion|Running|The Antispyware Signature version (major, minor, build, revision)||
|DefenderServiceStatus|Running|Status of Microsoft Defender Antivirus Service||
|DefenderSignaturesOutOfDate|FALSE|Whether or not defender signatures are not current||
|DeviceControlPoliciesLastUpdated|20221110120349.922000+000|Time that device control policies were last updated on this device||
|FullScanAge|663|Last full scan age in days- if signatures have never been updated you will see an age of 65535 days||
|FullScanEndTime|20210116110724.489000+000|Time of last Full Scan end - If this has never updated you will see a null value in this property||
|FullScanStartTime|20210116105021.231000+000|Time of last Full Scan start - If this has never updated you will see a null value in this property||
|LastFullScanSource|User|Last scan source||
|LastQuickScanSource|System|Last scan source||
|MPCompStatWMIClassExists|TRUE|Whether or not the device has the MSFT_MPComputerSTatus WMI Class||
|MPPrefCmdletExists|TRUE|Whether or not the Get-MPPreference cmdlet exists||
|MPPrefWMIClassExists|TRUE|Whether or not the device has the MSFT_MPPreference WMI Class||
|MPStatCmdletExists|TRUE|Whether or not the Get-MPComputerStatus cmdlet exists||
|NISEngineVersion|1.1.19800.4|NRI Engine version (major, minor, build, revision)||
|NISSignatureAge|0|NRI Signature age in days- if signatures have never been updated you will see an age of 65535 days||
|NISSignatureLastUpdated|20221110124458.000000+000|NRI Last updated local time - If this has never updated you will see a null value in this property||
|NISSignatureVersion|1.379.145.0|The NRI Signature version (major, minor, build, revision)||
|OnboardingState|1|Whether or not the device has been onboarded to ATP Portal.  1 = Onboarded, 0 = Not Onboarded||
|QuickScanAge|0|Last quick scan age in days- if signatures have never been updated you will see an age of 65535 days.||
|QuickScanEndTime|20221110091713.145000+000|Time of last Quick Scan end - If this has never updated you will see a null value in this property||
|QuickScanStartTime|20221110085746.226000+000|Time of last Quick Scan start - If this has never updated you will see a null value in this property||
|SecurityHealthService|Running|Status of Windows Security Service||
|SenseLocation|C:\Program Files\Windows Defender Advanced Threat Protection\|||
|SenseServiceStatus|Running|Status of Windows Defender Advanced Threat Protection Service||
|SenseVersion|10.8210.22621.608|Version of MSSense.exe ||
|TamperProtectionSource|Other|Configuration Solution that is enforcing Tamper Protection||
|TelemetryServiceStatus|Running|Status of Connected User Experiences and Telemetry Service||
|WindowsImageState|IMAGE_STATE_COMPLETE|Status of Os State during Setup.  IMAGE_STATE_UNDEPLOYABLE is incompatible with MDE|https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-states?view=windows-11|
|WindowsSecurityCenter|Running|Status of Security Center Service||








#### MDE_Configuration_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|ActionToTakeOnPotentiallyUnwantedApps|Disabled|Specifies the level of detection for potentially unwanted applications. ||
|AllowDatagramProcessingOnWinServer|FALSE|Specifies whether to disable inspection of UDP connections on Windows Server.||
|AllowNetworkProtectionDownLevel|FALSE|Specifies whether to allow network protection to be set to Enabled or Audit Mode on Windows versions before 1709.||
|AllowNetworkProtectionOnWinServer|FALSE|Specifies whether to allow network protection to be set to Enabled or Audit Mode for Windows Server.||
|AllowSwitchToAsyncInspection|FALSE|Specifies whether to enable a performance optimization that allows synchronously inspected network flows to switch to async inspection once they've been checked and validated.||
|AllowUserAccessToMicrosoftDefenderApp|FALSE|Specifies if the Defender User Interface (UI) is accessible and notifications ware allowed.||
|CheckForSignatureUpdatesBeforeRunningScan|FALSE|ndicates whether to check for new virus and spyware definitions before Windows Defender runs a scan.||
|CloudDeliveredProtectionLevel|Disabled|Configure how aggressive Defender Antivirus is in blocking and scanning suspicious files.||
|ComputerID|E6CADA42-E10D-4A7C-93FB-E01ADC69C24F|Computer ID created by MAPS||
|CPUUsageLimitPerScan|0|Specifies the maximum percentage CPU usage for a scan||
|DayOfWeekToRunAScheduledScan|Never|Specifies the day of the week on which to perform a scheduled scan.||
|DefenderCloudExtendedTimeoutInSeconds|0|Specifies the amount of extended time to block a suspicious file and scan it in the cloud. ||
|DisableAntiSpyware|Not Configured|specifies whether to disable Microsoft Defender Antivirus.||
|DisableAntivirus|Not Configured|specifies whether to disable Microsoft Defender Antivirus.||
|DisableArchiveScanning|FALSE|Indicates whether to scan archive files, such as .zip and .cab files, for malicious and unwanted software. ||
|DisableAutoExclusions|FALSE|Indicates whether to disable the Automatic Exclusions feature for the server.||
|DisableBehaviorMonitoring|TRUE|Indicates whether to enable behavior monitoring.||
|DisableBlockAtFirstSeen|FALSE|Indicates whether to enable block at first seen. ||
|DisableCatchupFullScan|TRUE|Indicates whether Windows Defender runs catch-up scans for scheduled full scans.||
|DisableCatchupQuickScan|TRUE|Indicates whether Windows Defender runs catch-up scans for scheduled quick scans. ||
|DisableCpuThrottleOnIdleScans|TRUE|Indicates whether the CPU will be throttled for scheduled scans while the device is idle. ||
|DisableDatagramProcessing|FALSE|Specifies whether to disable inspection of UDP connections.||
|DisableDnsOverTcpParsing|FALSE|Specifies whether to disable inspection of DNS traffic that occurs over a TCP channel.||
|DisableDnsParsing|FALSE|Specifies whether to disable inspection of DNS traffic that occurs over a UDP channel||
|DisableEmailScanning|TRUE|Indicates whether Windows Defender parses the mailbox and mail files, according to their specific format, in order to analyze mail bodies and attachments.||
|DisableFtpParsing|FALSE|Specifies whether to disable FTP Parsing for Network Protection.||
|DisableGradualRelease|FALSE|Specifies whether to disable gradual rollout of monthly and daily Windows Defender updates.||
|DisableHttpParsing|FALSE|Specifies whether disable inspection of HTTP traffic. ||
|DisableInboundConnectionFiltering|FALSE|Specifies whether to inspect only outbound connections. ||
|DisableNetworkProtectionPerfTelemetry|FALSE|disables the gathering and send of performance telemetry from Network Protection.||
|DisableRdpParsing|FALSE|This setting controls whether to parse RDP traffic to look for malicious attacks using the RDP protocol.||
|DisableRealtimeMonitoring|TRUE|Indicates whether to use real-time protection.||
|DisableRemovableDriveScanning|TRUE|Indicates whether to scan for malicious and unwanted software in removable drives, such as flash drives, during a full scan. ||
|DisableRestorePoint|TRUE|Indicates whether to disable scanning of restore points. ||
|DisableScanningDownloadedFilesAndAttachments|TRUE|Indicates whether to disable scans all downloaded files and attachments. ||
|DisableScanningMappedNetworkDrivesForFullScan|TRUE|Indicates whether to scan mapped network drives. ||
|DisableScanningNetworkFiles|TRUE|Indicates whether to scan for network files. ||
|DisableScriptScanning|TRUE|Specifies whether to disable the scanning of scripts during malware scans.||
|DisableSmtpParsing|FALSE|Specifies whether to disable inspection of SMTP traffic. ||
|DisableSshParsing|FALSE|Specifies whether to disable inspection of SSH traffic. ||
|DisableTlsParsing|FALSE|Specifies whether to disable inspection of TLS traffic. ||
|EDRGroupID||||
|EnableDnsSinkhole|TRUE|Specifies whether to examine DNS traffic to detect and sinkhole DNS exfiltration attempts and other DNS based malicious attacks. ||
|EnableFileHashComputation|FALSE|Specifies whether to enable file hash computation. ||
|EnableFullScanOnBatteryPower|FALSE|Specifies whether Windows Defender does a full scan while on battery power.||
|EnableLowCpuPriority|FALSE|Specifies whether Windows Defender uses low CPU priority for scheduled scans.||
|EnableNetworkProtection|0|Specifies how the network protection service handles web-based malicious threats, including phishing and malware. ||
|Fallback|InternalDefinitionUpdateServer|MicrosoftUpdateServer|MMPC|Specifies the order in which to contact different definition update sources.||
|HighThreatDefaultAction|Quarantine|Specifies which automatic remediation action to take for a high level threat.||
|LowThreatDefaultAction|Quarantine|Specifies which automatic remediation action to take for a low level threat.||
|ModerateThreatDefaultAction|Quarantine|Specifies which automatic remediation action to take for a moderate level threat.||
|NumberofDaysToKeepQuarantinedMalware|15|Specifies the number of days to keep items in the scan history folder. After this time, Windows Defender removes the items. ||
|OrgId|33a4a71f-65f1-4861-a775-50d2e8bfc816|OrgID value from HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status||
|RealTimeScanDirection|Incoming and Outgoing|Specifies scanning configuration for incoming and outgoing files on NTFS volumes. ||
|RunDailyQuickScanAt|0.5|Specifies the time of day, as the number of minutes after midnight, to perform a scheduled quick scan. The time refers to the local time on the computer. ||
|RunDailyScanAt|0|Specifies the time of day to run a scheduled scan. The time refers to the local time on the computer. ||
|ScanOnlyIfIdleEnabled|Other|Indicates whether to start scheduled scans only when the computer is not in use.||
|ScanType|Quick Scan|Specifies the type of scan to use during a scheduled scan||
|SenseID|b65ea20089369dd6be4e42c55c9fa8f5289c7ed1|Unique Identifier of device in ATP||
|SevereThreatDefaultAction|Quarantine|Specifies which automatic remediation action to take for a severe level threat.||
|SignatureUpdateInterval|1|Specify the interval from zero to 24 (in hours) that is used to check for signatures||
|SubmitSamplesConsent|Send Safe Samples Automatically|Specifies how Windows Defender checks for user consent for certain samples.||
|TurnOnCloudDeliveredProtection|No|Specifies whether Defender on Windows 10/11 desktop devices sends information to Microsoft about any problems it finds. ||



#### MDE_ProcessCPU_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|AVServiceCPU|0|% of CPU used by Windows Defender AV Service||
|SenseServiceCPU|0.78|% of CPU used by Windows Defender ATP service||
|SecurityHealthServiceCPU|0|% of CPU used by Windows Security Health Service||
|Rank1Name|sqlservr|Process Name of Top CPU Consumer||
|Rank1CPU|10|% of CPU used by Top CPU Consumer||
|Rank2Name|RSPortal|Process Name of 2nd highest CPU Consumer||
|Rank2CPU|8|% of CPU used by 2nd Highest CPU Consumer||
|Rank3Name|Powershell|Process Name of 3rd highest CPU Consumer||
|Rank3CPU|0.39|% of CPU used by 3rd Highest CPU Consumer||
|Rank4Name|MSSense|Process Name of 4th highest CPU Consumer||
|Rank4CPU|0.78|% of CPU used by 4th Highest CPU Consumer||
|Rank5Name|services|Process Name of 5th highest CPU Consumer||
|Rank5CPU|0|% of CPU used by 5th Highest CPU Consumer||
|Rank6Name|ReportingServicesService|Process Name of 6th highest CPU Consumer||
|Rank6CPU|0|% of CPU used by 6th Highest CPU Consumer||
|Rank7Name|Microsoft.PowerBI.EnterpriseGateway|Process Name of 7th highest CPU Consumer||
|Rank7CPU|1.95|% of CPU used by 7th Highest CPU Consumer||
|Rank8Name|lsass|Process Name of 8th highest CPU Consumer||
|Rank8CPU|0|% of CPU used by 8th Highest CPU Consumer||
|Rank9Name|Microsoft.ConfigurationManagement|Process Name of 9th highest CPU Consumer||
|Rank9CPU|0|% of CPU used by 9th Highest CPU Consumer||
|Rank10Name|Taskmgr|Process Name of 10th highest CPU Consumer||
|Rank10CPU|0.78|% of CPU used by 10th Highest CPU Consumer||
|CaptureTime||Time the CPU Snapshot was captured||






#### MDE_InstalledSoftware_CL
| Field Name | Example | Description | More Info |
|:--------------- |:----------------------|:----------------------|:----------------------|
|DisplayName|Microsoft Azure Compute Emulator - v2.9.7|Display name of the Installed Software||
|DisplayVersion|2.9.8999.43|Display Version of the Installed Software||
|Publisher|Microsoft Corporation|Publisher of the Installed Software||
|InstallDate|20220825|Install Date of the Installed Software||
