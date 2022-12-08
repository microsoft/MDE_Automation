<- <a href="Readme.md">Back to ReadMe</a>

## Querying Results using KQL

Here are some example KQL Queries that can be run against this data, and a sample of the results.

### Devices with Warning or Error findings from MDE Client Analyzer

#### KQL Query
````
MDE_CAResults_CL 
| where Severity_s <> "Informational" and TimeGenerated > ago(24h)
| project DeviceNameKey_s, Test_Name_s, Severity_s,  Results_s, Guidance_s
````

#### Results
![KQL Query Results](<https://github.com/microsoft/MDE_Automation/blob/main/Gather-MDEConfiguration/Documentation/Images/KQLResult1.png>)



### Count of Devices returning issues from MDE Client Analyzer

#### KQL Query
````
MDE_CAResults_CL 
| where Severity_s <> "Informational" 
and TimeGenerated > ago(24h)
| summarize dcount(DeviceNameKey_s) by id_s, Severity_s, Test_Name_s, Results_s
| project-rename id_s, AffectedDevices=dcount_DeviceNameKey_s, Severity_s, Test_Name_s, Results_s
````

#### Results
![KQL Query Results](<https://github.com/microsoft/MDE_Automation/blob/main/Gather-MDEConfiguration/Documentation/Images/KQLResult2.png>)

### Defender Component Status for Devices


#### KQL Query
````
MDE_Status_CL
| where TimeGenerated > ago(24h)
| distinct DeviceNameKey_s, AntivirusEnabled_b, AntivirusRunningMode_s, NetworkProtectionEnabled_b, BehaviorMonitorEnabled_b, RealTimeProtectionEnabled_b, TamperProtectionEnabled_b,
IoavProtectionEnabled_b, TamperProtectionSource_s 
````

#### Results
![KQL Query Results](<https://github.com/microsoft/MDE_Automation/blob/main/Gather-MDEConfiguration/Documentation/Images/KQLResult3.png>)




