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
````


````
