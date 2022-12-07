


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
