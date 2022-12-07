<- <a href="Readme.md">Back to ReadMe</a>
## Using with Azure Monitor

### Requirements

1. Azure Monitor Workspace

To create a workspace to use with this script, you can use the following as a reference:  https://learn.microsoft.com/en-Us/azure/azure-monitor/essentials/azure-monitor-workspace-overview?tabs=azure-portal#create-an-azure-monitor-workspace

2. Workspace ID:  You can obtain this on the Overview blade of your workspace.

3. Primary Key: This is located under Log Analytics agent instructions on the "Agents Management" blade.

4. The device that is running the Gather-MDEConfiguration.ps1 needs to be connected to the internet and allowed to communicate to Azure Monitor.

### Configuration

To enable the script to upload results to Azure Monitor:

Set the following variables in the script:

 - <b>$SendToAzureMonitor</b> should be set to true.
 - The Workspace ID of the Azure Monitor workspace should be set in <b>$WorkspaceID</b>
 - The Primary Key from the Azure Monitor workspace should be set in <b>$SharedKey</b>

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
