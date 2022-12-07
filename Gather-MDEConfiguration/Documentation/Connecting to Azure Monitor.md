<- <a href="Readme.md">Back to ReadMe</a>
## Connecting to Azure Monitor

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


