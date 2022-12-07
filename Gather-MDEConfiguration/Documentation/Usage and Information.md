# Gather-MDEConfiguration.ps1 usage and information


## Overview

This script can be used to capture output results of the MDE Client Analyzer, as well as some other settings, 
and upload the results to Azure Monitor.  This allows for analysis from a central point via KQL. 

## User Configured Variables
The following variables can be customized to control the actions and output of the script.

### General Settings

#### EnableLogging
Controls if this script writes to a log file. Valid values are $true or $false.
```
  $EnableLogging = $true
```
  
#### EnableConsoleOutput
Controls if this script echoes log entries to the console. Valid values are $true or $false.
```
  $EnableConsoleOutput = $true
```

#### SendToAzureMonitor
Controls if this script sends results to an Azure Monitor Workspace.
If this is set to $true, then the WorkspaceID and SharedKey values must be configured. Valid values are $true or $false.
```
  $SendToAzureMonitor = $true
```

#### WorkspaceID
Log Analytics Workspace ID
```
  $WorkspaceID = '4f5gab34-abcd-ab4d-cbda-23415fc34214'
```

#### SharedKey
Log Analytics Primary Key
```
  $SharedKey = 'ASH=dfio+ncipna++pivnfvk==vpirjoviuanlFVNsoiuveousdnlvkjwri' 
```


#### SendToXML
Controls if this script exports results to a local XML file. This file 
can be used to review data that would be sent to Azure Monitor.
```
  $SendToXML = $true
```

#### MDECAOutputFile
File to read for the MDE Client Analyzer Results, if present.
Default Value assumes that the Gather-MDEConfiguration.ps1 script is in the same 
folder as MDEClientAnalyzer.cmd
```
  $MDECAOutputFile = "$($ScriptDir)\MDEClientAnalyzerResult\SystemInfoLogs\MDEClientAnalyzer.xml"
```

### Dataset Control
  
#### IncludedSections
List of datasets you would like the script to gather. 
```
$IncludedSections += "SectionName"
```

The available Datasets are:

<dl> 
 <dt>DeviceInfo</dt>
 <dd>Basic Identifying information about the device.
   This <i><b>MUST</b></i> be included.</dd>

  <dt>Configuration</dt>
<dd>Reports on the current Configuration of MDE on this device</dd>

  <dt>Status</dt>
<dd>Reports on the current status of MDE components on this device</dd>

  <dt>AVExclusions</dt>
<dd>Reports on the AV exclusions this device is configured to use</dd>

  <dt>SignatureShares</dt>
<dd>Lists Signature shares (if any) that are defined</dd>

  <dt>ProcessCPU</dt>
<dd>Gathers a snapshot of key MDE Process CPU usage, along with the top 10 processes at execution time</dd>

  <dt>InstalledSoftware</dt>
<dd>Reports a list of software installed on this device</dd>

  <dt>CAResults</dt>
<dd>Checks for the output of the MDE Client Analyzer and if found, imports the results</dd>

<dt>RootCerts</dt>
<dd>Reports on the certificates in the Computers Trusted Root Store</dd>

</dl>

## Usage

### General
From PowerShell, run Gather-MDEConfiguration.ps1.

### Integration with MDE Client Analyzer
When the Gather-MDEConfiguration.ps1 script executes, it uses the <b>$MDECAOutputFile</b> variable to locate the MDEClientAnalyzer.xml.
If the <b>$IncludedSections</b> variable contains <b>CAResults</b>, the MDEClientAnalyzer.xml file is then scanned and the results are included in the script output.

The MDE Client Analyzer must be downloaded seperately and executed.  
You can find usage instructions, and file download for the MDE Client Analyzer at:  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-client-analyzer?view=o365-worldwide

### Local XML Output
If <b>$SendToXML</b> is set to <b>$True</b>, the script will output all results to an xml file. The file will be named MDEConfig.xml, and will reside in the same folder as the Gather-MDEConfiguration.ps1 script.

To browse the xml file via PowerShell, run the following command:
```
$MDEResults = Import-Clixml -Path [Path To File]\MDEConfig.xml
```

Once imported, you can explore the object.  Some examples are included below.

<b>Viewing a list of Datasets included in the file</b>
```
$MDEResults
```

Example output:
```
Name                           Value                                                                                                                                      
----                           -----                                                                                                                                      
AVExclusions                   {@{RecordGUID=a6c59cbe-9005-44cf-ac48-468055746fec; DeviceDomainKey=LINKEDEV; DeviceDomainSIDKey=S-1-5-21-3489571581-1889358629-12447473...
CAResults                      {@{DeviceNameKey=CM01; DeviceDomainKey=LINKEDEV; DeviceDomainSIDKey=S-1-5-21-3489571581-1889358629-1244747350-1105; GatherScriptVersion=...
SignatureShares                {@{DeviceNameKey=CM01; DeviceDomainKey=LINKEDEV; DeviceDomainSIDKey=S-1-5-21-3489571581-1889358629-1244747350-1105; GatherScriptVersion=...
RootCerts                      {@{Subject=CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com; Issuer=CN=Microsoft Root Certificate Authority, DC=microsoft, ...
DeviceInfo                     {DeviceDomainSIDKey, WorkplaceJoined, Architecture, OSName...}                                                                             
Configuration                  {AllowNetworkProtectionDownLevel, DisableRemovableDriveScanning, ScanOnlyIfIdleEnabled, DisableTDTFeature...}                              
Status                         {SenseServiceStatus, QuickScanStartTime, TelemetryServiceStatus, NISEngineVersion...}                                                      
ProcessCPU                     @{DeviceDomainKey=LINKEDEV; DeviceDomainSIDKey=S-1-5-21-3489571581-1889358629-1244747350-1105; DeviceNameKey=CM01; RecordGUID=a6c59cbe-9...
                                                                                               

```

<b>Getting a list of AV Exclusions</b>
```
$MDEREsults.AVExclusions
```

Example output:
```
RecordGUID          : a6c59cbe-9005-44cf-ac48-468055746fec
DeviceDomainKey     : LINKEDEV
DeviceDomainSIDKey  : S-1-5-21-3489571581-1889358629-1244747350-1105
DeviceNameKey       : CM01
GatherScriptVersion : 4.0.0
DefinedExclusion    : 
ExclusionType       : Process

RecordGUID          : a6c59cbe-9005-44cf-ac48-468055746fec
DeviceDomainKey     : LINKEDEV
DeviceDomainSIDKey  : S-1-5-21-3489571581-1889358629-1244747350-1105
DeviceNameKey       : CM01
GatherScriptVersion : 4.0.0
DefinedExclusion    : 
ExclusionType       : Extension
```

<b>Getting status of the MSSense service (Windows Defender ATP)</b>

```
 $MDEREsults.Status.SenseServiceStatus
```

Example output:
```
Value  
-----  
Running
```

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


