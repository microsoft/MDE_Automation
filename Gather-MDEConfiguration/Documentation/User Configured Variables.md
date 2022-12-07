<- <a href="Readme.md">Back to ReadMe</a>

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
