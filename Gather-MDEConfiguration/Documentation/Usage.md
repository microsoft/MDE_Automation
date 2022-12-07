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
