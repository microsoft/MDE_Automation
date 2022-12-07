

##############################################################
#region Functions
##############################################################
Function Check-BlankValue {
Param(
    [string]$Value
)
    
    $BlankValue = ""

    If ($Value.Length -gt 0) {
        $Output = $Value
    }
    else {
        $Output = $BlankValue
    }

    return $Output

}

Function Write-LogFile {

<#
    .SYNOPSIS
    This function is used to write a log entry to a log file.
    .DESCRIPTION
    Adds the specified text, component name, and a date/time stamp to a file.
    .EXAMPLE
    Write-LogFile -Description "Starting search for clients..." -Component "ClientCleanup" -LogfilePath c:\windows\ccm\logs\ClientCleanup.log

    .PARAMETER Description
    The text of the log entry (message) to be logged.
 
    .PARAMETER Component
    The component that generated the log entry.

    .PARAMETER LogFilePath
    The path and name of the log file to be written to.
    #>

param(

    [string]$Description,
    [string]$Component,
    [string]$LogFilePath,
    [string]$Seperator = "    ",
    [Parameter()][ValidateSet('Info','Warning','Error')]$Severity = "Info",
    [Parameter()][switch]$HeaderOnly = $false

)
    
    $Date = Get-Date
    $Month = Pad-Number -Number $Date.Month -PadLength 2
    $Day = Pad-Number -Number $Date.Day -PadLength 2
    $Year = Pad-Number -Number $Date.Year -PadLength 4
    $Hour = Pad-Number -Number $Date.Hour -PadLength 2
    $Minute = Pad-Number -Number $Date.Minute -PadLength 2
    $Second = Pad-Number -Number $Date.Second -PadLength 2
    $Milliseconds = Pad-Number -Number $Date.Millisecond -PadLength 3

    #Check if log exists and is over 5MB.  If so, rename it as a rollover.
    If (Test-Path -Path $LogFilePath) {
        $LogSize = $(Get-ItemProperty -Path $LogFilePath -Name Length).Length

        IF ($LogSize -ge 5MB) {
            $RolloverTimeStamp = "$($Component)-$($Year)$($Month)$($Day)-$($Hour)$($Minute)$($Second).log"
            $NewLogName = $LogFilePath -replace ("$($Component).log",$RolloverTimeStamp)
            Rename-Item -Path $LogFilePath -NewName $NewLogNAme -Force
        }
    }
    else {
        $DateString = "$Month-$Day-$Year $Hour`:$Minute`:$Second"
        $OutputString = "$DateString`t`t$Component`t`tStarting new log file"
        Add-Content -LiteralPath $LogFilePath -Value $OutputString


    }

    $DateString = "$Month-$Day-$Year $Hour`:$Minute`:$Second"

    If ($HeaderOnly) {
        $OutputString = $Description
    }
    else {
        $OutputString = "$DateString $Seperator $Component $Seperator $Description"
    }
    Add-Content -LiteralPath $LogFilePath -Value $OutputString

    If ($EnableConsoleOutput) {
        
        Switch($Severity) {
            "Info"{$MsgColor = $CurrentTextColor }
            "Warning"{$MsgColor = $WarningTextColor }
            "Error"{$MsgColor = $ErrorTextColor }
        }

         Write-Host $OutputString -ForegroundColor $MsgColor
    }

}

Function Add-LogEntry {
   
   <#
    .SYNOPSIS
    This function is a simpler version of the Write-LogFile cmdlet. The Write-LogFile cmdlet is required.
    .DESCRIPTION
    Adds the specified text, name of the calling script as the component name, and a date time stamp to a log file.
    .EXAMPLE
    Add-LogEntry -LogText "Starting search for clients..." -LogName c:\windows\ccm\logs\ClientCleanup.log

    .PARAMETER LogText
    The text of the log entry (message) to be logged.

    .PARAMETER LogName
    The path and name of the log file to be written to.
    #>
   
    param(
        [Parameter(Mandatory,ValueFromPipeline)][string]$LogText,
        [string]$LogName,
        [Parameter()][ValidateSet('Info','Warning','Error')]$Severity = "Info"
    )
    If ($EnableLogging) {

        $ScriptName = $($Script:MyInvocation.MyCommand.Name).replace(".ps1","")
        Write-LogFile -Description "$LogText" -Component $ScriptName -LogFilePath $LogName -Severity $Severity
       
    }

    
}

Function Get-ProcessCPU {
param(
    [string]$ProcessName
)

    $CtrFail = $false
    $CpuCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors
    try {
      $Ctr=Get-Counter "\Process($Processname*)\% Processor Time" -ErrorAction SilentlyContinue

    }
    catch {
        $CtrFail = $true
        $Output = ""
   
    }
    
    If ($CtrFail -eq $false){

        $Samples = $Ctr.CounterSamples
        $Result = $Samples | Select InstanceName, @{Name="CPU";Expression={[Decimal]::Round(($_.CookedValue / $CpuCores), 2)}}

        If ($Result.count -gt 1){

            $Output = $($REsult | Sort-Object -Property CPU -Descending | Select-Object -first 1).CPU


        }
        else {

            $Output = $Result.CPU

        }
    }
    return $Output
}

Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource){
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType){
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $TimeStampField = ""
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

Function Convert-PSObjectArraytoJSON {
param(
[PSObject[]]$PSObjectArray
)
    $ErrorCount = 0
    $JsonOutput = @()
    $ErrorOutput = @()
    $JsonOutput += "["

    $PSObjectCount = $PSObjectArray.count

$PSObjectArray | Foreach-Object {

    $PSObjectItem = $_

    $PreCheck = Validate-PSObjectItem -InputPSObject $PSObjectItem

    If ($PreCheck.Result -eq "Pass") {

        $JsonItem = $PSObjectItem | ConvertTo-Json
        If ($PSObjectCount -gt 1){

            $JsonOutput += "," + $JsonItem
        }
        else {
            $JsonOutput += $JsonItem
        }

    }
    else {
        $ErrorCount += 1
        $ErrorOutput += $PSObjectItem
    }

}

    $JsonOutput += "]"

    If ($ErrorCount -eq 0) {
    
        return $JsonOutput
    }
    else {

        $ErrorResult = New-Object -TypeName PSObject
        $ErrorResult | Add-Member -MemberType NoteProperty -Name "ErrorCount" -Value $ErrorCount
        $ErrorREsult | Add-Member -MemberType NoteProperty -NAme "FailedRecords" -Value $ErrorOutput
        $ErrorREsult | Add-Member -MemberType NoteProperty -NAme "PassedRecords" -Value $JsonOutput
        return $ErrorResult
    }
}

Function Validate-PSObjectItem {
param(
    $InputPSObject
)
    

     $PassedProperties = @()
     $FailedProperties = @()
     $Result = "Pass"
    

     $PropList = $($InputPSObject | gm | Where-Object {$_.MemberType -eq "NoteProperty"} | Select Name).Name

     Foreach ($Prop in $PropList) { 
        $PropGood = $True
        
        If ($InputPSObject.$Prop -is [array] -and $PropGood) {$PropGood = $false}
        If ($InputPSObject.$Prop.ToString() -eq "System.Object[]" -and $PropGood) {$PropGood = $false}

        If ($PRopGood) {$PassedProperties += $Prop} else {$FailedProperties += $Prop}

     }

     $Results = New-Object -TypeName PSObject
     
     If ($FailedProperties.Count -eq 0) {
        $Message = "All properties passed verification"
    
    } else {
        $Message = "$($FailedProperties.Count) properties failed verification"
        
        $Result = "Fail"
    }

     $Results | Add-Member -MemberType NoteProperty -Name "Result" -Value $Result
     $Results | Add-Member -MemberType NoteProperty -Name "Message" -Value $Message
     $Results | Add-Member -MemberType NoteProperty -Name "PassedProperties" -Value $PassedProperties
     $Results | Add-Member -MemberType NoteProperty -Name "FailedProperties" -Value $FailedProperties
     return $Results

    }

Function Parse-DSRegCmdStatus {
    
    If (Test-Path -Path "$($env:SystemRoot)\system32\dsregcmd.exe") {
        $DSRegStatus = dsregcmd /status
        $Results = @{}
        $SectionName = "None"
        $DSRegStatus | Foreach-Object {
            $Stat = $_
            If ($Stat -like "|*|") {
                If ($SectionName -ne "None") {
                    $Results.$($SectionName) = $SectionData
                }
                $SectionName = $($($Stat.Replace("|","")).Trim()).Replace(" ","_")
                $SectionData = New-Object -TypeName PSObject
            }
            If ($Stat -like "*:*") {
                $LineInfo = $Stat -Split(":")
                $PropName = $LineInfo[0].Trim()
                $PropValue = $LineInfo[1..$($LineInfo.Length)] -join ("")
                $PropValue = $PropValue.Trim()
                $SectionData | Add-Member -MemberType NoteProperty -Name $PropName -Value $PropValue
            }
        }
    }
    else {
        $Results = "DSRegCMD not found."
    }

    return $Results
}

Function Get-RegistryValue {
    
param(
    [string]$Path,
    [string]$Name
)
    $Output = ""



    If (Test-Path -Path $Path) {
        
        $RI = Get-Item -Path $Path

        If ($RI.Property.count -gt 0) {

            $Properties = $(Get-ItemProperty -Path $Path | gm | Where-Object {$_.Name -notlike "PS*" -and $_.MEmberType -eq "NotePRoperty"}).Name
            If ($Properties -contains $Name) {

                $Output = Get-ItemPropertyValue -Path $Path -Name $Name 
            }
        }

    }

    return $Output




}

Function Check-TLS12Support {

$Output = ""

    $CurrentSSLProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    If ($CurrentSSLProtocol -like "*Tls12*") {
        $Output = "Enabled"
    }
    else {
        $Output= "Disabled"
     }
     return $Output
}

Function Enable-TLS12Support {
        $CurrentSSLProtocol = [System.Net.ServicePointManager]::SecurityProtocol
        If ($CurrentSSLProtocol -notlike "*Tls12*") {

            $EnabledProtocols = "$($CurrentSSLProtocol.ToString()), Tls12"
            [System.Net.ServicePointManager]::SecurityProtocol = $EnabledProtocols

            $Output = "TLS 1.2 support was missing and is now enabled"
    }
    else {

        $Output= "TLS 1.2 support is already enabled."

    }
     return $Output
}

Function Get-ServiceStatus {
param(
    [string]$ServiceName
)

    $Output = ""

    #Check if Service Exists
    $AllServices = $(Get-Service).Name

    If ($ServiceName -in $AllServices) { #Service is present

        $Output = @{}
        $ServiceDetails = (Get-Service -Name $ServiceName)
        $Output.ServiceName = $ServiceDetails.Name
        $Output.Status = $ServiceDetails.Status
        $Output.DisplayName = $ServiceDetails.DisplayName
        $Output.StartType = $ServiceDetails.StartType
    
    }
    else { #Service is not present

        $Output = "$ServiceName not found"

    }

    return $Output
}

Function Exit-Script {
Param(
    [string]$ExitCode = 0
    
)

    
    $EMatrix = @{}
    $EMatrix.Description = ""
    $EMatrix.Severity = "Info"

    Switch($ExitCode) {
        42 {
            $EMatrix.Description = @("Error $($ExitCode): TLS 1.2 is required for this script to run correctly.", "To enable this support, you can run 'Enable-TLS12Support', then execute this script again.")
            $EMatrix.Severity = "Error"
        }
        0 {
            $EMatrix.Description = "Script completed successfully."
        }

        Default {
            $EMatrix.Description = "Script complete."

        }

    }


    " " | Add-LogEntry -LogName $LogFile -Severity "Info"
    "------------------------------------------------------" | Add-LogEntry -LogName $LogFile -Severity $EMatrix.Severity

    If ($($EMatrix.Description.GetType()).IsArray) {

        $EMatrix.Description | Foreach-Object {
            $EDescription = $_

            $EDescription  | Add-LogEntry -LogName $LogFile -Severity $EMatrix.Severity

        }
    }
    else {

        "$($EMatrix.Description)"  | Add-LogEntry -LogName $LogFile -Severity $EMatrix.Severity
    }

  
    "------------------------------------------------------" | Add-LogEntry -LogName $LogFile -Severity $EMatrix.Severity
    " " | Add-LogEntry -LogName $LogFile -Severity "Info"
    "Exiting Script ($ExitCode)"  | Add-LogEntry -LogName $LogFile -Severity "Info"

    Write-LogHeader 

    #exiting with generic exit code
    Exit($ExitCode)

}

Function Get-ScriptPath {
$Output = ""
    If ($psISE) {

        $MyScriptPath = Split-Path $psISE.CurrentFile.FullPath
    }
    else {
        $MyScriptPath = $PSScriptRoot

    }

    $Output = $MyScriptPath
    return $Output
}

Function Get-ScriptName {

    If ($psISE) {
        $OutputTemp = $($psISE.CurrentFile.FullPath).split("\")
        $Output = $OutputTemp[$($OutputTemp.Length - 1)]


    }
    else {
        $Output = $($MyInvocation.MyCommand.Name).replace(".ps1","")
    }

    return $Output

}

function Verify-WMINamespace {

param(

   [string]$NamespaceName

)
    $NamespaceExists = $false

    #Check if WMI Namespace exists on the local device

    If ($NamespaceName -like "*\*\*") {

        $Namespaces = $NamespaceName.split("\")

            $PreNSName = "root"
        $Namespaces[1..$($Namespaces.Length -1)] | Foreach-Object {
            $NSCheckName = $_ 
            $PostNSName = "$($PreNSName)\$($NSCheckName)"

           $result = Get-WmiObject -Namespace $PreNSName -Class "__NAMESPACE" | Where-Object {$_.Name -eq $NSCheckName} | Select Name


            if ($result.name.Count -gt 0) {

                $NamespaceExists = $true
            }

            $PreNSName = $PostNSName

        }
    
    
    }
    else {

        $result = Get-WmiObject -Namespace root -Class "__NAMESPACE" | Where-Object {$_.Name -eq $NamespaceName} | Select Name
 
        if ($result.name.Count -gt 0) {

            $NamespaceExists = $true
        }

    }
    return $NamespaceExists


}

function Verify-WMIClass {
param(
 [string]$ClassName,
    [string]$Namespace = "root\cimv2"
)

    #Check if WMI Class exists on the local device
    $ClassExists = $false

    $nsc = Get-WmiObject -query "SELECT * FROM meta_class WHERE __class = '$ClassName'"
    
    if ($nsc.__NAMESPACE -eq $NameSpace) {
        $ClassExists = $true
    }

    try{
        Get-WmiObject -Class $ClassName -Namespace $Namespace -ErrorAction Stop | Out-Null
    }
    catch [System.Management.ManagementException]{
        return $ClassExists
    }

    $ClassExists = $true

    return $ClassExists


}

Function Pad-Number {

<#
    .SYNOPSIS
    This function is used to pad a number with leading zeros to a specific length.
    .DESCRIPTION
    Pads a number with leading zeros to a specific length.  If the number already exceeds the specified length, it is returned unchanged.
    .EXAMPLE
    Pad-Number -Number 10 -PadLength 3

    Returns 010

    .EXAMPLE
    Pad-Number -Number 10 -PadLength 2

    Returns 10

    .EXAMPLE
    Pad-Number -Number 100 -PadLength 2

    Returns 100

    .PARAMETER Number
    The Number to which leading zeros should be added if needed.
 
    .PARAMETER PadLength
    The desired number of digits in the output.
    #>

param(
    [int]$Number,
    [int]$PadLength
)
    $LeadingZeros = $PadLength - $Number.ToString().Length
    $PadString = ""
    If ($LeadingZeros -gt 0) {
        Do {
            $PadString += "0"
            $LeadingZeros = $LeadingZeros - 1
        } Until ($LeadingZeros -eq 0)
        $Result = "$PadString$($Number.ToString())"
        Return $Result
    }
    else
    {
        Return $Number.ToString()
    }
}

Function Write-LogHeader {

    Write-LogFile -Description " " -LogFilePath $LogFile -HeaderOnly
    Write-LogFile -Description "##############################################################################################" -LogFilePath $LogFile -HeaderOnly
    Write-LogFile -Description " " -LogFilePath $LogFile -HeaderOnly
}

##############################################################
#endregion Functions
##############################################################

#Get Current Script Directory
$ScriptDir =  Get-ScriptPath
$ScriptName = Get-ScriptName

#region User Configured Variables

#These variables can be changed to suite your environment
$EnableLogging = $true #Controls if this script writes to a log file
$EnableConsoleOutput = $true #Controls if this script echoes log entries to the console
$SendToAzureMonitor = $true #Controls if this script sends results to an Azure Monitor Workspace
$SendToXML = $true #Controls if this script exports results to a local XML file
$IncludedSections = @("DeviceInfo")


#The following 'sections' of data will be gathered.
#If you want to skip a section, comment it out with a "#"
$IncludedSections += "Configuration" #Reports on the current Configuration of MDE on this device
$IncludedSections += "Status" #Reports on the current status of MDE components on this device
$IncludedSections += "AVExclusions" #Reports on the AV exclusions this device is configured to use
$IncludedSections += "SignatureShares" #Lists Signature shares (if any) that are defined
$IncludedSections += "ProcessCPU" #Gathers a snapshot of key MDE Process CPU usage, along with the top 10 processes at execution time
#$IncludedSections += "InstalledSoftware" #Reports a list of software installed on this device
$IncludedSections += "CAResults" #Checks for the output of the MDE Client Analyzer and if found, imports the results
$IncludedSections += "RootCerts" #Reports on the certificates in the Computers Trusted Root Store


$MDECAOutputFile = "$($ScriptDir)\MDEClientAnalyzerResult\SystemInfoLogs\MDEClientAnalyzer.xml" #File to read for the MDE Client Analyzer Results, if present
$WorkspaceID = '628b2f33-4bd2-42ab-b63d-1623942fb505' #Log Analytics Workspace ID
$SharedKey = 'AWK+wrdHgSv9JFo2jI310735j+2Nmj1u3vS+p3QyPDGI7RujvsYChyH4VU5c7X1aJbB1Q9y82+kvELPKvYB1aw==' #Log Analytics Primary Key
#endregion User Configured Variables

#region Static Variables
#These variables should not be modified
$GatherScriptVer = "4.0.0" #Version of this script
$RecordGUID = $(New-Guid).GUID #Guid unique to this device and script run uploaded with every record
$TLS12Required = $true #If connecting to Log Analytics, this must be set to $true
$CurrentTextColor = [System.Console]::ForegroundColor
$ErrorTextColor = "Red"
$WarningTextColor = "Yellow"
$FinalOutputs = @{}
$ScriptOutputs = @{}
$ResultObjects = @()
#endregion Static Variables


#region Prep and Initialize


#Set up logfile
$LogFile = "$($ScriptDir)\$ScriptName.log"

Write-LogHeader 
"Starting '$ScriptName' from '$ScriptDir'" | Add-LogEntry -LogName $LogFile

#Validate if TLS 1.2 is enabled for use in PowerShell
"Checking if TLS 1.2 is enabled for use in PowerShell" | Add-LogEntry -LogName $LogFile

$TLSSupportStatus = Check-TLS12Support
$LogEntry = "TLS Status: $TLSSupportStatus" | Add-LogEntry -LogName $LogFile
If ($TLSSupportStatus -eq "Disabled" -and $TLS12Required) {
    "TLS 1.2 support is required by this script."| Add-LogEntry -LogName $LogFile
    Exit-Script -ExitCode 42
} 
#endregion Prep and Initialize

#region Get Device ID Info
"Gathering Device Identification Info" | Add-LogEntry -LogName $LogFile
$FinalOutputs.DeviceInfo = @{}

$DSRegInfo = Parse-DSRegCmdStatus
$CompInfo = Get-WMIObject -Class Win32_ComputerSystem
$DeviceName = $env:COMPUTERNAME
$OSInfo = Get-WMIObject -Class Win32_OperatingSystem
$Architecture = $OSInfo.OSArchitecture

If ($DSRegInfo.Device_State.DomainJoined.Length -gt 0) {
    $DeviceDomainName = $DSRegInfo.Device_State.DomainName
}
else {
    $DeviceDomainName = $(Get-WMIObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain
}
If ($DeviceDomainName -ne "WORKGROUP" -and $DeviceDomainName -ne $null) {
    $DomainJoined = "YES"
    $DDSID = New-Object System.Security.Principal.NTAccount("$($env:COMPUTERNAME)$")
    $DeviceDomainSID = $DDSID.Translate([System.Security.Principal.SecurityIdentifier]).toString()
    $DeviceDomainSID = Check-BlankValue -Value $DeviceDomainSID 
}
else {
    $DeviceDomainSID = ""
    $DomainJoined = "NO"
}


"DeviceName: $DeviceName " | Add-LogEntry -LogName $LogFile

"Device Domain Name: $DeviceDomainName " | Add-LogEntry -LogName $LogFile

"Device Domain SID: $DeviceDomainSID " | Add-LogEntry -LogName $LogFile


    $FinalOutputs.DeviceInfo.RecordGUID = $RecordGUID
    $FinalOutputs.DeviceInfo.Architecture = $Architecture   
    $FinalOutputs.DeviceInfo.GatherScriptVersion = $GatherScriptVer   
    $FinalOutputs.DeviceInfo.AzureADJoined = $DSRegInfo.Device_State.AzureAdJoined         
    $FinalOutputs.DeviceInfo.DeviceDomainKey = $DeviceDomainName    
    $FinalOutputs.DeviceInfo.DeviceDomainSIDKey = $DeviceDomainSID        
    $FinalOutputs.DeviceInfo.DeviceNameKey = $DeviceName      
    $FinalOutputs.DeviceInfo.DomainJoined  = $DomainJoined           
    $OSVer = [system.environment]::OSVersion.Version 
    $FinalOutputs.DeviceInfo.OSBuild = $OSVer.Build
    $FinalOutputs.DeviceInfo.OSVersion = $(Get-WMIObject -Class Win32_OperatingSystem).Version       
    $FinalOutputs.DeviceInfo.OSName =  $(Get-WMIObject -Class Win32_OperatingSystem).Caption         
    $FinalOutputs.DeviceInfo.WorkplaceJoined = $DSRegInfo.User_State.WorkplaceJoined     







#endregion Get Device ID Info

#region Parse MDEAnalyzerResults
    If ($IncludedSections -contains "CAResults") {


        "Checking to see if MDE Client Analyzer results are present" | Add-LogEntry -LogName $LogFile

        #Check for and process XML output file
                                                                                        If (Test-Path -Path $MDECAOutputFile) {

        "MDE Client Analyzer results found.  Parsing Analyzer findings" | Add-LogEntry -LogName $LogFile

        [xml]$XMLOutput = Get-Content -Path "$MDECAOutputFile"
        $CAOutputDate = $(Get-ItemPropertyValue -Path "$MDECAOutputFile" -Name "LastWriteTime").ToString()

        $($XMLOutput.MDEResults | gm | Where-Object {$_.MemberType -eq "Property" -and $_.Name -ne "events"}).Name | Foreach-Object {
            $SectionName = $_
                
            $MDEResultSection = New-Object -TypeName PSObject 
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $DeviceName
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer 
         
            $($XMLOutput.MDEResults.$SectionName  | gm | Where-Object {$_.MemberType -eq "Property"}).Name | foreach-object {
                $displayname = $_
                
                $MDEResultSection | Add-Member -MemberType NoteProperty -Name "$displayname" -Value $XMLOutput.MDEResults.$SectionName.$displayname.value
            }
            $ScriptOutputs.$($SectionName) = $MDEResultSection
        }
    }
                else {

        "MDE Client Analyzer results not found." | Add-LogEntry -LogName $LogFile -Severity Info

    }

        #Get and Process Detailed Results
                                                                                    If ($XMLOutput.MDEResults.events.event.count -gt 0) {
        $FinalOutputs.CAResults = @()
        $XMLOutput.MDEResults.events.event | Foreach-Object {
            $Event = $_
            $MDEResultSection = New-Object -TypeName PSObject 
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $DeviceName
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer 
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "id" -Value $Event.id 
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "Severity" -Value $Event.severity
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "Category" -Value $Event.category
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "Test_Name" -Value $Event.check
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "Results" -Value $Event.checkresult
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "Guidance" -Value $Event.guidance
            $MDEResultSection | Add-Member -MemberType NoteProperty -Name "CAOutputDate" -Value $CAOutputDate

            $FinalOutputs.CAResults += $MDEResultSection

        }
    }

    }


#endregion Parse MDEAnalyzerResults  
 
#region Additional MDE Status Data   
    If ($IncludedSections -contains "Status") { 
        "Gathering MDE Status" | Add-LogEntry -LogName $LogFile

        $FinalOutputs.Status = @{}


        #Add Machine Specific details so we can join data later if desired
        ##################################################################################
        $FinalOutputs.Status.RecordGUID = $RecordGUID
        $FinalOutputs.Status.DeviceDomainKey = $DeviceDomainName   
        $FinalOutputs.Status.DeviceDomainSIDKey = $DeviceDomainSID 
        $FinalOutputs.Status.DeviceNameKey = $DeviceName
        $FinalOutputs.Status.GatherScriptVersion = $GatherScriptVer



        #Check WMI, PowerShell and Windows Image State
        ##################################################################################
            #Verify MDE WMI Classes exist
        "Verifying MDE WMI Classes" | Add-LogEntry -LogName $LogFile

        $ChkNamespace = "root\Microsoft\protectionManagement"
        $ChkClass = "MSFT_MPPreference"
        If ($(Verify-WMINamespace -NamespaceName $ChkNamespace) -and $(Verify-WMIClass -Namespace $ChkNamespace -ClassName $ChkClass)) {
            $MPP = Get-WMIObject -Class MSFT_MPPreference -Namespace ROOT\Microsoft\protectionManagement
            $MPPrefClassExist = $true
            "Class '$ChkClass' exists at '$ChkNamespace'" | Add-LogEntry -LogName $LogFile
        }
        else {
            $MPPrefClassExist = $false
            "Class '$ChkClass' does not exist at '$ChkNamespace'" | Add-LogEntry -LogName $LogFile
        }

        $ChkNamespace = "root\Microsoft\protectionManagement"
        $ChkClass = "MSFT_MPComputerStatus"
        If ($(Verify-WMINamespace -NamespaceName $ChkNamespace) -and $(Verify-WMIClass -Namespace $ChkNamespace -ClassName $ChkClass)) {
            $MPStat = Get-WMIObject -Class MSFT_MPComputerStatus -Namespace ROOT\Microsoft\protectionManagement
            $MPStatClassExist = $true
            "Class '$ChkClass' exists at '$ChkNamespace'" | Add-LogEntry -LogName $LogFile
        }
        else {
            $MPStatClassExist = $false
            "Class '$ChkClass' does not exist at '$ChkNamespace'" | Add-LogEntry -LogName $LogFile
        }

        $FinalOutputs.Status.MPPrefWMIClassExists = $MPPrefClassExist 
        $FinalOutputs.Status.MPCompStatWMIClassExists = $MPStatClassExist


        #Check for presence of MDE Cmdlets
        $MDECmds = $(Get-Command | Where-Object {$_.Name -like "Get-MP*"}).Name
        If ($MDECmds -contains "Get-MPComputerStatus") {
            $PSStat = $true
            "Cmdlet 'Get-MPComputerStatus' is available for use" | Add-LogEntry -LogName $LogFile
        }
        else {$PSStat = $false
                "Cmdlet 'Get-MPComputerStatus' is not available for use" | Add-LogEntry -LogName $LogFile

        }

        If ($MDECmds -contains "Get-MPPreference") {
            $PSPref = $true
                "Cmdlet 'Get-MPPreference' is available for use" | Add-LogEntry -LogName $LogFile
        }
        else {$PSPref = $false
            "Cmdlet 'Get-MPPreference' is not available for use" | Add-LogEntry -LogName $LogFile
        }

        $FinalOutputs.Status.MPPrefCmdletExists = $PSPref
        $FinalOutputs.Status.MPStatCmdletExists = $PSStat


        #Get Windows Image State (https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-states?view=windows-11)
        $FinalOutputs.Status.WindowsImageState = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -Name "ImageState"



        #Get Versions of Services, Engines
        ##################################################################################
        $AMProductVersion = $MPStat.AMProductVersion
        $FinalOutputs.Status.AMProductVersion = $AMProductVersion

        $AMEngineVersion = $MPStat.AMEngineVersion
        $FinalOutputs.Status.AMEngineVersion = $AMEngineVersion

        $NISEngineVersion = $MPStat.NISEngineVersion
        $FinalOutputs.Status.NISEngineVersion = $NISEngineVersion

        $AMServiceVersion  = $MPStat.AMServiceVersion
        $FinalOutputs.Status.AMServiceVersion = $AMServiceVersion

        $SenseLocation = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Name "InstallLocation"
        If (Test-Path -Path "$SenseLocation\MSSense.exe") {
            $SenseVersion = $($(Get-Item -Path "$SenseLocation\MSSense.exe").VersionInfo.ProductVersion)
        }
        else { $SenseVersion= ""}

        $FinalOutputs.Status.SenseServiceVersion = $SenseVersion
        $FinalOutputs.Status.SenseServiceLocation = $SenseLocation




        #Get Signature Versions, Age
        ##################################################################################
        #AntiSpyware
        $AntispywareSignatureVersion = $MPStat.AntispywareSignatureVersion
        $FinalOutputs.Status.AntispywareSignatureVersion = $AntispywareSignatureVersion

        $AntispywareSignatureAge = $MPStat.AntispywareSignatureAge
        $FinalOutputs.Status.AntispywareSignatureAge = $AntispywareSignatureAge

        $AntispywareSignatureLastUpdated = $MPStat.AntispywareSignatureLastUpdated
        $FinalOutputs.Status.AntispywareSignatureLastUpdated = $AntispywareSignatureLastUpdated

        #Antivirus
        $AntivirusSignatureVersion = $MPStat.AntivirusSignatureVersion
        $FinalOutputs.Status.AntivirusSignatureVersion = $AntivirusSignatureVersion

        $AntivirusSignatureAge = $MPStat.AntivirusSignatureAge
        $FinalOutputs.Status.AntivirusSignatureAge = $AntivirusSignatureAge

        $AntivirusSignatureLastUpdated = $MPStat.AntivirusSignatureLastUpdated
        $FinalOutputs.Status.AntivirusSignatureLastUpdated = $AntivirusSignatureLastUpdated

        #NIS
        $NISSignatureVersion = $MPStat.NISSignatureVersion
        $FinalOutputs.Status.NISSignatureVersion = $NISSignatureVersion

        $NISSignatureAge = $MPStat.NISSignatureAge
        $FinalOutputs.Status.NISSignatureAge = $NISSignatureAge

        $NISSignatureLastUpdated = $MPStat.NISSignatureLastUpdated
        $FinalOutputs.Status.NISSignatureLastUpdated = $NISSignatureLastUpdated

        #Overall
        $DefenderSignaturesOutOfDate = $MPStat.DefenderSignaturesOutOfDate
        $FinalOutputs.Status.DefenderSignaturesOutOfDate = $DefenderSignaturesOutOfDate

        #Device Control
        $FinalOutputs.Status.DeviceControlPoliciesLastUpdated = $MPStat.DeviceControlPoliciesLastUpdated

    
        #Get Status of Windows Services
        ##################################################################################
        #Microsoft Defender Antivirus Service - WinDefend
        $WinDefendSvc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        $FinalOutputs.Status.DefenderServiceStatus = $WinDefendSvc.Status
        $FinalOutputs.Status.DefenderServiceStartType = $WinDefendSvc.StartType

        #Connected User Experiences and Telemetry- DiagTrack
        $DiagTrackSvc = Get-Service -Name DiagTrack -ErrorAction SilentlyContinue
        $FinalOutputs.Status.TelemetryServiceStatus = $DiagTrackSvc.Status
        $FinalOutputs.Status.TelemetryServiceStartType = $DiagTrackSvc.StartType

        #Windows Defender Advanced Threat Protection Service - Sense
        $SenseSvc = Get-Service -Name Sense -ErrorAction SilentlyContinue
        $FinalOutputs.Status.SenseServiceStatus = $SenseSvc.Status
        $FinalOutputs.Status.SenseServiceStartType = $SenseSvc.StartType

        #Windows Security Service - SecurityHealthService
        $SecurityHealthSvc = Get-Service -Name SecurityHealthService -ErrorAction SilentlyContinue
        $FinalOutputs.Status.SecurityHealthServiceStatus = $SecurityHealthSvc.Status
        $FinalOutputs.Status.SecurityHealthServiceStartType = $SecurityHealthSvc.StartType

        #Security Center - wscsvc
        $wscsvc = Get-Service -Name wscsvc -ErrorAction SilentlyContinue
        $FinalOutputs.Status.SecurityCenterServiceStatus = $wscsvc.Status
        $FinalOutputs.Status.SecurityCenterServiceStartType = $wscsvc.StartType

        #Microsoft Account Sign-in Assistant - wlidsvc
        $wlidsvc = Get-Service -Name wlidsvc -ErrorAction SilentlyContinue
        $FinalOutputs.Status.MSAccountSignInServiceStatus = $wlidsvc.Status
        $FinalOutputs.Status.MSAccountSignInServiceStartType = $wlidsvc.StartType

        #Windows Push Notifications System Service - wpnservice
        $wpnservice = Get-Service -Name wpnservice -ErrorAction SilentlyContinue
        $FinalOutputs.Status.WinPushNotifyServiceStatus = $wpnservice.Status
        $FinalOutputs.Status.WinPushNotifyServiceStartType = $wpnservice.StartType


        #Get Status of MDE Features
        ##################################################################################
        $FinalOutputs.Status.AntivirusRunningMode = $MPStat.AMRunningMode
    
        $FinalOutputs.Status.OnboardingState = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Name OnboardingState

        $FinalOutputs.Status.TamperProtectionEnabled = $MPStat.IsTamperProtected
        $FinalOutputs.Status.TamperProtectionSource =  $MPStat.TamperProtectionSource

        $FinalOutputs.Status.AntiMalwareEnabled = $MPStat.AMServiceEnabled
        $FinalOutputs.Status.AntispywareEnabled = $MPStat.AntispywareEnabled
        $FinalOutputs.Status.AntivirusEnabled = $MPStat.AntivirusEnabled
        $FinalOutputs.Status.BehaviorMonitorEnabled = $MPStat.BehaviorMonitorEnabled
        $FinalOutputs.Status.IoavProtectionEnabled = $MPStat.IoavProtectionEnabled
        $FinalOutputs.Status.NetworkProtectionEnabled = $MPStat.NISEnabled
        $FinalOutputs.Status.OnAccessProtectionEnabled = $MPStat.OnAccessProtectionEnabled
        $FinalOutputs.Status.RealTimeProtectionEnabled = $MPStat.RealTimeProtectionEnabled
        $FinalOutputs.Status.DeviceControlEnabled = $MPStat.DeviceControlState

        #Get Status of Scans
        ##################################################################################
        #Quickscan
        $FinalOutputs.Status.QuickScanAge = $MPStat.QuickScanAge
        $FinalOutputs.Status.QuickScanStartTime = $MPStat.QuickScanStartTime
        $FinalOutputs.Status.QuickScanEndTime = $MPStat.QuickScanEndTime
        $FinalOutputs.Status.QuickScanOverdue = $MPStat.QuickScanOverdue
        $FinalOutputs.Status.QuickScanSignatureVersion = $MPStat.QuickScanSignatureVersion
        $FinalOutputs.Status.LastQuickScanSource = $MPStat.LastQuickScanSource

        #FullScan
        $FinalOutputs.Status.FullScanAge = $MPStat.FullScanAge
        $FinalOutputs.Status.FullScanStartTime = $MPStat.FullScanStartTime
        $FinalOutputs.Status.FullScanEndTime = $MPStat.FullScanEndTime
        $FinalOutputs.Status.FullScanOverdue = $MPStat.FullScanOverdue
        $FinalOutputs.Status.FullScanRequired = $MPStat.FullScanRequired
        $FinalOutputs.Status.FullScanSignatureVersion = $MPStat.FullScanSignatureVersion
        $FinalOutputs.Status.LastFullScanSource = $MPStat.LastFullScanSource

    }
#endregion Additional MDE Status Data  

#region Additional MDE Configuration Data  
    If ($IncludedSections -contains "Configuration") {
        "Gathering MDE Configuration" | Add-LogEntry -LogName $LogFile

        $FinalOutputs.Configuration = @{}

        #Add Machine Specific details so we can join data later if desired
        ##################################################################################
        $FinalOutputs.Configuration.RecordGUID = $RecordGUID
        $FinalOutputs.Configuration.DeviceDomainKey = $DeviceDomainName   
        $FinalOutputs.Configuration.DeviceDomainSIDKey = $DeviceDomainSID 
        $FinalOutputs.Configuration.DeviceNameKey = $DeviceName
        $FinalOutputs.Configuration.GatherScriptVersion = $GatherScriptVer


        #Get MDE Specific Identifying Info
        ##################################################################################
        $FinalOutputs.Configuration.SenseID= Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Name "SenseId"
        $FinalOutputs.Configuration.OrgId = Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Name "OrgID" 
        $FinalOutputs.Configuration.EDRGroupID = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "GroupIDs"
        $FinalOutputs.Configuration.ComputerID = $MPP.ComputerID
        $FinalOutputs.Configuration.MachineAuthId = Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection" -Name "C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9"

        #Check for MDE Group Policies (https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus-when-migrating?view=o365-worldwide#group-policy-results)
        ##################################################################################
        If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender") {

            #Disable AntiSpyware
            $DisableAntiSpyware =  Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
        
            If ($DisableAntiSpyware -eq 0) {$V = "No"}
            elseif ($DisableAntiSpyware -eq 1) {$V = "Yes"}
            else {$V = "Not Configured"}

            $DisableAntiSpywareVal =  $V

            $DisableAntivirus =  Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntivirus"
        
            If ($DisableAntivirus -eq 0) {$V = "No"}
            elseif ($DisableAntivirus -eq 1) {$V = "Yes"}
            else {$V = "Not Configured"}
    
            $DisableAntivirusVal =  $V
        }
        else {

            $DisableAntiSpywareVal =  "Not Configured"
            $DisableAntivirusVal =  "Not Configured"

        }

        $FinalOutputs.Configuration.DisableAntiSpyware = $DisableAntiSpywareVal
        $FinalOutputs.Configuration.DisableAntivirus = $DisableAntivirusVal


        #Check for Functionality configured to be disabled/enabled 
            #https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp
            #https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
        ##################################################################################

        $FinalOutputs.Configuration.DisableArchiveScanning = $MPP.DisableArchiveScanning
        $FinalOutputs.Configuration.DisableAutoExclusions = $MPP.DisableAutoExclusions
        $FinalOutputs.Configuration.DisableBehaviorMonitoring = $MPP.DisableBehaviorMonitoring
        $FinalOutputs.Configuration.DisableBlockAtFirstSeen = $MPP.DisableBlockAtFirstSeen
        $FinalOutputs.Configuration.DisableCatchupFullScan = $MPP.DisableCatchupFullScan
        $FinalOutputs.Configuration.DisableCatchupQuickScan = $MPP.DisableCatchupQuickScan
        $FinalOutputs.Configuration.DisableCpuThrottleOnIdleScans = $MPP.DisableCpuThrottleOnIdleScans
        $FinalOutputs.Configuration.DisableDatagramProcessing = $MPP.DisableDatagramProcessing
        $FinalOutputs.Configuration.DisableDnsOverTcpParsing = $MPP.DisableDnsOverTcpParsing
        $FinalOutputs.Configuration.DisableDnsParsing = $MPP.DisableDnsParsing
        $FinalOutputs.Configuration.DisableEmailScanning = $MPP.DisableEmailScanning
        $FinalOutputs.Configuration.DisableFtpParsing= $MPP.DisableFtpParsing
        $FinalOutputs.Configuration.DisableGradualRelease = $MPP.DisableGradualRelease
        $FinalOutputs.Configuration.DisableHttpParsing = $MPP.DisableHttpParsing
        $FinalOutputs.Configuration.DisableInboundConnectionFiltering = $MPP.DisableInboundConnectionFiltering
        $FinalOutputs.Configuration.DisableScanningDownloadedFilesAndAttachments = $MPP.DisableIOAVProtection
        $FinalOutputs.Configuration.DisableNetworkProtectionPerfTelemetry = $MPP.DisableNetworkProtectionPerfTelemetry
        $FinalOutputs.Configuration.DisablePrivacyMode = $MPP.DisablePrivacyMode
        $FinalOutputs.Configuration.DisableRdpParsing = $MPP.DisableRdpParsing
        $FinalOutputs.Configuration.DisableRealtimeMonitoring = $MPP.DisableRealtimeMonitoring
        $FinalOutputs.Configuration.DisableRemovableDriveScanning = $MPP.DisableRemovableDriveScanning
        $FinalOutputs.Configuration.DisableRestorePoint = $MPP.DisableRestorePoint
        $FinalOutputs.Configuration.DisableScanningMappedNetworkDrivesForFullScan = $MPP.DisableScanningMappedNetworkDrivesForFullScan
        $FinalOutputs.Configuration.DisableScanningNetworkFiles = $MPP.DisableScanningNetworkFiles
        $FinalOutputs.Configuration.DisableScriptScanning = $MPP.DisableScriptScanning
        $FinalOutputs.Configuration.DisableSmtpParsing = $MPP.DisableSmtpParsing
        $FinalOutputs.Configuration.DisableSshParsing = $MPP.DisableSshParsing
        $FinalOutputs.Configuration.DisableTDTFeature = $MPP.DisableTDTFeature
        $FinalOutputs.Configuration.DisableTlsParsing = $MPP.DisableTlsParsing
        $FinalOutputs.Configuration.EnableDnsSinkhole = $MPP.EnableDnsSinkhole
        $FinalOutputs.Configuration.EnableFileHashComputation = $MPP.EnableFileHashComputation
        $FinalOutputs.Configuration.EnableFullScanOnBatteryPower = $MPP.EnableFullScanOnBatteryPower
        $FinalOutputs.Configuration.EnableLowCpuPriority= $MPP.EnableLowCpuPriority
        $FinalOutputs.Configuration.EnableNetworkProtection= $MPP.EnableNetworkProtection
        $FinalOutputs.Configuration.AllowDatagramProcessingOnWinServer= $MPP.AllowDatagramProcessingOnWinServer
        $FinalOutputs.Configuration.AllowNetworkProtectionDownLevel= $MPP.AllowNetworkProtectionDownLevel
        $FinalOutputs.Configuration.AllowNetworkProtectionOnWinServer= $MPP.AllowNetworkProtectionOnWinServer
        $FinalOutputs.Configuration.AllowSwitchToAsyncInspection= $MPP.AllowSwitchToAsyncInspection
    
        #Get Scan Settings
        ##################################################################################         
                            
        #Daily Scan Schedules
        [string]$RunDailyQuickScanAt = $($MPP.ScanScheduleQuickScanTime.ToString()) 
        $RunDailyQuickScanAt = $RunDailyQuickScanAt.Substring(8,6)
        $DQST = Get-Date -Hour $RunDailyQuickScanAt.Substring(0,2) -Minute $RunDailyQuickScanAt.Substring(2,2) -Second $RunDailyQuickScanAt.Substring(4,2)
        $RunDailyQuickScanAt = $DQST.ToShortTimeString()
        $FinalOutputs.Configuration.RunDailyQuickScanAt =  $RunDailyQuickScanAt          
              
        [string]$RunDailyScanAt = $($MPP.ScanScheduleTime.ToString()) 
        $RunDailyScanAt = $RunDailyScanAt.Substring(8,6)
        $DQST = Get-Date -Hour $RunDailyScanAt.Substring(0,2) -Minute $RunDailyScanAt.Substring(2,2) -Second $RunDailyScanAt.Substring(4,2)
        $RunDailyScanAt = $DQST.ToShortTimeString()
        $FinalOutputs.Configuration.RunDailyScanAt = $RunDailyScanAt          
                
        $V = ""
        Switch ($MPP.ScanParameters) { 1 {$V = "Quick Scan"} 2 {$V = "Full Scan"} $Null{$V = "Not Configured"} Default {$V = "Other"}}
        $ScanType = $V
        $FinalOutputs.Configuration.ScanType =  $ScanType
 
        $V = ""
        Switch ($MPP.ScanScheduleDay) { 0 {$V = "Every Day"} 1 {$V = "Sunday"}  2 {$V = "Monday"}   3 {$V = "Tuesday"}   4 {$V = "Wednesday"}   5 {$V = "Thursday"}  6 {$V = "Friday"}  7 {$V = "Saturday"}  8 {$V = "Never"} $Null{$V = "Not Configured"} Default {$V = "Other"}}
        $DayOfWeekToRunAScheduledScan = $V
        $FinalOutputs.Configuration.DayOfWeekToRunAScheduledScan =  $DayOfWeekToRunAScheduledScan

        #Scan Settings
        $FinalOutputs.Configuration.CheckForSignatureUpdatesBeforeRunningScan = $MPP.CheckForSignaturesBeforeRunningScan   

        $V = ""
        Switch ($MPP.RealTimeScanDirection) { 0 {$V = "Incoming and Outgoing"} 1 {$V = "Incoming"} 2 {$V = "Outgoing"} $Null{$V = "Not Configured"} Default {$V = "Other"}}
        $MonitoringForIncomingAndOutgoingFiles = $V
        $FinalOutputs.Configuration.RealTimeScanDirection =  $MonitoringForIncomingAndOutgoingFiles

        $V = ""
        Switch ($MPP.ScanOnlyIfIdleEnabled) { 0 {$V = "Incoming and Outgoing"} 1 {$V = "Yes"} 2 {$V = "No"} $Null{$V = "Not Configured"} Default {$V = "Other"}}
        $ScanOnlyIfIdleEnabled = $V
        $FinalOutputs.Configuration.ScanOnlyIfIdleEnabled =  $ScanOnlyIfIdleEnabled

        $V = ""
        $ScanAvgCPULoadFactor = $V
        $FinalOutputs.Configuration.CPUUsageLimitPerScan =  $MPP.ScanAvgCPULoadFactor

        $V = ""
        If ($MPP.ScanPurgeItemsAfterDelay -gt 0) {$V = $MPP.ScanPurgeItemsAfterDelay} else {$V = 15}
        $ScanPurgeItemsAfterDelay = $V
        $FinalOutputs.Configuration.NumberofDaysToKeepQuarantinedMalware =  $MPP.ScanPurgeItemsAfterDelay

        #Remdiation Actions
        $V = ""
        Switch ($MPP.LowThreatDefaultAction) {  1 {$V = "Clean"} 2 {$V = "Quarantine"}  3 {$V = "Remove"} 6 {$V = "Allow"} 8 {$V = "User Defined"} 9 {$V = "No Action"} 10 {$V = "Block"}  $Null{$V = "Not Configured"}  Default {$V = "Other"}}
        $LowThreatDefaultAction = $V
        $FinalOutputs.Configuration.LowThreatDefaultAction =  $LowThreatDefaultAction

        $V = ""
        Switch ($MPP.ModerateThreatDefaultAction) {  1 {$V = "Clean"} 2 {$V = "Quarantine"}  3 {$V = "Remove"} 6 {$V = "Allow"} 8 {$V = "User Defined"} 9 {$V = "No Action"} 10 {$V = "Block"}  $Null{$V = "Not Configured"}  Default {$V = "Other"}}
        $ModerateThreatDefaultAction = $V
        $FinalOutputs.Configuration.ModerateThreatDefaultAction =  $ModerateThreatDefaultAction

        $V = ""
        Switch ($MPP.HighThreatDefaultAction) {  1 {$V = "Clean"} 2 {$V = "Quarantine"}  3 {$V = "Remove"} 6 {$V = "Allow"} 8 {$V = "User Defined"} 9 {$V = "No Action"} 10 {$V = "Block"}  $Null{$V = "Not Configured"}  Default {$V = "Other"}}
        $HighThreatDefaultAction = $V
        $FinalOutputs.Configuration.HighThreatDefaultAction =  $HighThreatDefaultAction

        $V = ""
        Switch ($MPP.SevereThreatDefaultAction) {  1 {$V = "Clean"} 2 {$V = "Quarantine"}  3 {$V = "Remove"} 6 {$V = "Allow"} 8 {$V = "User Defined"} 9 {$V = "No Action"} 10 {$V = "Block"}  $Null{$V = "Not Configured"}  Default {$V = "Other"}}
        $SevereThreatDefaultAction = $V
        $FinalOutputs.Configuration.SevereThreatDefaultAction =  $SevereThreatDefaultAction
             
        $V = ""
        Switch ($MPP.PUAProtection) { 0 {$V = "Disabled"} 1 {$V = "Block"} 2 {$V = "Never Send"}  3 {$V = "Audit Mode"}  $Null{$V = "Not Configured"}  Default {$V = "Other"}}
        $ActionToTakeOnPotentiallyUnwantedApps = $V
        $FinalOutputs.Configuration.ActionToTakeOnPotentiallyUnwantedApps = $ActionToTakeOnPotentiallyUnwantedApps
             
        #Misc Settings
        $FinalOutputs.Configuration.SignatureUpdateInterval = $MPP.SignatureUpdateInterval

        $FinalOutputs.Configuration.AllowUserAccessToMicrosoftDefenderApp = $MPP.UILockdown

        $FinalOutputs.Configuration.Fallback = $MPP.SignatureFallbackOrder

        #Cloud Enabled Settings
        $V = ""
        Switch ($MPP.SubmitSamplesConsent) { 0 {$V = "Always Prompt"} 1 {$V = "Send Safe Samples Automatically"} 2 {$V = "Never Send"}  3 {$V = "Send All Samples Automatically"}  $Null{$V = "Not Configured"}  Default {$V = "Other"}}
        $SubmitSamplesConsent = $V
        $FinalOutputs.Configuration.SubmitSamplesConsent =  $SubmitSamplesConsent
                                                             
        If ($MPP.CloudBlockLevel -eq 0) {$TurnOnCloudDeliveredProtection = "No"} elseif ($MPP.CloudBlockLevel -gt 0) {$TurnOnCloudDeliveredProtection = "Yes"}
        $FinalOutputs.Configuration.TurnOnCloudDeliveredProtection =  $TurnOnCloudDeliveredProtection

        $V = ""
        Switch ($MPP.CloudBlockLevel) {0 {$V="Disabled"} 1 {$V="Moderate"} 2 {$V="High"} 3 {$V="High Plus"} 4 {$V="Zero Tolerance"} $null {$V="Not Configured"} Default {$V="Other"} }
        $CloudDeliveredProtectionLevel = $V
        $FinalOutputs.Configuration.CloudDeliveredProtectionLevel = $CloudDeliveredProtectionLevel

        $DefenderCloudExtendedTimeoutInSeconds = $MPP.CloudExtendedTimeout
        $FinalOutputs.Configuration.DefenderCloudExtendedTimeoutInSeconds =  $DefenderCloudExtendedTimeoutInSeconds
                    
    }
#endregion Additional MDE Configuration Data  

#AVExclusions
#region Antivirus Exclusion Data  
    If ($IncludedSections -contains "AVExclusions"){
        $FinalOutputs.AVExclusions = @()

        "Gathering MDE Exclusions" | Add-LogEntry -LogName $LogFile

        #Get AV Exclusions
        $MPP.ExclusionProcess | Foreach-Object{
            $AntivirusExclusions = New-Object -TypeName PSObject

            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $DeviceName
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DefinedExclusion" -Value $_
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "ExclusionType" -Value "Process"
            $FinalOutputs.AVExclusions += $AntivirusExclusions
        }

        $MPP.ExclusionExtension | Foreach-Object{
            $AntivirusExclusions = New-Object -TypeName PSObject
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $DeviceName
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DefinedExclusion" -Value $_
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "ExclusionType" -Value "Extension"
            $FinalOutputs.AVExclusions += $AntivirusExclusions
        }

        $MPP.ExclusionPath | Foreach-Object{
            $AntivirusExclusions = New-Object -TypeName PSObject
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $DeviceName
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "DefinedExclusion" -Value $_
            $AntivirusExclusions | Add-Member -MemberType NoteProperty -Name "ExclusionType" -Value "Path"
            $FinalOutputs.AVExclusions += $AntivirusExclusions
        }
    }
#endregion Antivirus Exclusion Data   

#SignatureShares
#region Antivirus Signature Shares 
    If ($IncludedSections -contains "SignatureShares") {
        "Gathering MDE Signature File Shares" | Add-LogEntry -LogName $LogFile

        $FinalOutputs.SignatureShares = @()


        $MPP.SignatureDefinitionUpdateFileSharesSources | Foreach-Object{
            $AntivirusSignatureFileShare = New-Object -TypeName PSObject
            $AntivirusSignatureFileShare | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $DeviceName
            $AntivirusSignatureFileShare | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $AntivirusSignatureFileShare | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $AntivirusSignatureFileShare | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer  
            $AntivirusSignatureFileShare | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
            $AntivirusSignatureFileShare | Add-Member -MemberType NoteProperty -Name "FileShare" -Value $_
            $FinalOutputs.SignatureShares += $AntivirusSignatureFileShare
        }

    }
#endregion Antivirus Antivirus Signature Shares  

#ProcessCPU
#region Top process CPU usage
    If ($IncludedSections -contains "ProcessCPU") {
       "Checking CPU usage on Defender Processes" |  Add-LogEntry -LogName $LogFile

        #Get CPU Usage Sample for Defender Services
        $AVServiceCPU = Get-ProcessCPU -ProcessName MsMPEng
        $SenseServiceCPU = Get-ProcessCPU -ProcessName MSSense
        $SecurityHealthServiceCPU = Get-ProcessCPU -ProcessName SecurityHealthService

        $ProcessCPUData = New-Object -TypeName PSOBject
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $env:COMPUTERNAME
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "AVServiceCPU" -Value $AVServiceCPU
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "SenseServiceCPU" -Value $SenseServiceCPU
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "SecurityHealthServiceCPU" -Value $SecurityHealthServiceCPU

        #Get cPU Usage for top 10 processes
        $TopProc = Get-Process | Sort-Object -Property CPU -Descending | Select-Object -first 10

        $c = 1
        $TopProc | Foreach-Object {
            $Proc = $_

            $PN = $($Proc.ProcessName).replace(" ","")

          # WRite-Output "$($PRoc.ProcessName)"
           $CU = Get-ProcessCPU -ProcessName $PRoc.ProcessName

           $fName = "Rank$($c)Name"
           $fVAlue = "Rank$($c)CPU"

           $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "$fName" -Value $PN
           $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "$fValue" -Value $CU
           $c = $c + 1
        }


        $CaptureTime = "$($(Get-Date).ToString())"
        $ProcessCPUData | Add-Member -MemberType NoteProperty -Name "CaptureTime" -Value $CaptureTime

         $FinalOutputs.ProcessCPU = $ProcessCPUData
    }
#endregion Top process CPU usage

#InstalledSoftware
#region List of Installed Software
    If ($IncludedSections -contains "InstalledSoftware") {
        "Checking Installed Software" | Add-LogEntry -LogName $LogFile

        $InstalledSoftwares = @()

        $SWPresent = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate -ErrorAction SilentlyContinue

        $SWPresent | Foreach-Object {
               $ISW = $_
       
            $InstalledSoftware = New-OBject -TypeName PSOBject 
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $env:COMPUTERNAME
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $ISW.DisplayName
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $ISW.DisplayVersion
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $ISW.Publisher
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $ISW.InstallDate
            $InstalledSoftware | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer
            $InstalledSoftwares += $InstalledSoftware

        }

         $FinalOutputs.InstalledSoftware = $InstalledSoftwares 
    }
#endregion List of Installed Software 

#RootCerts
#region Inventory of Trusted Root Certs
    If ($IncludedSections -contains "RootCerts") {
        "Checking Trusted Root Certificates" | Add-LogEntry -LogName $LogFile

        #Gather Root Certs from Device
        $CertStore = "TrustedRoot"
        $RootCertInfos = Get-ChildItem -Path Cert:\LocalMachine\Root

        $RootCerts = @()
        $RootCertInfos | ForEach-Object {
            $RootCertInfo = $_

            $RootCert  = New-Object -TypeName psobject
            $RootCert | Add-Member -MemberType NoteProperty -Name "Subject" -Value $RootCertInfo.Subject
            $RootCert | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $RootCertInfo.Issuer
            $RootCert | Add-Member -MemberType NoteProperty -Name "ExpirationDate" -Value $RootCertInfo.NotAfter.ToShortDateString()
            $RootCert | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $RootCertInfo.FriendlyName
            $RootCert | Add-Member -MemberType NoteProperty -Name "CertStore" -Value $CertStore
            $RootCert | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" -Value $DeviceDomainName
            $RootCert | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" -Value $DeviceDomainSID
            $RootCert | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID
            $RootCert | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" -Value $env:COMPUTERNAME
            $RootCert | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer
            $RootCerts += $RootCert

        }

        $FinalOutputs.RootCerts = $RootCerts
    }
#endregion Inventory of Trusted Root Certs 

#region Status of ASR Rules
#ASRRulesStatus
    If ($IncludedSections -contains "ASRRulesStatus") {
       "Checking ASR Rule Status" | Add-LogEntry -LogName $LogFile

        #ASR Rule Status
        $ASRRulesStatus = @()

        #https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix
        $ASRRuleGUIDMatrix = @{}
        $ASRRuleGUIDMatrix.'56a863a9-875e-4185-98a7-b882c64b5ce5' = "Block abuse of exploited vulnerable signed drivers"
        $ASRRuleGUIDMatrix.'7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = "Block Adobe Reader from creating child processes"
        $ASRRuleGUIDMatrix.'d4f940ab-401b-4efc-aadc-ad5f3c50688a' = "Block all Office applications from creating child processes"	
        $ASRRuleGUIDMatrix.'9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"	
        $ASRRuleGUIDMatrix.'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = "Block executable content from email client and webmail"
        $ASRRuleGUIDMatrix.'01443614-cd74-433a-b99e-2ecdc07bfc25' = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"	
        $ASRRuleGUIDMatrix.'5beb7efe-fd9a-4556-801d-275e5ffc04cc' = "Block execution of potentially obfuscated scripts"	
        $ASRRuleGUIDMatrix.'d3e037e1-3eb8-44c8-a917-57927947596d' = "Block JavaScript or VBScript from launching downloaded executable content"	
        $ASRRuleGUIDMatrix.'3b576869-a4ec-4529-8536-b80a7769e899' = "Block Office applications from creating executable content"	
        $ASRRuleGUIDMatrix.'75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = "Block Office applications from injecting code into other processes"	
        $ASRRuleGUIDMatrix.'26190899-1602-49e8-8b27-eb1d0a1ce869' = "Block Office communication application from creating child processes"	
        $ASRRuleGUIDMatrix.'e6d3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = "Block untrusted and unsigned processes that run from USB"	
        $ASRRuleGUIDMatrix.'92b77e5-3df2-4cf1-b95a-636979351e5b' = "Block persistence through WMI event subscription"
        $ASRRuleGUIDMatrix.'d1e49aac-8f56-4280-b9ba-993a6d77406c' = "Block process creations originating from PSExec and WMI commands"	
        $ASRRuleGUIDMatrix.'b2be97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = "Block Win32 API calls from Office macros"
        $ASRRuleGUIDMatrix.'c1db55ab-c21a-4637-bb3f-a12568109d35' = "Use advanced protection against ransomware"	

        $ASRRuleIDs = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
        $ASRRuleActions = Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

        $ASRStatusCodes = @{}
        $ASRStatusCodes.'0' = "Disabled"
        $ASRStatusCodes.'1' = "Block"
        $ASRStatusCodes.'2' = "Audit"
        $ASRStatusCodes.'5' = "Not Configured"
        $ASRStatusCodes.'6' = "Warn"

        $ASRRuleStatMatrix = @{}
        $RuleIndex = 0
        $ASRRuleIDs | ForEach-Object {
            $RuleID = $_
            $ASRRuleStatMatrix."$RuleID" = $ASRStatusCodes."$($ASRRuleActions[$RuleIndex])"
            $RuleIndex += 1

        }

        $ASRRuleGUIDMatrix.GetEnumerator() | Foreach-Object {
            $Rule = $_

            $ASRRuleStatus = New-Object -TypeName PSObject
            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "RuleGUID" -Value $Rule.Name
            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "RuleName" -Value $Rule.Value
            If ($Rule.Name -in $ASRRuleStatMatrix.Keys) {
                $RuleStatus = $ASRRuleStatMatrix."$($Rule.Name)" 
            }
            else {
                $RuleStatus = $ASRStatusCodes.'5'
            }
            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "RuleStatus" -Value "$RuleStatus"

            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "DeviceNameKey" $DeviceName
            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "DeviceDomainKey" $DeviceDomainName
            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "DeviceDomainSIDKey" $DeviceDomainSID
            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "GatherScriptVersion" -Value $GatherScriptVer 
            $ASRRuleStatus | Add-Member -MemberType NoteProperty -Name "RecordGUID" -Value $RecordGUID

            $ASRRulesStatus += $ASRRuleStatus

        }

        $FinalOutputs.ASRRulesStatus = $ASRRulesStatus

    }
#endregion Status of ASR Rules 

#region Output script results
If ($SendToXML) {
    "Exporting results to $($ScriptDir)\MDEConfig.xml" | Add-LogEntry -LogName $LogFile

    $FinalOutputs | Export-Clixml -Path "$ScriptDir\MDEConfig.xml" -Force
}

If ($SendToAzureMonitor) {

    "Sending output to Log Analytics" | Add-LogEntry -LogName $LogFile

    $RecordSuccess = 0
    $RecordError = 0
    $FinalOutputs.Keys | Foreach-Object {
        $Key = $_
            
        If ($IncludedSections -contains $Key){
            $SectionRecordCount = 0
            $SectionRecordSuccess = 0
            $SectionRecordError = 0

            $FinalOutputs.$Key | foreach-object {
                $DO = $_
                #$DO
                $LogName = "MDE_$Key"

                $json = $DO | ConvertTo-Json

                #Write DAta to Log Analytics
                $PostResult = Post-LogAnalyticsData -customerId $WorkspaceID -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $LogName

                If ($Postresult -eq "200") {
                    $RecordSuccess += 1
                    $SectionRecordSuccess += 1

                }
                Elseif ($PostResult.length -gt 0 -and $PostResult -ne "200") {
                    $RecordError += 1
                    $SectionRecordError += 1

                }
               
               $SectionRecordCount += 1

            }

            "Section $($LogName): Total=$SectionRecordCount, Sent=$SectionRecordSuccess, Failed=$SectionRecordError" | Add-LogEntry -LogName $LogFile

        }
    }


    "Log Analytics Submission Results:" | Add-LogEntry -LogName $LogFile

    "$RecordSuccess rows successfully uploaded to Log Analytics" | Add-LogEntry -LogName $LogFile

    "$RecordError rows failed to upload to Log Analytics" | Add-LogEntry -LogName $LogFile

}


"Script completed" | Add-LogEntry -LogName $LogFile

#endregion Output script results

Exit-Script -ExitCode 0
