<#
.SYNOPSIS
    Get all child proceses from a security eventlog for W3WP.
.DESCRIPTION
    Get all child proceses from a security eventlog for W3WP.
.EXAMPLE
    PS C:\> $starttime = [datetime]"3/6/2021"
    PS C:\> .\Get-EventW3WPChild.ps1 -StartTime $starttime | Out-GridView
    
    Get all child processes of the W3WP.exe process and show the output in a GridView. 

.EXAMPLE
    PS C:\>ls 'D:\Securitylogs\*.evtx' | .\Get-EventW3WPChild.ps1

    Process multiple .evtx files.
.INPUTS
    String
.OUTPUTS
    PSObject
.NOTES
    Author: Carlos Perez, carlos.perez@trustedsec.com
#>
[CmdletBinding(DefaultParameterSetName="Local")]
param (
    # Start Date to query events from.
    [Parameter(mandatory=$false)]
    [datetime]
    $StartTime,

    # End date to query events to.
    [Parameter(mandatory=$false)]
    [datetime]
    $EndTime,

    # Specifies the path to the event log files that this cmdlet get events from. Enter the paths to the log files in a comma-separated list, or use wildcard characters to create file path patterns. Function supports files with the .evtx file name extension. You can include events from different files and file types in the same command.
    [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName="file",
        ValueFromPipelineByPropertyName=$true)]
    [Alias("FullName")]
    [ValidateNotNullOrEmpty()]
    [SupportsWildcards()]
    [string[]]
    $Path
)

begin {
    $Params = $MyInvocation.BoundParameters.Keys
}

process {
    $Filter = @{
        Id=4688;
        #ParentProcessName='C:\Windows\System32\inetsrv\w3wp.exe'
        ParentProcessName='C:\Windows\System32\SearchIndexer.exe'
    }
    if ($Params -contains "Path") {
        $Filter.Add("Path",$Path) | Out-Null
    } else {
        $Filter.Add("Logname","Security") | Out-Null
    }

    if ($Params -contains "StartTime") {
        $Filter.Add("StartTime",$StartTime) | Out-Null
    }

    if ($Params -contains "EndTime") {
        $Filter.Add("EndTime",$StartTime) | Out-Null
    }

    get-winevent -FilterHashtable $Filter | foreach-object {
        [xml]$evtxml = $_.toxml()
        $ProcInfo = [ordered]@{}
        $ProcInfo['EventId'] = $evtxml.Event.System.EventID
        $ProcInfo['Computer'] = $evtxml.Event.System.Computer
        $ProcInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
        $ProcInfo['TimeCreated'] = [datetime]$evtXml.Event.System.TimeCreated.SystemTime
        $evtxml.Event.EventData.Data | ForEach-Object {
            $ProcInfo[$_.name] = $_.'#text'
        }
        $Obj = New-Object psobject -Property $ProcInfo
        $Obj
    }
}

end {
    
}
