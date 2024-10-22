#Requires -Version 5
<# Datto EDR Maintenance
    Version 2 (Updated: 22 October 2024)
    Written by: Chris Gerritz

    Variables: 
        varAction - Mandatory
        varBypassInstallCheck - Optional to run diagnostic even if Datto EDR service is not installed
        varUninstallToken - Optional - Uninstall Key from the Datto EDR Settings console or Offline Uninstall Key from Support

    Actions:
        Diagnostic
        Restart Service
        Stop Service
        Fix Known Issues
        Uninstall


    Diagnostic:
        Can be used to diagnose problems with Datto EDR, Datto AV, Ransomware Detection and Ransomware Rollback agents on the
         endpoint. It retrieves the following information:

         - 
        - Check EDR Installation Status
            -- Service Running
            -- Process Running
            -- DattoEDR.JSON Present and Updated
        - Service Info
            -- EDR (HUNTAgent)
            -- AV (endpointprotectionservice)
            -- Ransomware Detection (n/a)
            -- Ransomware Rollback (rollbackservice)
        - Process Info
        - Agent Configuration and Settings
            -- version
            -- config.toml
            -- Registry
            -- KaseyaOne (dattoedr.json)
        - Log Snippets
            -- Available Log Files
            -- Today's Errors 
            -- Last Log Tail (30 lines)
        - Agent Known Problem Detection
          -- Service Not Running
          -- Service Not Connecting
          -- Service Not Updated
          -- Old Installers (RMM.AdvancedThreatDetection.exe)

    Fix Known Issues:
        Fix Actions for known issues we are currently experiancing, if any. 
        WARNING: This will uninstall Datto AV in order to fix certain multiple installer problems.  It will be reinstalled at the next policy enforcement check.
    
    Restart Service:
        The recommended maintenance action for when the EDR service is not communicating with the API.
    
    Stop Service:
        It is recommended you turn off realtime monitoring or other policies from the console. But if necessary, this utility will stop the service from the endpoint. A reboot or forced restart of the service will restore it.
    
    Uninstall:
        Used when other methods of removing Datto EDR are not working.  Primary recommended uninstallation method is to remove the
         Datto EDR Security policy from the system in RMM and then issue uninstall from the Datto EDR user interface. 
         WARNING: Uninstalling Datto AV deletes all quarantine files making them unrecoverable.


   This script, like all datto RMM Component scripts unless otherwise explicitly stated, is the copyrighted property of Datto, Inc.;
   it may not be shared, sold, or distributed beyond the Datto RMM product, whole or in part, even with modifications applied, for 
   any reason. this includes on reddit, on discord, or as part of other RMM tools. PCSM and VSAX stand as exceptions to this rule.
   	
   the moment you edit this script it becomes your own risk and support will not provide assistance with it.#>


#region ---Variables--------------------------------------------------------------------------------------------------------------------------

# Static Variables
$EDR_SERVICE_NAME = "HUNTAgent"
$EDR_PROCESS_NAME = "agent"
$EDR_PROCESS_FRIENDLY_NAME = "Datto EDR Agent"

$AV_SERVICE_NAME = "EndpointProtectionService"
$AV_SERVICE_NAME2 = "EndpointProtectionService2"
$AV_PROCESS_NAME = "endpointprotection"
$AV_DATA_PATH = "$Env:ProgramData\DattoAV\Endpoint Protection SDK"


$RWD_PROCESS_NAME = 'RWDWrapper'

$RB_SERVICE_NAME = 'dattorollbackservice'
$RB_PROCESS_NAME = 'rollbackservice'


# Input Variables
$varGetLogSnips = if ($env:varGetLogSnips) { $true } else { $false }
$BYPASS_SERVICE_CHECK = if ($env:varBypassInstallCheck) { $true } else { $false }

Write-Host "varAction: $($env:varAction)"
SWITCH ($env:varAction) {
    "Diagnostic" { $Diagnostic = $true }
    "Fix Known Issues" { $FixKnownIssues = $true }
    "Restart Service" { $RestartService = $true }
    "Stop Service" { $StopService = $true }
    "Force Uninstall" { 
        $UninstallEDR = $true;
        if ($env:varUninstallToken) {
            $UninstallToken = $env:varUninstallToken
            Write-Host "varUninstallToken: $UninstallToken"
        } else {
            Write-Host "! Notice: No Uninstall Token (varUninstallToken) was specified. If Uninstall Protection is turned on, this action will be blocked without an Uninstall Token from your EDR console."
        }
     }
}


#region ---Functions--------------------------------------------------------------------------------------------------------------------------

# Helper Functions
Function Write-FormattedObject ([Object]$Object) {
    # Helper Function to print an object with indendation in RMM Scripts. Helps readability.
    try {
        if (-NOT $MAX_WIDTH) {
            if ($pshost.UI.RawUI.BufferSize.Width) {
                $Global:MAX_WIDTH = $pshost.UI.RawUI.BufferSize.Width -3
            } elseif ((Get-Host).UI.RawUI.BufferSize.Width) {
                $Global:MAX_WIDTH = (Get-Host).UI.RawUI.BufferSize.Width -3
            } else {
                $Global:MAX_WIDTH = 150
            } 
        }
        $width = $MAX_WIDTH - 3
        Write-Host ('-'*$width)
        $Object | Out-String -Stream -Width $width | foreach { if ($_) { Write-Host "|  $_" } } 
        Write-Host ('-'*$width)
        Write-Host `r
    } catch {
        Write-BetterErrorTrace -Err $_
    }
}

Function Write-BetterErrorTrace {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Management.Automation.ErrorRecord]$Err,

        [Switch]$WarnOnly
    )
    try {
        $Level = if ($WarnOnly) { "WARN" } else { "ERROR" }

        $Message = $Err.Exception.Message
        $Category = $Err.CategoryInfo.Category
        $InvocationName = $Err.InvocationInfo.InvocationName
        $MyCommand = $Err.InvocationInfo.MyCommand
        $Statement = $Err.InvocationInfo.Statement
        $LineNumber = $Err.InvocationInfo.ScriptLineNumber
        $Line = $Err.InvocationInfo.Line
        $StackTrace = $err.ScriptStackTrace
    
        $CallStack = Get-PSCallStack | Select Location, FunctionName
        $CallingFunctionName = $CallStack[1].FunctionName
        $Location = $CallStack[1].Location
        
        $msg = "! $Level [$CallingFunctionName][$InvocationName]"
        if ("$MyCommand" -ne "$InvocationName") {
            $msg += "[$MyCommand]"
        }        
        $msg += "[$Category] $Message"
        if ($Statement) {
            $msg +=  "($Statement)"
        }
        Write-Host -ForegroundColor Red $msg
        Write-Host -ForegroundColor Red $StackTrace
        Write-Host -ForegroundColor Red "$($LineNumber): $($Line.Trim(' '))"
        Write-Host `r
    } catch {
        Write-Host -ForegroundColor Red "! ERROR: Error Handling Function ran into an error: $_"
    }   
}

Function Convertto-ShortenedEDRLogs ($logs) {
    $parsed_logs = $logs | foreach {
        try {
            #Parse it so the lines are more readable
            $parsed = [regex]::Match($_, "\[(?<timestamp>[^\[\]]+)\]\[[^\[\]]+\]\[[^\[\]]+\]\[(?<ver>[^\[\]]+)\]\[[^\[\]]+\]\[(?<level>[^\[\]]+)\]\[(?<where>[^\[\]]+)](?<msg>.*)$")
            if ($parsed.Success) {
                $ver = $($parsed.Groups['ver'].Value)
                if ($version -ne $ver) {
                    $version = $ver
                    "`rEDR AGENT VERSION: $version==>"
                }       
                "[$($parsed.Groups['timestamp'].Value)][$($parsed.Groups['where'].Value)][$($parsed.Groups['level'].Value)] $($parsed.Groups['msg'].Value)"
                #[2024-10-18 18:54:46 UTC][ccd9778b-e8d8-45da-bf73-4b5266ac34a7][hyperion][3.12.0.2205][63568][INF][agent::jobs::98] Executing Real Time (8759f8e8-212e-41d8-89e6-3fce6b0bf25e)
            } else {
                # Save unparsed
                $_
            }
        } catch {
            $err = $_.Exception.Message
            Write-Host "! ERROR: $err"
        }
    }
    return $parsed_logs
}


# Functions
Function Get-ServiceInfo ([String]$Name, [Switch]$Quiet=$false) {

    # Get-Service but with Installation directory, ImageName, ImagePath info.
    if (-NOT $Quiet) { Write-Host "- Retrieving Service Information for Service named '$Name'" }
    try {
        $Service = Get-Service -Name $name -ea 1
        $Service = Get-CimInstance -Query "select * from win32_service where name='$Name'" -ea 1
        #| Select-Object DisplayName, Name, Description, StartType, Status, ProcessId, 
        if (-NOT $Service) {
            Write-Host "  RESULT: Could not find a service named '$name'"
            return
        }

        if ($service.AcceptStop) {
            $isTamperProtected = $false
        } else {
            $isTamperProtected = $true
        }

        # Get InstallDirectory and Path
        $imagePath = [regex]::Match($Service.PathName, "(['`"](?<p>[^'`"]+)['`"]|(?<p>[^\s]+))").Groups["p"].Value
        if (Test-Path $imagePath) {
            $Directory = $imagePath | split-path
            $ImageName  = $imagePath | split-Path -Leaf
            $file = Get-Item $imagePath -ea 0 | select creationTimeUtc, LastWriteTimeUtc
        } else {
            Write-Host "!  WARNING: Could not parse or find ImagePath: [$($Service.BinaryPathName)] -> [$imagePath]"
        }

    } catch {
        $err = $_
        Switch -regex ($err.Exception.Message) {
            Default { 
                Write-BetterErrorTrace -Err $err 
            }
        }
        return
    }
        
    return [PSCustomObject]@{
        Name             = $service.Name
        DisplayName      = $service.DisplayName
        Description      = $service.Description
        Status           = $service.Status
        State            = $service.State
        ExitCode         = $service.ExitCode
        TamperProtected  = $isTamperProtected
        ProcessId        = if ($service.ProcessId -AND $service.ProcessId -ne 0) { $service.ProcessId } else { $null }
        StartMode        = $service.StartMode
        ImageName        = $ImageName
        ImagePath        = $imagePath
        ImageDirectory   = $Directory
        FileCreated      = $file.CreationTimeUtc
        FileModified     = $file.FileModifiedUtc
    }
}

Function Get-ProcessInfo {
    [CmdletBinding(DefaultParameterSetName='byId')]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byId')]
        [Int]$Id,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byIdu')]
        [UInt32]$ProcessId,

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byName')]
        [Alias("ProcessName")]
        [String]$Name
    )

    PROCESS {
        
        try {
            switch -Regex ($PSCmdlet.ParameterSetName) {
                'byId' {
                    if (-NOT $Id) { $Id = $ProcessId }

                    Write-Host "- Getting Process by Id $Id"
                    $Processes = Get-Process -Id $Id -ea 1
                    #$Processes = get-ciminstance -query "select * from win32_process where processId=$Id" -ea 1
                    if (-NOT $processes) {
                        Write-Host "!  RESULT: Cannot a find process with Id: $Id"
                        return
                    }
                }
                'byName' {
                    Write-Host "- Getting Process by Name $Name"
                    $Processes = Get-Process -Name $Name -ea 1
                    #$Processes = get-ciminstance -query "select * from win32_process where name='$Name.exe'" -ea 1
                    if (-NOT $processes) {
                        Write-Host "!  RESULT: Cannot find a process with Name: $Name"
                        return
                    }
                }
            }
        
            #$process | Select-Object Id, Name, Description, Company, ProductVersion, Path, CommandLine, ParentProcessId, Parent, Handles, Status, StartTime, Responding, TotalProcessorTime
            foreach ($process in $Processes) {
                try {
                    $ProcessCIM = get-ciminstance -query "select * from win32_process where processId=$($process.Id)" -ea 1
                    if ($ProcessCIM.ParentProcessId) {
                        Write-Verbose "  Getting Parent Process Information"
                        $Parent = get-ciminstance -query "select * from win32_process where processId=$($ProcessCIM.ParentProcessId)" -ea 1
                    }
    
                    if ($process.Path) {
                        $ImageDirectory = $process.Path | Split-Path
                        $file = Get-Item $process.Path | select creationTimeUtc, LastWriteTimeUtc
                    }
                    $Obj = [PSCustomObject]@{
                        Name                     = $process.Name
                        ProcessId                = if ( $process.Id) {  $process.Id } else { $process.ProcessId }
                        Description              = $process.Description
                        Company                  = $process.Company
                        ProductVersion           = $process.ProductVersion
                        ImageName                = $ProcessCIM.Name
                        ImagePath                = $process.Path
                        ImageDirectory           = $ImageDirectory
                        FileCreated              = $file.CreationTimeUtc
                        FileModified             = $file.LastWriteTimeUtc
                        CommandLine              = if ($process.CommandLine) { $process.CommandLine } else { $ProcessCIM.CommandLine } 
                        StartTime                = if ($process.StartTime) { $process.StartTime } else { $process.CreationDate } 
                        Responding               = $process.Responding
                        ParentProcessId          = $ProcessCIM.ParentProcessId
                        ParentProcessName        = $Parent.Name
                        ParentProcessPath        = $Parent.Path
                        ParentProcessCommandLine = $Parent.commandline
                    }
                    Write-Output $Obj 
                } catch {
                    $err = $_
                    Switch -regex ($err.Exception.Message) {
                        Default { 
                            Write-BetterErrorTrace -Err $err 
                        }
                    }
                    return
                }              
            }
            
        } catch {
            $err = $_
            Switch -regex ($err.Exception.Message) {
                'Cannot find a process with the name' {
                    Write-Host "! Error: Cannot find a process with name: $name"
                }
                'Cannot find a process with the process identifier' {
                    Write-Host "! Error: Cannot find a process with Id: $Id"
                }
                Default { 
                    Write-BetterErrorTrace -Err $err 
                }
            }
            return
        }
    }
}

Function Test-isDattoEDRInstalled {

    # Find Service
    if (-NOT $EDR_SERVICE_NAME) { $EDR_SERVICE_NAME = "HUNTAgent" }
    Write-Verbose "- Determining if Datto EDR is installed. Querying $EDR_SERVICE_NAME service."
    try {
        $Service =  Get-Service -Name $EDR_SERVICE_NAME -ea 1
    } catch {
        $err = $_
        Switch -regex ($err.Exception.Message) {
            "Cannot find a process" { 
                Write-Host "!  NOT FOUND: Could not find service with name $EDR_SERVICE_NAME."
                return $false
            }
            Default { 
                Write-BetterErrorTrace -Err $Err 
                return $false
            }
        }

    }

    return $true
}

Function Get-EDRInstallDirectory {
    # Sets $Global:DattoEDRInstallDirectory to point to the active install directory for Datto EDR.
    if (-NOT $EDR_SERVICE_NAME) { $EDR_SERVICE_NAME = "HUNTAgent" }
    if (-NOT $EDR_PROCESS_NAME) { $EDR_PROCESS_NAME = "agent" }
    if (-NOT $EDR_PROCESS_FRIENDLY_NAME) { $EDR_PROCESS_FRIENDLY_NAME = "Datto EDR Agent" }
    
    Write-Host "- Getting Datto EDR Installation Directory"
    try {
        Write-Host "- Retrieving Service Information for Service named '$EDR_SERVICE_NAME'"
        $Service = Get-CimInstance -Query "select * from win32_service where name='$EDR_SERVICE_NAME'" -ea 1
        if ($Service) {
            # Get InstallDirectory and Path
            $imagePath = [regex]::Match($Service.PathName, "(['`"](?<p>[^'`"]+)['`"]|(?<p>[^\s]+))").Groups["p"].Value
            if (Test-Path $imagePath -ea 1) {
                $InstallDirectory = $imagePath | split-path
            } else {
                Write-Host "! ERROR: Could not find EDR agent binary '$imagePath' from $EDR_SERVICE_NAME Service [$($Service.PathName)]."
                Write-Host "  Service may be pointed to a binary that no longer exists"
            }
        } else {
            Write-Host "! EDR Service named $EDR_SERVICE_NAME does not exist. EDR is not installed."
        }
        
    } catch {
        $err = $_
        Switch -regex ($err.Exception.Message) {
            Default { 
                Write-BetterErrorTrace -Err $err 
            }
        }
    }

    if (-NOT $InstallDirectory) {
        # Try the process path
        write-host "! WARNING: Unable to find valid install location from '$EDR_SERVICE_NAME' service. Trying from active processes."        

        # Get any EDR Agent processes:
        Write-Host "  Getting path from an active EDR Agent Process with description $EDR_PROCESS_FRIENDLY_NAME"
        try {
            $InstallDirectory = get-process -Name $EDR_PROCESS_NAME -ea 1 | Where { $_.description -eq $EDR_PROCESS_FRIENDLY_NAME } | select -First 1 | select path -ExpandProperty Path | Split-path
        } catch {
            $err = $_
            switch -regex ($Err.Exception.Message) {
                "Cannot find path" {
                     Write-Host "! NOTICE: Did not find any processes with name $($EDR_PROCESS_NAME)"
                }
                Default {
                    write-host "! WARNING: Unable to infer EDR installation location from any active EDR processes."
                    Write-BetterErrorTrace $err   
                }
            }
        }
    }

    if (-NOT $InstallDirectory) {
        # Try the process path
        write-host "! WARNING: Unable to find valid install location from '$EDR_SERVICE_NAME' service. Trying from active processes."        

        # Get any EDR Agent processes:
        Write-Host "  Getting path from an active EDR Agent Process with description $EDR_PROCESS_FRIENDLY_NAME"
        $procs = get-process | Where { $_.description -eq $EDR_PROCESS_FRIENDLY_NAME }
        if ($procs) {
            $procs | foreach {
                Write-Host "  Found an EDR agent process running in $($_.Path)" 
                $InstallDirectory = $_ | select path -ExpandProperty Path | Split-path
                break
            }
        } else {
            Write-Host "! NOTICE: Did not find any processes with name $($EDR_PROCESS_NAME): $err"
        }
    }


    $InfocyteFolder = "$env:ProgramFiles\Infocyte\Agent"
    if (-NOT $installDirectory -AND (Test-Path "$InfocyteFolder\agent.exe" -ea 0)) {
        Write-Host "Found an EDR agent in the legacy standalone folder: $InfocyteFolder"
        try {
            $Version = & "$InfocyteFolder\agent.exe" --Version
        } catch {
            Write-Host "  Error running agent.exe $InfocyteFolder\agent.exe --version"
            Write-BetterErrorTrace $_
        }
    }

    if (-NOT $InstallDirectory) {
        # Using Default RMM Install Location.
        write-host "  Falling back to Centrastage Folder."
        try {
            $InstallDirectory = "$((Get-ItemProperty "HKLM:\SOFTWARE\CentraStage" -Name "AgentFolderLocation" -ea stop).AgentFolderLocation)\AEMAgent\RMM.AdvancedThreatDetection"
        } catch {
            $err = $_
            write-host "! WARNING: Unable to infer EDR installation location from Datto RMM Registry. Attempting alternative logic with AEMAgent Process."
            Write-BetterErrorTrace $err 
            try {
                $InstallDirectory = "$(Get-Process aemagent -ea Stop | Select -First 1 | select Path -ExpandProperty Path | split-path)\RMM.AdvancedThreatDetection"
            } catch {
                $err = $_
                switch -regex ($Err.Exception.Message) {
                    "Cannot find path" {
                        write-host "! WARNING: Unable to infer EDR installation location from AEMAgent location. RMM's AEMAgent could not be found."
                    }
                    Default {
                        write-host "! WARNING: Unable to infer EDR installation location from AEMAgent location."
                        Write-BetterErrorTrace $err   
                    }
                }
            }
        }
    }

    if (-NOT $InstallDirectory) {
        # Use Hardcoded Default        
        $InstallDirectory = "$env:ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection"
        if (Test-Path $InstallDirectory) {
            Write-Host "Could not find path so using hardcoded default path: $InstallDirectory (exists)"
        } else {
            Write-Host "Could not find path so using hardcoded default path: $InstallDirectory (Does not exist)"
        }
    }

    return $InstallDirectory
}

Function Get-EDRVersion ($Path, [Switch]$raw){
    if ($Path) {
        Write-Host "- Retrieving Datto EDR Version information for agent: $Path"
    } else {
        
        if (-NOT $EDR_SERVICE_NAME) { $EDR_SERVICE_NAME = "HUNTAgent" }
        Write-Host "- Retrieving Datto EDR Version information of installed EDR service: $EDR_SERVICE_NAME"
        $Service = Get-ServiceInfo -Name $EDR_SERVICE_NAME -Quiet
        if (-NOT $Service) {
            Write-Host "! ERROR: Could not find service '$EDR_SERVICE_NAME'. Datto EDR may not be installed."
            return
        } elseif (-NOT (Test-Path $Service.ImagePath -ea 0)) {
            Write-Host "!  ERROR: Could not find ImagePath for service $EDR_SERVICE_NAME. Datto EDR installation appears broken"
            return
        }
        $Path = $Service.ImagePath
    }
       

    # Call agent.exe --version to get the version
    if (Test-Path $Path -ea 0) {
        try {
            $versionOutput = & ($Path) --version --no-gui --ignore-versioning 2>&1
            <# EXAMPLE:
                RTS Agent 3.12.0
                Build Number: 2205
                Build Date:   2024-09-27 18:12:07
                Build Commit: 1da5221b7565c0b89c92e7642d03436d2454eaa3
            #>
            if( -NOT $versionOutput -OR $versionOutput -match "error") {
                Write-Host "! ERROR: Error calling 'agent.exe --version'."
                Write-FormattedObject $versionOutput
                return
            }
         
            #tokenise output data
            $varVersion1=((($versionOutput | select-string 'RTS Agent') -as [string]) -split " " | select -last 1)
            $varVersion2=((($versionOutput | select-string 'Number') -as [string]) -split " " | select -last 1)
            [version]$AgentVersion="$varVersion1.$varVersion2"      
            #Write-Host "  Version: $($Version.ToString())"
            #Write-FormattedObject $versionOutput
        } catch {
            $err = $_.Exception.Message
            Write-Host "!  ERROR Parsing Version Output: $err" 
        }
    } else {
        Write-Host "!  ERROR: Could not find Path: $Path"
        return
    }

    # Check version stored in Uninstall Key to find any mismatches
    $DattoEDRUninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent"
    [version]$UninstallVersion=(Get-ItemProperty $DattoEDRUninstallKey -Name DisplayVersion -ea 0).DisplayVersion
    if (!$UninstallVersion) {
        [version]$UninstallVersion=(Get-ItemProperty $DattoEDRUninstallKey -Name DisplayVersion -ea 0).DisplayVersion
    }
    if (!$UninstallVersion) {
        write-host "! WARNING: '$DattoEDRUninstallKey' could not be found"
        write-host "  Datto EDR may not be installed correctly. You will not be able to use add/remove programs to remove Datto EDR."
    }     
    if ($AgentVersion -ne $UninstallVersion) {
        write-host "! WARNING: '$DattoEDRUninstallKey' version ($UninstallVersion) does not match actual agent version ($AgentVersion)"
        write-host "  Datto EDR may not be updating the displayed version correctly. Please report this error to Datto Support."
    }
    
    if ($raw) {
        return $versionOutput
    } else {
        return [version]$AgentVersion
    }
}

Function Restart-EDR {

    if (-NOT $EDR_SERVICE_NAME) { $EDR_SERVICE_NAME = "HUNTAgent" }
    Write-host "- Restarting Datto EDR service ($EDR_SERVICE_NAME)."
    
    $Service = Get-ServiceInfo $EDR_SERVICE_NAME
    if (-NOT $Service) {
        Write-Host "$EDR_SERVICE_NAME Service not running. Exiting..."
        exit 1
    }
    Write-Host "  Found $EDR_SERVICE_NAME service."
    Write-FormattedObject $Service
    
    if ($Service.TamperProtected) {
        # This is not implimented yet but may be before the end of 2024.
        write-host "! NOTICE: Datto EDR service cannot be stopped directly."
        write-host "  This utility will need to be updated to support tamper protection."
        Write-Host "Exiting..."
        return $false
    }


    if ($Service.State -eq "Running") {
        $ProcessIdOld = $Service.ProcessId
        Write-Host "  ... Stopping $EDR_SERVICE_NAME Service."
        Stop-Service -Name $EDR_SERVICE_NAME
        Start-Sleep 1
    }

    Write-Host "  ...Starting $EDR_SERVICE_NAME Service."
    try {
        Start-Service $EDR_SERVICE_NAME -ea 1
    } catch {
        $err = $_
        switch -Regex ($err) {
            default { 
                Write-BetterErrorTrace $_
                Write-Host "Exiting..."
                return $false
            }
        }
    }

    Write-Host "  Datto EDR Service Restarted!"

    # Check startup type is automatic
    if ($Service.StartupType -match "Auto") {
        write-host "! WARNING: Datto EDR Service is not set to start automatically!  $(($Service.StartupType)) Attempting to fix"
        write-host "  StartType of $($EDR_SERVICE_NAME): '$($Service.StartupType)'"

        try {
            Set-Service -Name $EDR_SERVICE_NAME -StartupType Automatic -ea 1
        } catch {
            $err = $_.Exception.Message
            switch -Regex ($err) {
                "Access is denied" {
                    write-host "! ERROR: Datto EDR Service could not be set to automatic StartupType due to tamper protection.  Let Datto Support know about this error as the script may need to be updated."
                }
                default { 
                    Write-Host "  ERROR: Datto EDR Service could not be set to automatic StartupType." 
                    Write-BetterErrorTrace $err
                    Write-Host "  Let Datto Support know about this error as it is unexpected."
                }
            }
        }
    }

    Write-Host "  Checking final status..."
    $Service = Get-ServiceInfo -Name $EDR_SERVICE_NAME
    if ($Service.State -eq "Running" -AND $Service.ProcessId) {
        if ($Service.ProcessId -eq $ProcessIdOld) {
            Write-Host "! ERROR: ProcessId is the same."
            return $false
        } else {
            Write-Host "  Restarted $EDR_SERVICE_NAME service, now running as Process Id: $($Service.ProcessId)."
            Write-Host "  Status: $($Service.State) ($($Service.Status))"
            return $true
        }        
    } else {
        Write-Host "! WARNING: Restarted Service failed checks. May not be running."
        Write-Host "  New Status: $($Service.State) ($($Service.Status))"
        return $false
    }

    
}

Function Stop-EDR {
    if (-NOT $EDR_SERVICE_NAME) { $EDR_SERVICE_NAME = "HUNTAgent" }

    Write-Host "- Stopping Datto EDR Service ($EDR_SERVICE_NAME)"

    $Service = Get-ServiceInfo $EDR_SERVICE_NAME
    if (-NOT $Service) {
        Write-Host "$EDR_SERVICE_NAME Service not running.  Cannot stop service."
        return
    }
    Write-Host "  Found $EDR_SERVICE_NAME service."
    Write-FormattedObject $Service
    
    if ($Service.TamperProtected) {
        # This is not implimented yet but may be before the end of 2024.
        write-host "! NOTICE: Datto EDR service cannot be stopped directly."
        write-host "  This utility will need to be updated to support tamper protection."
        return
    }

    try {
        Stop-Service $EDR_SERVICE_NAME -ea 1

    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            "Cannot find any service" { 
                write-host "! WARNING: Datto EDR Service is not installed. Cannot restart service."
                write-host "  ERROR: $err"
            }
            "Cannot stop" {
                write-host "! WARNING: Datto EDR Service could not be stopped. This error is not related to tamper protection."
                write-host "  ERROR: $err"
            }
            default { 
                Write-Host "  ERROR: Could not stop service. $err" 
            }
        }
    }
    Write-Host "  Checking final status..."
    $Service = Get-ServiceInfo $EDR_SERVICE_NAME
    Write-Host "  New Status: $($Service.State) ($($Service.Status))"
}

Function Uninstall-EDR ([String]$UninstallToken) {
    if (-NOT $EDR_SERVICE_NAME) { $EDR_SERVICE_NAME = "HUNTAgent" }

    if ($UninstallToken) {
        Write-Host "- Uninstalling Datto EDR (Service = $EDR_SERVICE_NAME) with uninstall token: '$UninstallToken'"
    } else {
        Write-Host "- Uninstalling Datto EDR (Service = $EDR_SERVICE_NAME)"
    }
    

    $Service = Get-ServiceInfo $EDR_SERVICE_NAME
    if (-NOT $Service) {
        Write-Host "$EDR_SERVICE_NAME Service not installed. Exiting..."
        exit 1
    }
    
    Write-Host "  Found $EDR_SERVICE_NAME service."
    Write-FormattedObject $Service
    
    if ($Service.TamperProtected) {
        # This is not implimented yet but may be before the end of 2024.
        write-host "! NOTICE: Datto EDR service is tamper protected."
        write-host "  This utility may need to be updated to support tamper protection."
    }

    try {
        Write-Host "  Attempting to stop service (may not be necessary but safer)"
        Stop-Service $EDR_SERVICE_NAME -ea 1
    } catch {
        $err = $_
        switch -Regex ($err) {
            "Cannot find any service" { 
                write-host "! WARNING: Datto EDR Service is not installed."
            }
            "Cannot stop" {
                write-host "! WARNING: Datto EDR Service could not be stopped. This error is not related to tamper protection."
            }
            default { 
                Write-Host "  ERROR: Could not stop service." 
                Write-BetterErrorTrace $err
            }
        }
    }

    # Run Uninstall
    if (Test-Path $Service.ImagePath) {
        
        $agentOutput = & ($Service.ImagePath) --no-gui --uninstall $UninstallToken 2>&1
        Write-FormattedObject $agentOutput

        if ($agentOutput -match "Error: Unable to verify uninstallation with server" -OR $agentOutput -match "NotApproved") {
            Write-Host "!  NOTICE: Uninstallation Key Required.  You can get this from the Datto EDR Settings Page under Uninstall Protection."
        }

    } else {
        Write-Host "!  Notice: $($Service.ImagePath) does not exist, cannot run uninstaller."
    }
}

Function Clean-EDR {
    Write-Host "- Cleaning up Datto EDR Artifacts from Broken Installations"

    if (-NOT $EDR_SERVICE_NAME) { $EDR_SERVICE_NAME = "HUNTAgent" }
    $Service =  Get-Service -Name $EDR_SERVICE_NAME -ea 0
    if (-NOT $Service) {
        write-host "! Datto EDR service is not installed"
        return
    }

    if ($Service.CanStop -eq $false) {
        # This is not implimented yet but may be before the end of 2024.
        write-host "! Datto EDR service cannot be stopped directly."
        write-host "  This utility will need to be updated to support tamper protection."
        return $false
    }

    try {
        Stop-Service $EDR_SERVICE_NAME -ea 1
    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            "Cannot find any service" { 
                write-host "! WARNING: Datto EDR Service is not installed. Cannot restart service."
                write-host "  ERROR: $err"
                return $false
            }
            "Cannot stop" {
                write-host "! WARNING: Datto EDR Service could not be stopped. This error is not related to tamper protection."
                write-host "  ERROR: $err"
                return $false
            }
            default { 
                Write-Host "  ERROR: Could not stop service. $err" 
            }
        }
    }
    
    try {
        Start-Service $EDR_SERVICE_NAME -ea 1
        #Write-Host "  Datto EDR Service Restarted!"
    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            default { 
                Write-Host "  ERROR: Could not start service: $err" 
            }
        }
    }

    # Check startup type is automatic
    if ($Service.StartMode -ne 2) {
        write-host "! WARNING: Datto EDR Service is not set to start automatically!  Attempting to fix"
        write-host "  StartType of $($EDR_SERVICE_NAME): '$($Service.StartType)'"

        try {
            Set-Service -Name $EDR_SERVICE_NAME -StartupType Automatic -ea Stop
        } catch {
            $err = $_.Exception.Message
            switch -Regex ($err) {
                "Access is denied" {
                    write-host "! ERROR: Datto EDR Service could not be set to automatic StartupType due to tamper protection."
                    Write-BetterErrorTrace $err
                    Write-Host "  You may need to reinstall Datto EDR."
                }
                default { 
                    Write-Host "  ERROR: Datto EDR Service could not be set to automatic StartupType: $err" 
                    Write-Host "  You may need to reinstall Datto EDR."
                }
            }
        }
    }
    return $true
}

Function Get-EDRRegistry {
    $RegistryKey = 'HKLM:\SOFTWARE\Datto\EDR\'
    # Get EDR Registry Keys
    write-Host "- Getting EDR Registry Key $RegistryKey"
    try {
        
        if (Test-Path $RegistryKey) {
            $EDR_Registry = Get-ItemProperty $RegistryKey -ea 1
            return $EDR_Registry
        } else {
            Write-Host "! WARNING: EDR Registry key '$RegistryKey' does not exist!"
        }
    } catch {
        Write-BetterErrorTrace $_
    }
}

Function Get-EDRConfigToml {
    if (-NOT $DattoEDRInstallDirectory) { $DattoEDRInstallDirectory = Get-EDRInstallDirectory }

    $configTOMLPath = "$DattoEDRInstallDirectory\config.toml"
    Write-Host "Getting EDR Config file: $configTOMLPath"
     # Get EDR from config.toml
     try {
        if (Test-Path $configTOMLPath) {
            $Config_raw = get-content $configTOMLPath -ea 1   
        } else {
            Write-Host "! WARNING: Config.toml at '$configRegistry' does not exist!"
        }
    } catch {
        Write-BetterErrorTrace $_
    }


    if (-NOT $Config_raw) {
        Write-Host "  Couldn't find config.toml -- trying to grab the backup from registry:"
        $RegistryKey = 'HKLM:\SOFTWARE\Datto\EDR\'
        try {
            $Config_raw = Get-ItemProperty $RegistryKey -Name AgentConfig -ea 0 | select -ExpandProperty AgentConfig | ConvertFrom-Base64String
        } catch {
            Write-BetterErrorTrace $_
        }
   }

    $Config = [PSCustomObject]@{
        TomlPath = $configTOMLPath
        TomlRaw = $Config_raw
    }

    if ($Config_raw) {
        try {
            $Config_raw.split("`n") | foreach { 
                if ($_) { 
                    $var_name = ($_ -split " = ")[0]
                    $var_value = ($_ -split " = ")[1].Replace('"', '').Replace("'","")
                    $Config | Add-Member -MemberType NoteProperty -Name $var_name -Value $var_value
                }
            }
            $InstanceName = [regex]::Match($Config.'api-url', "https://(?<cname>[^\.]+)\.infocyte\.com").Groups["cname"].Value
            $API_URL = [regex]::Match($Config.'api-url', "(?<url>https://.*\.infocyte\.com)").Groups["url"].Value    
        } catch {
            Write-BetterErrorTrace $_
            Write-FormattedObject $Config_raw
        }   
    }

    $Config | Add-Member -MemberType NoteProperty -Name InstanceName -Value $InstanceName
    $Config | Add-Member -MemberType NoteProperty -Name API_URL -Value $API_URL

    return $Config
    
}

Function Get-EDRConfig {
    
    if (-NOT $DattoEDRInstallDirectory) { $DattoEDRInstallDirectory = Get-EDRInstallDirectory }
    
    $configTOMLPath = "$DattoEDRInstallDirectory\config.toml"
    $configRegistry = 'HKLM:\SOFTWARE\Datto\EDR\'

    Write-Host "- Getting EDR Configuration from $configTOMLPath and $configRegistry"

    # Get EDR Registry Keys
    try {
        
        if (Test-Path $configRegistry) {
            $EDR_Registry = Get-ItemProperty $configRegistry -ea 1
            $AgentId = $EDR_Registry.AgentId
            $DeviceId = $EDR_Registry.DeviceID
            #Write-FormattedObject $EDR_Registry
        } else {
            Write-Host "! WARNING: EDR Registry key '$configRegistry' does not exist!"
        }
    } catch {
        Write-BetterErrorTrace $_
    }
 
    # Get EDR from config.toml
    try {
        if (Test-Path $configTOMLPath) {
            $Config_raw = get-content $configTOMLPath -ea 1   
        } else {
            Write-Host "! WARNING: Config.toml at '$configRegistry' does not exist!"
        }
    } catch {
        Write-BetterErrorTrace $_
    }
    if (-NOT $Config_raw -AND $EDR_Registry) {
        # Try grabbing from registry:
        try {
            if ($EDR_Registry.AgentConfig) {
                $Config_raw = $EDR_Registry.AgentConfig | ConvertFrom-Base64String
            } else {
                Write-Host "! Warning: Registry did not contain a config.toml backup in AgentConfig"
            }
        } catch {
            Write-BetterErrorTrace $_
        }
        Write-Host "! ERROR Couldn't get config from AgentConfig in '$configRegistry'"
   }

    $Config = [PSCustomObject]@{
        TomlPath = $configTOMLPath 
        RegistryPath = $configRegistry
        AgentId = $AgentId
        DeviceId = $DeviceId
        Toml = New-Object -Type PSCustomObject
        TomlRaw = $Config_raw
        Registry = $EDR_Registry
    }

    if ($Config_raw) {
        try {
            $Config_raw.split("`n") | foreach { 
                if ($_) { 
                    $var_name = ($_ -split " = ")[0]
                    $var_value = ($_ -split " = ")[1].Replace('"', '').Replace("'","")
                    $Config.Toml | Add-Member -MemberType NoteProperty -Name $var_name -Value $var_value
                }
            }
            $InstanceName = [regex]::Match($Config.Toml.'api-url', "https://(?<cname>[^\.]+)\.infocyte\.com").Groups["cname"].Value
            $API_URL = [regex]::Match($Config.Toml.'api-url', "(?<url>https://.*\.infocyte\.com)").Groups["url"].Value    
        } catch {
            Write-BetterErrorTrace $_
            Write-FormattedObject $Config_raw
        }   
    }

    $Config | Add-Member -MemberType NoteProperty -Name InstanceName -Value $InstanceName
    $Config | Add-Member -MemberType NoteProperty -Name API_URL -Value $API_URL

    return $Config
}

function Get-KaseyaOneConfig {
    # Get KaseyaOne dattoedr.json.  This file is written by EDR and tells other Kaseya modules what features are available and configured in Datto EDR.
    
    $dattoedrJSONPath = "C:\programData\kaseyaone\dattoedr.json"
    Write-Host "- Retrieving KaseyaOne EDR Configuration File from $dattoedrJSONPath"
    try {
        $Dattoedrjson =  Get-Content $dattoedrJSONPath -ea 1 | convertfrom-json
        $lastUpdated = [DateTime]$Dattoedrjson.timestamp

        if ($lastUpdated -lt (Get-Date).AddDays(-1)) {
            Write-Host "! WARNING: DattoEDR.json has not been updated since $($lastUpdated.ToUniversalTime()) UTC ($((Get-Date) - $lastUpdated))"
        }
    } catch {
        Write-BetterErrorTrace $_
    }
    Write-Host " Found DattoEDR.json -- last updated $lastUpdated ($($Dattoedrjson.timestamp))"
    return $Dattoedrjson
}


#region ---Code--------------------------------------------------------------------------------------------------------------------------

#region ---Pre-Checks

Write-Host "`n"
Write-Host "`n=============================================`n"
Write-Host "- Datto EDR Installed Service Info"
Write-Host "`n=============================================`n"

# Checks if Datto EDR is Installed and Running
$EDR_isInstalled = $false
$EDR_isActive = $false

# Get Datto EDR Service
$EDRService = Get-ServiceInfo $EDR_SERVICE_NAME
if ($EDRService) {
    Write-Host "  Found EDR Service."
    Write-FormattedObject $EDRService
    $EDR_isInstalled = $true

    # Set Installation Directory to Root of Service
    $DattoEDRInstallDirectory = $EDRService.ImageDirectory
    Write-Host "  Datto EDR Installed to $DattoEDRInstallDirectory"
    Write-Host `r

    if ($EDRService.State -eq "Running") {

        # Get Datto EDR Agent Processes from Service
        if ($EDRService.ProcessId) {
            Write-Host "-  Getting process information for the $EDR_SERVICE_NAME service's primary process (processId = $($EDRService.ProcessId))"
            
            $EDRServiceProcess = Get-ProcessInfo -Id $EDRService.ProcessId
            if ($EDRServiceProcess) {
                Write-Host "  Found EDR Process:"
                Write-FormattedObject $EDRServiceProcess

                $EDR_isActive = $true
                
            } else {
                Write-Host "! ERROR: Primary process for $EDR_SERVICE_NAME is not running."
                
            }
            
            # Get EDR Version
            if ($EDRServiceProcess.ProductVersion) {
                [version]$EDRAgent_CurrVer = $($EDRServiceProcess.ProductVersion)
                Write-Host "EDR Version (from Process's ProductVersion): $EDRAgent_CurrVer"
            } else {
                Write-Host "! NOTE: ProductVersion not available in Process Info. Might be a Windows version thing."
            }
            
        } else {
            Write-Host "  ProcessId was not present in the service info, service may not be running."
        }
    } else {
        Write-Host "! NOTICE: EDR service present but not running."
    }
    
} else {
    Write-Host "! NOTICE: Could not find service '$EDR_SERVICE_NAME'. Datto EDR is NOT installed."
    if ($BYPASS_SERVICE_CHECK) {
        # Check for remnants or broken installs
        Write-Host "  Bypass Service Check was enabled so continuing with diagnostic and other selected aactions.  Checking for remnants or broken installs."
    } else {
        Write-Host "!  Diagnostic not applicable. Exiting.  If you believe there are remnents or simply problems with the service, set the varBYPASS_SERVICE_CHECK variable to True and rerun the diagnostic."
        exit 0
    }
}
Write-Host `r

Write-Host "`n"
Write-Host "`n=============================================`n"
Write-Host "- Active Datto EDR Agents"
Write-Host "`n=============================================`n"


# Get any EDR Agent processes:
Write-Host "- Getting EDR Agent Processes with description $EDR_PROCESS_FRIENDLY_NAME"
$procs = Get-Process | Where { $_.description -eq $EDR_PROCESS_FRIENDLY_NAME }
Write-Host "  Found $($procs.count) active processes."
if ($procs) {
    $EDRProcesses = $procs | Get-ProcessInfo
    $EDRProcesses | foreach { 
        Write-FormattedObject $_; 
    }
}
Write-Host `r


Write-Host "`n"
Write-Host "`n=============================================`n"
Write-Host "- Datto EDR Module Config (kaseyaone\dattoedr.json)"
Write-Host "  This file is written by EDR and tells other Kaseya modules what features are available and configured in Datto EDR."
Write-Host "  While EDR is active, this file will be updated every two minutes."
Write-Host "`n=============================================`n"

# Get KaseyaOne dattoedr.json.  This file is written by EDR and tells other Kaseya modules what features are available and configured in Datto EDR.
$Dattoedrjson =  Get-KaseyaOneConfig
if ($Dattoedrjson) {
    Write-FormattedObject $Dattoedrjson
    $ts = [DateTime]$Dattoedrjson.timestamp

    if ($EDRProcesses -AND [DateTime]$Dattoedrjson.timestamp -lt (Get-Date).AddMinutes(-10)) {
        $EDR_isActive = $true

    } elseif ($EDRProcesses -AND [DateTime]$Dattoedrjson.timestamp -gt (Get-Date).AddMinutes(-60)) {
        # Active EDR Processes but EDR has not updated dattoedr.json
        Write-Host "! POTENTIAL PROBLEM: Datto EDR Processes are running but dattoedr.json has not been updated in over an hours."
        $EDR_isActive = $false

    } elseif ([DateTime]$Dattoedrjson.timestamp -lt (Get-Date).AddDays(-1)) {
        # Datto EDR datto.json not updated in over a day.
        Write-Host "! POTENTIAL PROBLEM: dattoedr.json has not been updated in over 24 hours."
        $EDR_isActive = $false
    }
    
} else {
    Write-Host "! ERROR: File Not Found. Service may not be active."
    $EDR_isActive = $false
}
Write-Host `r

Write-Host "`n"
Write-Host "`n=============================================`n"
Write-Host "- Datto EDR Version and Build Info"
write-Host "  Provide this output to Datto Support if you need an Offline Uninstall Key generated."
Write-Host "`n=============================================`n"

# Get EDR Agent Version
if (-NOT $EDRAgent_CurrVer) {
    [version]$EDRAgent_CurrVer = Get-EDRVersion
}
Write-host "  Current Datto EDR version: $EDRAgent_CurrVer"
Write-host `r

$EDRAgent_CurrVer_raw = Get-EDRVersion -raw
if ($EDRAgent_CurrVer_raw) {
    Write-Host "EDR Version and Build Output:"
    Write-FormattedObject $EDRAgent_CurrVer_raw
}
Write-host `r


# -------------------------------------------------------------------------------------------------------------
if ($Diagnostic) {

    Write-Host "- Running Full EDR Endpoint Diagnostic"
    Write-Host `r

    # Get System Info
    Write-Host "`n=============================================`n"
    Write-Host "- System Info"
    Write-Host "`n=============================================`n"

    $SystemInfo = systeminfo
    Write-FormattedObject $SystemInfo
    Write-Host `r

    # Get Timezone
    $tz = Get-TimeZone -ea Continue | select DisplayName -ExpandProperty DisplayName
    Write-Host "  TIMEZONE: $tz"
    Write-Host `r


    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Datto Configuration Info"
    Write-Host "`n=============================================`n"

    # List EDR Installation Directory files
    Write-Host  "  Datto EDR Installation Directory: $DattoEDRInstallDirectory"
    Write-Host "-------------------------------------------------------------------"
    Write-Host (Get-ChildItem $DattoEDRInstallDirectory | Out-String)
    Write-Host "-------------------------------------------------------------------`n"
    Write-Host `r
    
    # Get EDR Config from File
    $Config = Get-EDRConfigToml
    if ($Config) {
        Write-FormattedObject ($config | Select-Object -ExcludeProperty TomlRaw)
        Write-Host "`rRaw Unparsed config.toml:"
        Write-FormattedObject ($Config.TomlRaw)
        # Potential Issue: Ignore Versioning is On
        if ($Config.'ignore-versioning' -eq "true") {
            Write-Host "!  WARNING: ignore-versioning is turned on. Datto EDR Agent could not update with this setting in place. This setting is used for testing only."
        }
    }
    Write-Host `r
    
    # Get EDR Config from Registry
    $EDRRegistry = Get-EDRRegistry
    if ($EDRRegistry) {
        $AgentId = $EDRRegistry.AgentId
        $DeviceId = $EDRRegistry.DeviceId
    
        Write-FormattedObject $EDRRegistry
    }
    Write-Host `r

    
    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Antivirus Info"
    Write-Host "`n=============================================`n"

    # Active AV from Security Center
    Write-Host "-  Getting Installed AVs Registered with Microsoft Windows Security Center:"
    $ActiveAV = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct
    if ($ActiveAV) {
        $ActiveAV | foreach {
            Write-FormattedObject $_
        }
        
    }
    Write-Host `r

    if ($Dattoedrjson.dattoAv) {

        Write-Host "  Datto EDR is configured to deploy and manage Datto AV"

        # Get Datto AV Service
        Write-Host "- Determining if Datto AV is installed. Querying $AV_SERVICE_NAME and $AV_SERVICE_NAME2 service."
        $AVService = Get-ServiceInfo $AV_SERVICE_NAME
        $AVService2 = Get-ServiceInfo $AV_SERVICE_NAME2
        if ($AVService) {
            Write-FormattedObject $AVService
        } else {
            Write-Host "! ERROR: Could not find $AV_SERVICE_NAME"
        }
        if ($AVService2) {
            Write-FormattedObject $AVService2
        } else {
            Write-Host "! ERROR: Could not find $AV_SERVICE_NAME2"
        }
        Write-Host `r 


        # Get Datto AV process:
        Write-Host "- Getting Datto AV process with name $AV_PROCESS_NAME"
        $AVProcesses = Get-ProcessInfo -name $AV_PROCESS_NAME
        if ($AVProcesses) {
            Write-Host "  NOTE: Datto AV is active which means Tamper Protection is active, you will not be able to see the Path, CommandLine or ParentProcess Information."
            Write-FormattedObject $AVProcesses

            #Should only be 1
            $AVProcess = $AVProcesses | Select -First 1 
        } else {
            Write-Host "! NOTICE: Did not find any processes with name $($AV_PROCESS_NAME)"
        }
        Write-host `r


        # Get Datto AV AppSettings
        Write-Host "- Getting Datto AV AppSettings File"
        $AppSettingsPath = "$AV_DATA_PATH\Settings\AppSettings.json"
        
        if (Test-Path $AppSettingsPath) {
            $DattoAVAppSettings = Get-Content $AppSettingsPath | convertfrom-json
            if ($DattoAVAppSettings) {
                Write-FormattedObject ($DattoAVAppSettings | Select -ExcludeProperty Excluded*, Update.LastUrl)
                ($DattoAVAppSettings | Select Excluded*).PSObject.Members | ? { $_.MemberType -eq "NoteProperty"} | foreach {
                    Write-Host "$($_.Name):"
                    Write-FormattedObject $_.Value
                }
            } else {
                Write-Host "! WARNING: Datto AV AppSettings file could not be read or parsed from $AppSettingsPath"
            }
        } else {
            Write-Host "! WARNING: Datto AV AppSettings file does not exist at $AppSettingsPath"
        }
        Write-Host `r


    } elseif ($Dattoedrjson.managedWinDefAntivirus) {
        Write-Host "  Datto EDR is configured to manage Defender AV."
        try {
            $DefenderConfig = Get-MPPreference -ea 1
            if ($DefenderConfig) {
                Write-FormattedObject $DefenderConfig
            }    
        } catch {
            $err = $_.Exception.Message
            Write-Host "! ERROR could not get Defender Malware Protection Preferences. $err"
        } 
    } else {
        Write-Host "! WARNING: No Antivirus is configured to be managed by Datto EDR"
    }
    Write-Host `r

    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Datto Ransomware Detection (RWD) Module Info"
    Write-Host "`n=============================================`n"


    if ($Dattoedrjson.ransomwareDetection) {
        # Ransomware Detection Status
        $RWDProcesses = Get-ProcessInfo -Name $RWD_PROCESS_NAME
        if ($RWDProcesses) {
            if (([Object[]]$RWDProcesses).count -gt 1) {
                Write-Host "!  WARNING: Found $(([Object[]]$RWDProcesses).count) RWD processes.  Should only be 1..."
                
            } else {
                Write-Host "Found RWD Process process"
            }
            $RWDProcess = $RWDProcesses | Select -First 1
                
            $RWDProcesses | foreach { 
                Write-FormattedObject $_; 
            }

        } else {
            Write-host "  NO RESULTS"
        }

    } else {
        Write-Host "  Ransomware Detection is not enabled in EDR."
    }
    Write-Host `r


    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Datto Ransomware Rollback Module Info"
    Write-Host "`n=============================================`n"

    if ($Dattoedrjson.ransomwareRollback) {
        # Ransomware Rollback Status

        Write-Host "- Getting Ransomware Rollback Service ($RB_SERVICE_NAME)"
        $RBService = Get-ServiceInfo $RB_SERVICE_NAME
        if ($RBService) {
            Write-FormattedObject $RBService 

            # Get Datto EDR Agent Processes from Service
            if ($RBService.ProcessId) {
                Write-Host "-  Getting process information for the $RB_SERVICE_NAME service's primary process (processId = $($RBService.ProcessId)"
                
                $RBProcess = Get-ProcessInfo -Id $RBService.ProcessId
                if ($RBProcess) {   
                    Write-Host "  Found process:"
                    Write-FormattedObject $RBProcess
                } else {
                    Write-Host "! ERROR: Could not get primary listed process for $RB_SERVICE_NAME."
                }
            } 

        } else {
            Write-Host "! NOTICE: Could not find service '$RBService'. Ransomware Rollback is not installed."
        }
        Write-Host `r 

        
        # Get Rollback Processes:
        Write-Host "- Getting Ransomware Rollback processes named $RB_PROCESS_NAME"
        try {
            $RBProcesses = Get-Process -Name $RB_PROCESS_NAME -ea 1 | Get-ProcessInfo
        } catch {
            $err = $_.Exception.Message
            Write-Host "! NOTICE: Did not find any processes with name $($RB_PROCESS_NAME): $err"
        }
        if ($RBProcesses) {
            Write-Host "  Found $(([Object[]]$RBProcesses).count) processes"
            $RBProcesses | foreach { Write-FormattedObject $_; Write-Host `r }
        } else {
            Write-host "  NO RESULTS"
        }
    } else {
        Write-Host "  Ransomware Rollback Policy is not enabled in EDR."
    }
    Write-Host `r


    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Known Problem Detection Routines"
    Write-Host "`n=============================================`n"

    if ($EDRService.State -eq "Running" -AND $Dattoedrjson.timestamp -lt (Get-Date).AddMinutes(-60)) {
        Write-Host "! POTENTIAL PROBLEM: Datto EDR is running but has not updated the DattoEDR.JSON file in over an hour (should be every two minutes)"
        Write-Host "  This file lets Datto RMM know what services and configurations should be on the system to aid in RMM service monitoring."
        Write-Host "  Service Monitoring in RMM will be impacted by this issue.  Please reach out to support to let them know about this issue."
    }

    if ($EDRService.State -eq "Running" -AND $Dattoedrjson.timestamp -gt (Get-Date).AddMinutes(-60)) {
        # EDR is active and updating DattoEDR.JSON... so lets check some settings.
        Write-Host "- Checking for mismatches with the reported modules in DattoEDR.JSON."

        if ($Dattoedrjson.rebootRequired) {
            Write-Host "!  POTENTIAL PROBLEM: Datto AV Requires a Reboot."
        }
        
        if ($Dattoedrjson.isIsolated) {
            Write-Host "!  POTENTIAL PROBLEM: System is isolated by Datto EDR.  Unisolate from the console."
        }
        
        if ($Dattoedrjson.dattoAV -eq $false -AND ($AVService -OR $AVProcess)) {
            Write-Host "! POTENTIAL PROBLEM: DattoAV policy IS NOT applied according to dattoedr.json but Datto AV IS installed and/or running..."
        } elseif ($Dattoedrjson.dattoAV -eq $true -AND (!$AVService -OR !$AVProcess)) {
            Write-Host "! POTENTIAL PROBLEM: DattoAV policy IS applied according to dattoedr.json but Datto AV IS NOT installed and running..."
        }
        
        if ($Dattoedrjson.ransomwareDetection -eq $true -AND !$RWDProcess) {
            Write-Host "! POTENTIAL PROBLEM: Ransomware Detection policy IS applied according to dattoedr.json but Datto AV IS ONT installed or running..."
        } elseif ($Dattoedrjson.ransomwareDetection -eq $false -AND !$RWDProcess) {
            Write-Host "! POTENTIAL PROBLEM: Ransomware Detection policy IS NOT applied according to dattoedr.json but Datto AV IS installed and/or running..."
        }

        if ($Dattoedrjson.ransomwareRollback -eq $false -AND ($RBService -OR $RBProcess)) {
            Write-Host "! POTENTIAL PROBLEM: DattoAV policy IS NOT applied according to dattoedr.json but Datto AV IS installed and/or running..."
        } elseif ($Dattoedrjson.ransomwareRollback -eq $true -AND (!$RBService -OR !$RBProcess)) {
            Write-Host "! POTENTIAL PROBLEM: DattoAV policy IS applied according to dattoedr.json but Datto AV IS NOT installed and running..."
        }

    }
    Write-Host `r

    # Find problems with EDR Processes
    Write-Host "- Checking for Old EDR Agents or EDR Agent version mismatches."
    foreach ($process in $EDRProcesses) {

        if ($process.ProductVersion) {
            if ($EDRAgent_CurrVer -ne [Version]$process.ProductVersion) {
                Write-Host "! POTENTIAL PROBLEM: Process Id $($process.ProcessId) ($($process.name)) is running a mismatched version of the EDR Agent.  Service Agent is $EDRAgent_CurrVer while this process is $($process.ProductVersion)."
            }
        } else {
            # ToDO: Call --version on the file.
            if ($Process.Path) {
                $Version =  Get-EDRVersion -Path $process.Path
                if ($EDRAgent_CurrVer -ne $Version) {
                    Write-Host "! POTENTIAL PROBLEM: Process Id $($process.ProcessId) ($($process.name)) is running a mismatched version of the EDR Agent.  Service Agent is $EDRAgent_CurrVer while this process is $($process.ProductVersion)."
                }
            }
        }

        $thisisold = 30
        if ($process.FileModified -AND $process.FileModified -lt (Get-Date).AddDays(-$thisisold)) {
            Write-Host "! POTENTIAL PROBLEM: Process Id $($process.ProcessId) ($($process.name)) has an agent that has not been updated in over $thisisold days old.  This process's image was last modified on $($process.FileModified)."
        }

    }

    if ($EDRProcesses.count -gt 2) {
        Write-Host "! POTENTIAL PROBLEM: More than 2 EDR Processes ($($EDRProcesses[0].Name)) running. There should only be two generally (one for EDR service and one for Datto AV)."
    }
    if ($AVProcesses.count -gt 1) {
        Write-Host "! POTENTIAL PROBLEM: Multiple AV Processes ($($AVProcess.Name)) running. There should only be one."
    }
    if ($RWDProcesses.count -gt 1) {
        Write-Host "! POTENTIAL PROBLEM: Multiple Ransomware Detection Processes ($($RWDProcess.Name)) running. There should only be one."
    }
    if ($RBProcesses.count -gt 1) {
        Write-Host "! POTENTIAL PROBLEM: Multiple RAnsomware Rollback Processes ($($RBProcess.Name)) running. There should only be one."
    }
    Write-Host `r

    # Un-updated RMM Installers       
    Write-Host "- Checking for Rogue RMM Datto EDR Installer Processes"
    $EDRInstallerProcesses = $EDRProcesses | where { $_.Name -match "rmm.AdvancedThreatDetection" }
    if ($EDRInstallerProcesses) {
        Write-Host "! POTENTIAL PROBLEM: Found Rogue rmm.advancedthreatdetection processes. There should be no rmm.AdvancedThreatDetection.exe processes following an install by RMM."
        Write-Host "  RMM downloads and executes this process but it will end and be renamed agent.exe following successful Install."
        Write-FormattedObject $EDRInstallerProcesses
    }
    Write-Host `r

    
    if ($EDRService) {
        Write-Host "- Checking for EDR Service Issues"
        try {
            # Check for installation issues:
            if ($EDRService.StartMode -NotMatch "Auto") {
                write-host "! POTENTIAL PROBLEM: Datto EDR Service is installed but not set to start automatically!"
                write-host "   StartType of $($EDR_SERVICE_NAME): $($EDRService.StartMode)"
                write-host "   This is unexpected and should be reported to Datto Support."
            }

            # Check Uninstall Key
            [version]$UninstallVersion=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent" -Name DisplayVersion -ea 1).DisplayVersion
            if (!$UninstallVersion) {
                [version]$UninstallVersion=(Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent" -Name DisplayVersion -ea 1).DisplayVersion
            }
            if (!$UninstallVersion) {
                write-host "! POTENTIAL PROBLEM: Uninstall Key named 'Datto EDR Agent' could not be found. Datto EDR may not be installed correctly"
                write-host "  Please report to Datto Support that Datto EDR is installed without an associated Uninstall Key."
            }
        } catch {
            $err = $_
            Write-BetterErrorTrace -Err $err
        }
    }
    Write-Host `r

    <#
        # Check all possible folders for files:
        Write-Host "- Getting a list of other possible files associated to Datto EDR:"
        try {
            $Files = Get-ChildItem "$((Get-ItemProperty "HKLM:\SOFTWARE\CentraStage" -Name "AgentFolderLocation" -ea stop).AgentFolderLocation)\AEMAgent\RMM.AdvancedThreatDetection" -Depth 5 -include *.exe, *.config
            $Files += Get-ChildItem "$env:ProgramData\CentraStage*\AEMAgent\RMM.AdvancedThreatDetection" -Depth 5 -include *.exe, *.config | where { $Files.FullPath -notcontains $_.FullPath }
            $Files += Get-ChildItem "$env:ProgramFiles\Infocyte\" -Depth 5 -include *.exe, *.config | where { $Files.FullPath -notcontains $_.FullPath }
            $Files += Get-ChildItem "$env:ProgramFiles\Datto\Datto Rollback Driver\" -Depth 5 -include *.exe, *.config | where { $Files.FullPath -notcontains $_.FullPath }
            $Files += $EDRService | foreach { Get-Item $_.ImagePath -ea 0 | where { $Files.FullPath -notcontains $_.FullPath }}
            $Files += $EDRProcesses | foreach { Get-Item $_.ImagePath -ea 0 | where { $Files.FullPath -notcontains $_.FullPath }}
            $Files += $AVProcesses | foreach { Get-Item $_.ImagePath -ea 0 | where { $Files.FullPath -notcontains $_.FullPath }}
            $Files += $RWDProcesses | foreach { Get-Item $_.ImagePath -ea 0 | where { $Files.FullPath -notcontains $_.FullPath }}
            $Files += $RBProcesses | foreach { Get-Item $_.ImagePath -ea 0 | where { $Files.FullPath -notcontains $_.FullPath }}
            Write-FormattedObject $Files
        } catch {
            Write-Host 
        }
    #>
}

if ($varGetLogSnips) {


    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Gather Snippet of Latest EDR Logs"
    Write-Host "`n=============================================`n"


    # Get Latest EDR Logs
    Write-Host "-  Getting List of Available EDR Log Files: "
    $log_files = Get-ChildItem "$($Config.'log-dir')" -Include *.log -ea 0 | Sort-Object LastWriteTimeUtc | select LastWriteTimeUtc, FullName, Length
    if ($log_files) {
        # Print available log EDR Log files
        Write-FormattedObject ($log_files | sort-object LastWriteTimeUtc)

        $TodaysLogs = $log_files | where { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }
        if (-NOT $TodaysLogs) {
            Write-Host "!  NOTE: No EDR Log file was written to in the last 24 hours. May not have been active."
        }
    } else {
        Write-Host "! WARNING: No logs were found in $($Config.'log-dir')\"
    }
    write-host `r


    # Last Agent Logs
    $LastAgentLog = Get-ChildItem "$($Config.'log-dir')\agent*" -Include *.log -ea 0 | Sort-Object LastWriteTimeUtc | select -Last 1
    if ($LastAgentLog) {

        Write-Host "-  Getting Errors from latest agent log:"
        Write-Host "  $LastAgentLog"
        $logs = $LastAgentLog | get-content | Select-String "(ERR|error|failed|could not)"
        $logs = Convertto-ShortenedEDRLogs $logs
        Write-FormattedObject $logs

        WRite-Host "-  Getting Last 30 Lines from latest Agent Log:"
        $logs = $LastAgentLog | get-content -Tail 30 
        $logs = Convertto-ShortenedEDRLogs $logs0
        Write-FormattedObject $logs
        
    } else {
        Write-Host "! NOTE: No agent logs were found in $($Config.'log-dir')\"
    }
    write-host `r


    # Last Update Logs
    $LastAgentUpdateLog = Get-ChildItem "$($Config.'log-dir')\update*" -Include *.log -ea 0 | Sort-Object LastWriteTimeUtc | select -Last 1
    if ($LastAgentUpdateLog) {

        Write-Host "-  Getting Errors from latest agent update log:"
        Write-Host "  $LastAgentUpdateLog"
        $logs = $null
        $logs = $Logs_EDRupdate | get-content | Select-String "(ERR|error|failed|could not)"
        $logs = Convertto-ShortenedEDRLogs $logs
        Write-FormattedObject $logs

        WRite-Host "-  Getting Last 30 Lines from latest agent update Log:"
        $logs = $LastAgentUpdateLog | get-content -Tail 30
        $logs = Convertto-ShortenedEDRLogs $logs
        Write-FormattedObject $logs
            
    } else {
        Write-Host "! NOTE: No agent update logs were found in $($Config.'log-dir')\"
    }
    write-host `r


    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Gather Snippet of Latest AV Logs"
    Write-Host "`n=============================================`n"


    # Get Latest AV Logs
    Write-Host "-  Getting List of Available EDR Log Files: "
    $log_files = Get-ChildItem "$AV_DATA_PATH\logs\" -Include *.log -ea 0 | Sort-Object LastWriteTimeUtc | select LastWriteTimeUtc, FullName, Length
    if ($log_files) {
        # Print available log EDR Log files
        Write-FormattedObject ($log_files | sort-object LastWriteTimeUtc)

        $TodaysLogs = $log_files | where { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }
        if (-NOT $TodaysLogs) {
            Write-Host "!  NOTE: No EDR Log file was written to in the last 24 hours. May not have been active."
        }
    } else {
        Write-Host "! WARNING: No logs were found in $($Config.'log-dir')\"
    }
    write-host `r


    # Last Datto EDR AV Interface Logs
    $LastAgentLog = Get-ChildItem "$($Config.'log-dir')\datto-av-*" -ea 0 | Sort-Object LastWriteTimeUtc | select -Last 1
    if ($LastAgentLog) {

        Write-Host "-  Getting Errors from latest agent log:"
        Write-Host "  $LastAgentLog"
        $version = $null
        $logs = $LastAgentLog | get-content | Select-String "(ERR|error|failed|could not)"
        $logs = Convertto-ShortenedEDRLogs $logs
        Write-FormattedObject $logs

        WRite-Host "-  Getting Last 30 Lines from latest Agent Log:"
        $logs = $LastAgentLog | get-content -Tail 30 
        $logs = Convertto-ShortenedEDRLogs $logs
        Write-FormattedObject $logs
        
    } else {
        Write-Host "! NOTE: No agent logs were found in $($Config.'log-dir')\"
    }
    write-host `r

    # AV EndpointProtectionService Log Errors
    Write-Host "- Getting AV EndpointProtectionService Log Errors"
    $EndpointProtectionServiceLogs = Get-ChildItem "$AV_DATA_PATH\logs\EndpointProtectionService*" -ea 0
    if ($EndpointProtectionServiceLogs) {
        $EndpointProtectionServiceLogs | foreach {
            Write-Host "- Getting Error Logs from $($_.FullPath)"
            $logs = Get-Content $_ | select-string "(\[(WARN|ERRO?R?)\])" 
            Write-FormattedObject $logs
        }
    } else {
        Write-Host "! NOTE: No endpointprotectionservice logs were found in $AV_DATA_PATH\logs\"
    }
    Write-Host `r


    <# There are really not useful

    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Gather Snippet of Latest Ransomware Detection Logs"
    Write-Host "`n=============================================`n"

    $LogFiles = Get-ChildItem "$DattoEDRInstallDirectory\rwd" -Include *.log -Recurse
    Write-FormattedObject $LogFiles

    "$DattoEDRInstallDirectory\rwd\install.log"
    #>

    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Gather Snippet of Latest Ransomware Rollback Logs"
    Write-Host "`n=============================================`n"

    $RBDataPath = "C:\programData\Datto\Datto Rollback Driver"
    $LogFiles = Get-ChildItem "$RBDataPath\Logs" -Include *.log -Recurse -ea 0
    if ($LogFiles) {
        Write-FormattedObject $LogFiles
    } else {
        Write-Host "  NO RESULTS"
    }


    # Errors and stuff
    Write-Host "- Getting Interesting logs from wrapper.log:"
    $logs = Get-Content "$RBDataPath\Logs\wrapper.log" -tail 250 -ea 0 | select-string "(ERROR|Starting new RWD|exclude|watch|RWD wrapper version)"
    if ($logs) {
        Write-FormattedObject $logs
    } else {
        Write-Host "! NOTE: Could not find Ransomware Rollback Log $RBDataPath\Logs\wrapper.log"
    }
    Write-Host `r

}


#region Actions


if ($FixKnownIssues) {
    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Fix Rogue EDR Installer Problem"
    Write-Host "`n=============================================`n"

    $RMMInstallerName = "RMM.AdvancedThreatDetection"
    $EDRInstallerProcesses = Get-Process -Name $RMMInstallerName -ea 0
    if ($EDRInstallerProcesses) {
        Write-Host "  Found Rogue rmm.advancedthreatdetection processes. There should be no rmm.AdvancedThreatDetection.exe processes following an install by RMM."
        Write-Host "  RMM downloads and executes this process but it will end and be renamed agent.exe following successful Install."
        Write-FormattedObject $EDRInstallerProcesses

        Write-Host "- Killing processes and deleting the old installer."

        if (Get-Process -Name $AV_PROCESS_NAME -ea 0) {
            Write-Host "  Datto AV is protecting these processes, forcing Datto AV Uninstall first"

            try {
                Stop-Service $EDR_SERVICE_NAME -ea 1
        
            } catch {
                $err = $_.Exception.Message
                switch -Regex ($err) {
                    "Cannot find any service" { 
                        write-host "! WARNING: Datto EDR Service is not installed. Cannot restart service."
                       
                    }
                    "Cannot stop" {
                        write-host "! WARNING: Datto EDR Service could not be stopped. This error is not related to tamper protection."
                    }
                    default { 
                        Write-FormattedObject $err
                    }
                }
            }

            # Uninstall Datto AV
            $out = & "$DattoEDRInstallDirectory\dattoav\Endpoint Protection SDK\endpointprotection.exe" uninstallSdk
            Write-FormattedObject $out
            start-sleep -seconds 2
        }

        try {
                
            Stop-Process -Id $RMMInstallerName -Force -ea Continue
            write-host "- Killed 'RMM.AdvancedThreatDetection' processes."
        } catch {
            $err = $_
            switch -Regex ($err) {
                "Cannot find a process" { 
                    Write-Host "  Could not find process named RMM.AdvancedThreatDetection" 
                }
                default { 
                    Write-Host "! ERROR: Unable to kill RMM.AdvancedThreatProtection.exe." 
                    Write-BetterErrorTrace $err
                }
            }
        }

        # Delete files
        try {
            $InstallerPath = $EDRInstallerProcesses[0].Path
            Write-Host "- Deleting rmm.advancedthreatdetection.exe files: $p"
            Remove-Item -Path $InstallerPath -Force -ea 1
        } catch {
            $err = $_
            switch -Regex ($err) {
                "Cannot find a process" { 
                    Write-Host "  Could not find process named RMM.AdvancedThreatDetection" 
                }
                default { 
                    Write-Host "! ERROR: Unable to kill RMM.AdvancedThreatProtection.exe." 
                    Write-BetterErrorTrace $err
                }
            }
        }    
        
    } else {
        Write-Host "  Did not find any active processes named $RMMInstallerName"
    }

    
    # delete files
    $InstallerFiles = Get-ChildItem "$env:ProgramData\CentraStage*\AEMAgent\RMM.AdvancedThreatDetection\RMM.AdvancedThreatDetection.exe" -ea 0 
    if ($InstallerFiles) {
        Write-FormattedObject $InstallerFiles
        Write-Host "  Deleting any other EDR installers in Centrastage folders"
        $InstallerFiles | Remove-item -Recurse -Force
    } else {
        Write-Host "  Did not find any EDR installer files $env:ProgramData\CentraStage*\AEMAgent\RMM.AdvancedThreatDetection\RMM.AdvancedThreatDetection.exe"
    }

    # Restart Service
    Start-Service -Name $EDR_SERVICE_NAME -ea Continue
}


if ($RestartService) {

    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Restart Datto EDR"
    Write-Host "`n=============================================`n"

    [Boolean]$result = Restart-EDR
    if ($result) {
        exit 0
    } else {
        exit 1
    }
}

if ($StopService) {

    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Stop Datto EDR"
    Write-Host "`n=============================================`n"

    [Boolean]$result = Stop-EDR
    if ($result) {
        exit 0
    } else {
        exit 1
    }
}


if ($UninstallEDR) {


    Write-Host "`n"
    Write-Host "`n=============================================`n"
    Write-Host "- Uninstall Datto EDR"
    Write-Host "`n=============================================`n"

    [Boolean]$result = Uninstall-EDR -UninstallToken $UninstallToken
    if ($result) {
        exit 0
    } else {
        exit 1
    }
}



#================