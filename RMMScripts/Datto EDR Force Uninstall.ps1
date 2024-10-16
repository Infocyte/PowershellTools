#Requires -Version 5
<# Datto EDR Force Remove
    Updated: 11 October 2024
    Written by: Chris Gerritz

   This script, like all datto RMM Component scripts unless otherwise explicitly stated, is the copyrighted property of Datto, Inc.;
   it may not be shared, sold, or distributed beyond the Datto RMM product, whole or in part, even with modifications applied, for 
   any reason. this includes on reddit, on discord, or as part of other RMM tools. PCSM and VSAX stand as exceptions to this rule.
   	
   the moment you edit this script it becomes your own risk and support will not provide assistance with it.#>

#region ---Functions--------------------------------------------------------------------------------------------------------------------------

Function Get-ServiceWithMessage ($Name) {
    
    $service = Get-CimInstance -Query "select * from win32_service where name='$Name'" #| Select-Object DisplayName, Name, Description, StartType, Status, ProcessId, PathName
    if ($service) {
        # Get InstallDirectory and Path
        $imagePath = [regex]::Match($service.PathName, "(['`"](?<p>[^'`"]+)['`"]|(?<p>[^\s]+))").Groups["p"].Value
        if (Test-Path $imagePath) {
            $InstallDirectory = $imagePath | split-path
            $ImageName  = $imagePath | split-Path -Leaf
        } else {
            $message += "ERROR: Could not parse ImagePath: [$($service.PathName)] -> [$imagePath]"
        }
    } else {
        $message += "ERROR: Service does not exist or you do not have permission to see it." 
    }
    
    return [PSCustomObject]@{
        Name             = $Name
        DisplayName      = $service.DisplayName
        Description      = $service.Description
        Status           = $service.Status
        ProcessId        = if ($service.ProcessId -AND $service.ProcessId -ne 0) { $service.ProcessId } else { $null }
        StartMode        = $service.StartMode
        ImageName        = $ImageName
        ImagePath        = $imagePath
        InstallDirectory = $InstallDirectory
        Message          = $message
    }
}

Function Get-DattoEDRInstallDirectory {
    # Sets $Global:DattoEDRInstallDirectory to point to the active install directory for Datto EDR.
    $ServiceName = "HUNTAgent"
    $Path =  Get-CimInstance -Query "select PathName from win32_service where name='$ServiceName'" | Select-Object PathName -ExpandProperty PathName
    if ($Path) {
        $imagePath = [regex]::Match($Path, "(['`"](?<p>[^'`"]+)['`"]|(?<p>[^\s]+))").Groups["p"].Value
        if (Test-Path $imagePath) {
            $InstallDirectory = $imagePath | split-path
        } else {
            Write-Host "  ERROR (Get-DattoEDRVersion): Could not find agent binary path $imagePath"
            return
        }
    } else {
        Write-Host "  ERROR (Get-DattoEDRVersion): Could not find agent binary path from HUNTAgent service. Looking for an agent.exe"
        gci "$env:ProgramData\CentraStage*" | % {
            if (test-path "$_\AEMAgent\RMM.AdvancedThreatDetection\agent.exe") {
                Write-Host "  Found agent.exe in $_\AEMAgent\RMM.AdvancedThreatDetection\agent.exe"
                $InstallDirectory = gci "$_\AEMAgent\RMM.AdvancedThreatDetection\agent.exe" | Sort-Object LastWriteTime | Select -Last 1 | select Path -ExpandProperty Path
                break
            }
        }
        if (!$InstallDirectory) {
            write-host "- Unable to find valid install location. One will be created."
            try {
                $InstallDirectory="$((gp "HKLM:\SOFTWARE\CentraStage" -Name "AgentFolderLocation" -ea stop).AgentFolderLocation)\AEMAgent\RMM.AdvancedThreatDetection"
            } catch {
                write-host "- Unable to infer EDR installation location from Registry. Attempting alternative logic."
                try {
                    $InstallDirectory="$((get-process aemagent -ea Stop | select *).path | split-path)\RMM.AdvancedThreatDetection"
                } catch {
                    write-host "- Unable to infer EDR installation location from AEMAgent location. Using default location."
                    $InstallDirectory="$env:ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection"
                }
            }
        }
    }
    $Global:DattoEDRInstallDirectory = $InstallDirectory
    return $InstallDirectory
}

Function Get-DattoEDRVersion {
    # Call agent.exe --version to get the version

    if (-NOT $DattoEDRInstallDirectory) {
        $DattoEDRInstallDirectory = Get-DattoEDRInstallDirectory 
    }
    if (Test-Path $DattoEDRInstallDirectory\agent.exe) {
        try {
            $versionOutput = & $DattoEDRInstallDirectory\agent.exe --version  2>&1
            <#
                RTS Agent 3.12.0
                Build Number: 2205
                Build Date:   2024-09-27 18:12:07
                Build Commit: 1da5221b7565c0b89c92e7642d03436d2454eaa3
            #>
            if (-NOT $versionOutput -OR $versionOutput -match "error") {
                Write-Host "  ERROR (Get-DattoEDRVersion): Error calling 'agent.exe --version'. $Config"
                return
            }
         
            #tokenise output data
            $varVersion1=((($versionOutput | select-string 'RTS Agent') -as [string]) -split " " | select -last 1)
            $varVersion2=((($versionOutput | select-string 'Number') -as [string]) -split " " | select -last 1)
            [version]$AgentVersion="$varVersion1.$varVersion2"      
            #Write-Host "  Version: $($Version.ToString())"
            Write-Host ($versionOutput | Out-String)
        } catch {
            $err = $_.Exception.Message
            switch -Regex ($err) {
                default { 
                    Write-Host "  ERROR (Get-DattoEDRVersion): $err" 
                }
            }
        }
    } else {
        Write-Host "!  ERROR: $DattoEDRInstallDirectory\agent.exe does not exist"
    }

    # Check version stored in Uninstall Key to find any mismatches
    [version]$UninstallVersion=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent" -Name DisplayVersion -ea 0).DisplayVersion
    if (!$UninstallVersion) {
        [version]$UninstallVersion=(Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent" -Name DisplayVersion -ea 0).DisplayVersion
    }
    if (!$UninstallVersion) {
        write-host "! NOTICE: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent could not be found"
        write-host "  Datto EDR may not be installed correctly. This is not a catastrophic error but you will not be able to use add/remove programs to remove Datto EDR."
    }     
    if ($AgentVersion -ne $UninstallVersion) {
        write-host "! NOTICE: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent version ($UninstallVersion) does not match actual agent version ($AgentVersion)"
        write-host "  Datto EDR may not be updating correctly."
    }
    
    return [version]$AgentVersion
}

Function Get-DattoEDRMasterUninstallKey {
    # Call agent.exe --version to get the version

    if (-NOT $DattoEDRInstallDirectory) {
        Set-DattoEDRInstallDirectory 
    }

    try {
        $versionOutput = & $DattoEDRInstallDirectory\agent.exe --version  2>&1
          if (-NOT $versionOutput -OR $versionOutput -match "error") {
            Write-Host "  ERROR (Get-DattoEDRVersion): Error calling 'agent.exe --version'. $Config"
            return
        }

        $str = ""
        $versionOutput | foreach { 
            $str += [regex]::Match($_, "(RTS Agent|Build Number:|Build Date:|Build Commit:)\s+(?<m>.*)").Groups["m"].Value 
        }
        
        $stringAsStream = [System.IO.MemoryStream]::new()
        $writer = [System.IO.StreamWriter]::new($stringAsStream)
        $writer.write($str)
        $writer.Flush()
        $stringAsStream.Position = 0

        $hash = Get-FileHash -Algorithm "SHA1" -InputStream $stringAsStream | Select-Object -ExpandProperty Hash
        return $hash.ToLower()
    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            default { 
                Write-Host "  ERROR: Could not generate uninstall key. $err" 
            }
        }
    }    
}

Function isDattoEDRInstalled {
 
    # Find Service
    $ServiceName = "HUNTAgent"
    $Service =  Get-Service -Name $ServiceName -ea 0
    if (-NOT $Service) {
        write-host "! Datto EDR Service is not installed"
        return $false
    }

    # Check for installation issues:
    if ($Service.StartType -ne 2) {
        write-host "! WARNING: Datto EDR Service is installed but not set to start automatically!"
        write-host "  StartType of $($ServiceName): $($Service.StartType)"
        write-host "  This is usually caused by tampering with the service and may need to be reinstalled."
    }

    # Check Uninstall Key
    [version]$UninstallVersion=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent" -Name DisplayVersion -ea 0).DisplayVersion
    if (!$UninstallVersion) {
        [version]$UninstallVersion=(Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent" -Name DisplayVersion -ea 0).DisplayVersion
    }
    if (!$UninstallVersion) {
        write-host "! WARNING: 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Datto EDR Agent' could not be found"
        write-host "  Datto EDR may not be installed correctly."
    }

    if ($Service) {
        return $true
    } else {
        return $false
    }
}

Function Restart-DattoEDR {
    $ServiceName = "HUNTAgent"
    $Service =  Get-Service -Name $ServiceName -ea 0
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
        Stop-Service $ServiceName -ea Stop
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
                write-Host "  Attempting to start service anyway..."
            }
        }
    }
    
    try {
        Start-Service $ServiceName -ea Stop
        Write-Host "  Datto EDR Service Restarted!"
    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            default { 
                Write-Host "  ERROR: Could not start service: $err" 
            }
        }
    }

    # Check startup type is automatic
    if ($Service.StartType -ne 2) {
        write-host "! WARNING: Datto EDR Service is not set to start automatically!  Attempting to fix"
        write-host "  StartType of $($ServiceName): '$($Service.StartType)'"

        try {
            Set-Service -Name $ServiceName -StartupType Automatic -ea Stop
        } catch {
            $err = $_.Exception.Message
            switch -Regex ($err) {
                "Access is denied" {
                    write-host "! ERROR: Datto EDR Service could not be set to automatic StartupType due to tamper protection."
                    write-host "  $err"
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

Function Get-EDRConfig {
    if (-NOT $DattoEDRInstallDirectory) {
        Set-DattoEDRInstallDirectory 
    }

    $configTOMLPath = "$DattoEDRInstallDirectory\config.toml"
    $configRegistry = 'HKLM:\SOFTWARE\Datto\EDR\'

    # Get EDR Registry Keys
    $EDR_Registry = Get-ItemProperty $configRegistry
    if ($EDR_Registry) {   
        $AgentId = $EDR_Registry.AgentId
        $DeviceId = $EDR_Registry.DeviceID
        Write-Verbose "  $($EDR_Registry | Out-String)"
    } else {
        $message += "ERROR (Get-EDRConfig): Could not find HKLM:\SOFTWARE\Datto\EDR\"
    }

    try {
        $Config_raw = get-content $configTOMLPath -ea 1
        if (-NOT $Config_raw -AND $EDR_Registry) {

             # Try grabbing from registry:
             $Config_raw = $EDR_Registry.AgentConfig | ConvertFrom-Base64String
        }
        Write-Verbose ($Config_raw | Out-String)
    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            default { $message += "ERROR (Get-EDRConfig): Couldn't get config from $configTOMLPath. $err" }
        }
    }
    
    $Config = New-Object -Type PSCustomObject
    $Config | Add-Member -MemberType NoteProperty -Name configTOMLPath -Value "$DattoEDRInstallDirectory\config.toml"
    $Config | Add-Member -MemberType NoteProperty -Name configRegistry -Value 'HKLM:\SOFTWARE\Datto\EDR\'
    $Config | Add-Member -MemberType NoteProperty -Name AgentId -Value $AgentId
    $Config | Add-Member -MemberType NoteProperty -Name DeviceId -Value $DeviceId
    if ($Config_raw) {
        $Config_raw.split("`n") | foreach { 
            if ($_) { 
                $var_name = ($_ -split " = ")[0]
                $var_value = ($_ -split " = ")[1].Replace('"', '').Replace("'","")
                $Config | Add-Member -MemberType NoteProperty -Name $var_name -Value $var_value
            }
        }
        $InstanceName = [regex]::Match($Config.'api-url', "https://(?<cname>[^\.]+)\.infocyte\.com").Groups["cname"].Value
        $API_URL = [regex]::Match($Config.'api-url', "(?<url>https://.*\.infocyte\.com)").Groups["url"].Value    
    }

    $Config | Add-Member -MemberType NoteProperty -Name InstanceName -Value $InstanceName
    $Config | Add-Member -MemberType NoteProperty -Name API_URL -Value $API_URL
    $Config | Add-Member -MemberType NoteProperty -Name RegistryConfig -Value $EDR_Registry
    $Config | Add-Member -MemberType NoteProperty -Name Message -Value $message

    return $Config
}


#region ---Code--------------------------------------------------------------------------------------------------------------------------

$EDRServiceName = "HUNTAgent"
$AVServiceName = "EndpointProtectionService"
$AVServiceName2 = "EndpointProtectionService"
$EDRProcessName = "agent"
$AVProcessName = "endpointprotection"

# Determine if Datto EDR is Installed:
$EDRServiceKey = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\HUNTAgent\" -ea 0
$EDRService = Get-ServiceWithMessage "HUNTAgent"
$EDRProcess = get-process -Name agent -EA 0 | Where { $_.description -eq "Datto EDR Agent" } 
$EDRRogueInstallerProcesses = Get-process -Name RMM.AdvancedThreatDetection -ea 0

if (-NOT $EDRServiceKey -AND -NOT $EDRService.ImagePath) {
    Write-Host "!  : Datto EDR service is not installed. Exiting."
    if ($EDRProcess -OR $EDRRogueInstallerProcesses) {
        Write-Host ($EDRProcess | Out-String)
        Write-Host ($EDRRogueInstallerProcesses | Out-String)
        Write-Host "EDR Processes do exist, cleaning things up!"
    }
} else {
    $Installed = $true
    Write-Host ($EDRService | Out-String)
    Write-Host ($EDRServiceKey | Out-String)
    Write-Host ($EDRProcess | Out-String)
    Write-Host ($EDRRogueInstallerProcesses | Out-String)
}

# Store the install directory in $Global:DattoEDRInstallDirectory
$Global:DattoEDRInstallDirectory = Get-DattoEDRInstallDirectory

if ($Installed) {
    # Determine EDR Version
    Write-Host "- Getting EDR Agent version"
    [version]$EDRAgent_CurrVer = Get-DattoEDRVersion
    write-host "Current Datto EDR version: $($EDRAgent_CurrVer.ToString())"
    write-host `r


    # Get EDR Config
    Write-Host "- Getting EDR Config from file and registry"
    $Config = Get-EDRConfig
    Write-Host "  Config file: $DattoEDRInstallDirectory\config.toml"  
    Write-Host ($config | Select-Object -ExcludeProperty RegistryConfig | Out-String)
    Write-Host "  EDR Registry Key: HKLM:\SOFTWARE\Datto\EDR\"
    Write-Host ($config.RegistryConfig | Out-String)
    write-host `r

    if ($Config.'ignore-versioning' -eq "true") {
        Write-Host "!  NOTICE: ignore-versioning is turned on. Datto EDR Agent could not update with this setting in place. Used for testing only."
    }
    
}

# Get KaseyaOne dattoedr.json.  This file is written by EDR and tells other Kaseya modules what features are available and configured in Datto EDR.
Write-Host "  Getting dattoedr.json from KaseyaOne folder"
try {
    $kaseyaone_dattoedrjson =  Get-Content "C:\programData\kaseyaone\dattoedr.json" | convertfrom-json
    Write-Host ($kaseyaone_dattoedrjson | Out-String)
} catch {
    $err = $_.Exception.Message
    switch -Regex ($err) {
        default { Write-Host "  ERROR: $err"; }
    }
}
if ($kaseyaone_dattoedrjson.timestamp -lt (Get-Date).AddDays(-1)) {
    Write-Host "! NOTICE: dattoedr.json has not been updated in over 24 hours. This should be updated every two minutes while DattoEDR is active."
}
write-host `r


if (Get-Process -Name EndpointProtection) {
    Write-Host "- Getting Datto AV Processes"
    Write-Host "  NOTE: Datto AV is active which means Tamper Protection is active, you will not be able to see the Path, CommandLine or ParentProcess Information unless you run this script as a protected process."
    Write-Host ($AVProcesses | Out-String)
    Write-Host "`n"
}


# PROBLEMS ===========

if ($kaseyaone_dattoedrjson.rebootRequired) {
    Write-Host "!  NOTICE: Datto AV Requires a Reboot. Forcing Reinstall anyway. Please let Chris Gerritz at Datto know if you see this and send him the output"
}

if ($kaseyaone_dattoedrjson.isIsolated) {
    Write-Host "!  NOTICE: System is isolated by Datto EDR.  Unisolating and forcing reinstall."
}
if ($kaseyaone_dattoedrjson.dattoAV -eq $false -AND $kaseyaone_dattoedrjson.timestamp -gt (Get-Date).AddDays(-1) -AND ($AVService -OR $AVProcesses)) {
    Write-Host "! NOTICE: DattoAV policy is not applied according to dattoedr.json but Datto AV is installed and/or running..."
}

if ($kaseyaone_dattoedrjson.dattoAV -eq $false -AND $kaseyaone_dattoedrjson.timestamp -gt ((Get-Date).AddDays(-1)) -AND (-NOT $AVService -AND -NOT $AVProcesses)) {
    Write-Host "! NOTICE: DattoAV policy is not applied according to dattoedr.json but Datto AV is installed and/or running..."
}

# Find Rogue RMM Datto EDR Installer Processes (bug from version 3.11.4)
$EDRInstallerProcesses = Get-Process -Name rmm.AdvancedThreatDetection -EA 0
if ($EDRInstallerProcesses) {
    Write-Host ($EDRInstallerProcesses | Out-String)
    Write-Host "! WARNING: There should be no rmm.AdvancedThreatDetection.exe processes following an install by RMM."
    Write-Host "  RMM downloads and executes this process but it will end and be renamed agent.exe following successful Install."
    if ($EDRAgent_CurrVer.Major -eq 3 -AND $EDRAgent_CurrVer.minor -eq 11 -AND $varEDRAgent_CurrVer.build -le 4) {
        Write-Host "!  Warning: Version is 3.11.4 or below, this version has known bugs with duplicate installers. Attempting to forced reinstall."
    }
    Write-Host "`n"
}

#================


# Stop Datto EDR Service
try {
    Stop-Service HUNTAgent -ea 1
} catch {
    $err = $_.Exception.Message
    switch -Regex ($err) {
        default { Write-Host "  ERROR: Could not stop Datto EDR Service (HUNTAgent): $err"; }
    }
}

# Force Uninstall Datto AV
if (Test-Path "$DattoEDRInstallDirectory\agent.exe") {
    $Key = Get-DattoEDRMasterUninstallKey
    & "$DattoEDRInstallDirectory\agent.exe" --uninstall $Key
} else {
    Write-Host "!  Notice: $DattoEDRInstallDirectory\agent.exe does not exist, cannot run uninstaller. Attempting manual cleanup"
}

#kill adt
if (get-process -Name RMM.AdvancedThreatDetection -ea 0) {
    Write-Host "- Found rogue RMM.AdvancedThreatDetection EDR Installer processes. Killing."
    if (Get-Process -Name $AVProcessName -ea 0) {
        Write-Host "  Datto AV is protecting these processes, forcing Datto AV Uninstall first"
        # Uninstall Datto AV
        & "$DattoEDRInstallDirectory\dattoav\Endpoint Protection SDK\endpointprotection.exe" uninstallSdk
        write-host "  $out"
        start-sleep -seconds 2
    }
    try {
        stop-process -Name RMM.AdvancedThreatDetection -Force -ea stop
        write-host "- Killed 'RMM.AdvancedThreatDetection' processes"
        start-sleep -seconds 1
    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            "Cannot find a process" { 
                Write-Host "  Could not find process named RMM.AdvancedThreatDetection" 
            }
            default { 
                Write-Host "  ERROR: $err" 
                write-host "! ERROR: Unable to kill RMM.AdvancedThreatProtection.exe."
                write-host "  Exception details follow."
                $_ | select *
            }
        }
    }
}

# Kill Datto EDR Agents
$Procs = get-process -EA 0 | Where { $_.description -eq "Datto EDR Agent" } 
if ($Procs) {
    try {
        $Procs | Stop-Process -Force
        write-host "- Killed 'agent' processes"
        start-sleep -seconds 1
    } catch {
        $err = $_.Exception.Message
        switch -Regex ($err) {
            default { 
                Write-Host "  ERROR: $err" 
                write-host "! ERROR: Unable to kill Datto EDR agent process."
                write-host "  Exception details follow."
                $_ | select *
            }
        }
    }    
}

# delete files
gci "$env:ProgramData\CentraStage*\AEMAgent\RMM.AdvancedThreatDetection" | Remove-item -Recurse -Force
Remove-item "C:\programData\kaseyaone\dattoedr.json" -Force


Write-host `r
Write-Host "!   SUCCESS: Datto EDR Uninstalled and/or killed."
Write-Host "  RMM Policy will perform a reinstall on its' next policy enforcement check if it is still enabled in RMM."
Write-Host "  You can force this immediately by restarting RMM's 'CAGService' or re-applying the policy to the host in RMM."