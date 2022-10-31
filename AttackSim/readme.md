## Datto EDR Behavioral Attack Simulator
**Platform:** Microsoft Windows 7+ or Server 2008+\
**Powershell Version:** 3.0+\
**.NET Version:** 4.5+

The following command is all you need.  Run it on any windows system and it will download this script and execute it.  


> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1")`


### Example 2 (For use in batch or from cmd.exe):
If running from outside Powershell (like in cmd.exe or a batch script):
> `powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1") }`
