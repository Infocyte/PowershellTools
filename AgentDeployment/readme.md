## Datto EDR Agent Scripted Installer (One Line Powershell)
**Platform:** Microsoft Windows 7+ or Server 2008+\
**Powershell Version:** 2.0+\
**.NET Version:** 4.8+

The following command is all you need.  Run it on any windows system and it will download this script and execute it.  This is useful for scripted software distribution, sccm, or GPO deployments in leu of an MSI.  The script will manage an automated installation process for the Datto EDR agent.  *IMPORTANT: You DO NOT need to download this script. Leave it here unless you want to host it yourself.*

To execute this script on a windows host, run this command replacing `<url>` with your EDR instance's url \<mandatory\> and any optional arguments like registration key `[regkey]`.  
IMPORTANT: Do not include the brackets.

```
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; Install-EDR <url> [regkey]
```

#### The positional arguments after the command *Install-EDR* are:  
* **(1st Argument) \<Mandatory\>:** `-url https://alpo1.infocyte.com` (urls formated like `alpo1.infocyte.com` or even just the cname `alpo1` also work here)
* **(2nd Argument) [Optional]:** `-RegKey regkey`

Registration Key (*regkey*) is created in the Agent Admin panel. This will automatically approve the agent registration and add it to its' associated org and location instead of the default one.

Note: *Url* (1) and *RegKey* (2) are positional arguments so they don't require argument headers if in position 1 and 2 after `Install-EDR`.

### Example 1 (instancename only - Installing to demo1.infocyte.com with no registration key):  
> `(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; Install-EDR https://demo1.infocyte.com`

### Example 2 (For use in batch or GPO - Installing to demo1.infocyte.com with registration key 'xregkey01'):
If running from outside Powershell (like in a batch or GPO install script):
> `powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; Install-EDR https://demo1.infocyte.com xregkey01 }`

### Example 3 (using named arguments):  
> `(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; Install-EDR -url https://alpo1.infocyte.com -regkey "asdfasdf" -friendlyname "DBServer01" -proxy "user:password@192.168.1.1:8080" -interactive`

---

## Additional (Optional) Parameters:
* *-Interactive*
* *-Force*
* *-FriendlyName "String"*
* *-Proxy "user:password@192.168.1.1:8080"*


##### Interactive Mode
Silent run is default so if you want to troubleshoot or check out what is happening, check the log file or run the command in interactive mode:  Add *-Interactive* to the end of the command.

In either mode, the output/log can be read here:
> `Get-Content "$env:Temp\agentinstallscript.log"`

##### Proxy Configuration:
* Authenticated: *-Proxy "\<user\>:\<password\>@\<ProxyAddress\>:\<ProxyPort\>"*
* Unauthenticated: *-Proxy "\<ProxyAddress\>:\<ProxyPort\>"*

##### Force Reinstall:
Use *-Force* to force a reinstall (by default it bails)

##### Friendly Name:
Use *-FriendlyName* to add a descriptive name for the system (otherwise it uses hostname). This can be added or changed in the web console as well after install.



## Uninstall One-Liner
This script also includes an uninstallagent command:

```
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; Uninstall-EDR
```
