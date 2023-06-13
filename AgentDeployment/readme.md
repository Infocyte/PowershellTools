## Infocyte Agent Scripted Installer (One Line Powershell)
**Platform:** Microsoft Windows 7+ or Server 2008+\
**Powershell Version:** 2.0+\
**.NET Version:** 4.8+

The following command is all you need.  Run it on any windows system and it will download this script and execute it.  This is useful for scripted software distribution, sccm, or GPO deployments in leu of an MSI.  The script will manage an automated installation process for the HUNT agent.  *IMPORTANT: You DO NOT need to download this script. Leave it here unless you want to host it yourself.*

To execute this script on a windows host, run this command replacing `<instancename>` and `[regkey]` with your hunt instance \<mandatory\> and registration key [optional]. Do not include the brackets.


> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent <instancename> [regkey]`


#### The positional arguments after the command *installagent* are:  
* **(1st Argument) \<Mandatory\>:** `-InstanceName instancename`
* **(2nd Argument) [Optional]:** `-RegKey regkey`

Instance Name (*instancename*) is your cname from the URL, not the FULL url https://instancename.infocyte.com).

Registration Key (*regkey*) is created in the Agent Admin panel. This will automatically approve the agent registration and add it to its' default Target Group. Without it, the agent will initially report as "pending" in the web console and cannot be used until approved.

Note: *InstanceName* (1) and *RegKey* (2) are positional arguments so they don't require argument headers if in position 1 and 2 after `installagent`.

### Example 1 (instancename only - Installing to demo1.infocyte.com):  
> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072);
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex;
installagent demo1`

### Example 2 (For use in batch or GPO - Installing to alpo1.infocyte.com):
If running from outside Powershell (like in a batch or GPO install script):
> `powershell.exe -ExecutionPolicy bypass -noprofile -nologo -command { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent alpo1 }`

---

## Additional (Optional) Parameters:
* *-Interactive*
* *-Force*
* *-FriendlyName "String"*
* *-Proxy "user:password@192.168.1.1:8080"*


##### Interactive Mode
Silent run is default so if you want to troubleshoot or check out what is happening, check the log file or run the command in interactive mode:  Add *-Interactive* to the end of the command.

In either mode, the output/log can be read here:
> `Get-Content "C:\Windows\Temp\infocyteagentinstaller.log"`

##### Proxy Configuration:
* Authenticated: *-Proxy "\<user\>:\<password\>@\<ProxyAddress\>:\<ProxyPort\>"*
* Unauthenticated: *-Proxy "\<ProxyAddress\>:\<ProxyPort\>"*

##### Force Reinstall:
Use *-Force* to force a reinstall (by default it bails)

##### Friendly Name:
Use *-FriendlyName* to add a descriptive name for the system (otherwise it uses hostname). This can be added or changed in the web console as well after install.


### Example 3 (using named arguments):  
> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072);
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex;
installagent -InstanceName "demo1" -RegKey "asdfasdf" -FriendlyName "DBServer1" -Proxy "user:password@192.168.1.1:8080" -Interactive`


## Uninstall One-Liner
This script also includes an uninstallagent command:

> `[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; uninstallagent`
