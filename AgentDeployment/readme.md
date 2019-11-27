## Infocyte HUNT Agent One-Line Powershell Installer  
**Platform:** Windows  
**Powershell Version:** 3.0+
**.NET Version:** 4.5+

The following command is all you need. Run it on any windows system and it will download this script and execute it. This is useful for scripted software distribution, sccm, or GPO deployments in leue of an MSI. The script will manage the installation process for the HUNT agent. IMPORTANT: You DO NOT need to download this script. Leave it here unless you want to host it yourself.

To execute this script as a one liner on a windows host with powershell 2.0+, run this command replacing `instancename` and `regkey` with your hunt instance <mandatory> and registration key [optional].

    ```powershell
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent <instancename> [regkey]
    ```

#### The essential arguments are after the command *installagent*:  
**-InstanceName (1st Argument) <Manadatory>:** `instancename`  
**-RegKey (2nd Argument) [Optional]:** `regkey`

Instance name is your cname from the URL, not the FULL url https://instancename.infocyte.com). This script will append the url for you during install.

Registration Key (`regkey`) is created in the Agent Admin panel. This will automatically approve the agent registration and add it to its' default Target Group. Without it, the agent will initially report as "pending" in the web console and cannot be used till approved.

#### Example 1:  
```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex;
installagent demo1
```

### Additional (Optional) Parameters:
* `-Interactive`
* `-Force`
* `-FriendlyName "String"`
* `-Proxy "user:password@192.168.1.1:8080"`

##### Interactive Mode
Silent run is default so if you want to troubleshoot or check out what is happening, check the log file or run the command in interactive mode:

Add `-Interactive` to the end of the command.

Log can be read here:
Get-Content "C:\Windows\Temp\infocyteagentinstaller.log"

##### Proxy Configuration:
Authenticated: "<user>:<password>@<ProxyAddress>:<ProxyPort>"
Unauthenticated: "<ProxyAddress>:<ProxyPort>"

##### Force Reinstall:
Use `-Force` to force a reinstall (by default it bails)

##### Friendly Name:
Use -FriendlyName to add a name for the system. This can be added or changed in the web console as well after install.
`-FriendlyName "John Doe's Laptop"`


#### Example 2:  
```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex;
installagent -InstanceName "demo1" -RegKey "asdfasdf" -FriendlyName "DBServer1" -Proxy "user:password@192.168.1.1:8080" -Interactive
```
Note: InstanceName (1) and RegKey (2) are positional arguments so they don't actually require argument headers if in position 1 and 2.
---
