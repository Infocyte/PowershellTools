## Infocyte HUNT Agent One-Line Powershell Installer  
**Platform:** Windows  
**Powershell Version:** 3.0+
**.NET Version:** 4.5+

The following command is all you need. Run it on any windows system and it will download this script and execute it. This is useful for scripted software distribution, sccm, or GPO deployments in leue of an MSI. The script will manage the installation process for the HUNT agent.

IMPORTANT: You DO NOT need to download this script. Leave it here unless you want to host it yourself.

To execute this script as a one liner on a windows host with powershell 2.0+, run this command replacing `instancename` and `regkey` with your hunt instance <mandatory> and registration key [optional]. NOTE: Instancename is the cname from the URL, not the FULL url https://instancename.infocyte.com). This script will append the url for you during install.

```[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent instancename regkey```

The arguments are after the command *installagent*:  
**1st Arg [Manadatory]:** `instancename`  
**2nd Arg [Optional]:** `regkey`

Example:  
```[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent myhuntinstance asdfasdf```

If you want to troubleshoot or check out what is happening, run in interactive mode or check the log file:
Add `-Interactive` to the end of the command.

Log can be read here:
Get-Content "$($env:TEMP)\huntagentinstall.log"

---

