## Infocyte HUNT Client-side Initiated Survey  
**Platform:** Windows  
**Powershell Version:** 3.0+
**.NET Version:** 4.5+

The following command or script will initiate a survey of a sytem. Run it on any windows system and it will download the survey, execute it, and upload the results to your HUNT instance for processing. 

IMPORTANT: You DO NOT need to download this script. Yoy can leave it here unless you want to host it yourself.

To execute this script as a one liner on a windows host with powershell 2.0+, run this command replacing `instancecname` and `apikey` with your hunt instance <mandatory> and API key. NOTE: Instance name is your cname from the URL, not the FULL url https://instancecname.infocyte.com). This script will append the rest of the url for you.

```[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/manualscan/survey.ps1") | iex; survey instancecname apikey```

The arguments are after the command *installagent*:  
**1st Arg [Manadatory]:** `instancecname`  
**2nd Arg [Mandatory]:** `apikey`

Example:  
```[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/manualscan/survey.ps1") | iex; survey myhuntinstance asdfasdf```

If you want to troubleshoot or check out what is happening, run in interactive mode or check the log file:
Add `-Interactive` to the end of the command.

Log can be read here:
Get-Content "$($env:TEMP)\s1_deploy.log"

---

