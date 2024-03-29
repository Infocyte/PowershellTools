@echo off
:: Install Infocyte Agent
:: For use in a GPO Startup Script (Note: Logon script will not work as it operates with the user's non-admin permissions)
:: Best Reference for steps: https://www.petri.com/run-startup-script-batch-file-with-administrative-privileges

:: Change "instancename" to your cname
:: Change "regkey" to your registration key made in the Infocyte HUNT admin panel (or leave blank if not using)

set instancename=demo1 
set regkey= 

:: if download folder needs to be changed, uncomment the following and modify the path:
set downloadpath= 
::set downloadpath=-DownloadPath 'C:\windows\temp\agent.windows.exe'

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command "& { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1') | iex; installagent %instancename% %regkey% %downloadpath% }"

:: for testing, you can add a -interactive to the installagent command. The end of the above command would look like this:
:: ...installagent %instancename% %regkey% -interactive }"

