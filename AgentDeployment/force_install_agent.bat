@echo off
:: Install Infocyte Agent
:: For use in a GPO Startup Script (Note: Logon script will not work as it operates with the user's non-admin permissions)
:: Best Reference for steps: https://www.petri.com/run-startup-script-batch-file-with-administrative-privileges

:: Change "instancename" to your cname
:: Change "regkey" to your registration key made in the Infocyte HUNT admin panel (or leave blank if not using)

set instancename=dobsondemo
set regkey=

:: Uninstall old agent first, if any.

:: Attempt find uninstaller from registry and run it.
%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command "& { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/force_uninstall.ps1') | iex; }"


:: Install agent with provided instance name and regkey (if any).
%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command "& { [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1') | iex; installagent %instancename% %regkey% }"

:: for testing, you can add a -interactive to the installagent command. The end of the above command would look like this:
:: ...installagent %instancename% %regkey% -interactive }"
