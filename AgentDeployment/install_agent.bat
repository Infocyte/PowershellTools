@echo off
:: Install Infocyte Agent
:: For use in a GPO Startup Script (Note: Logon script will not work as it operates with the user's non-admin permissions)
:: Best Reference for steps: https://www.petri.com/run-startup-script-batch-file-with-administrative-privileges
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-objectNet.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") ^| iex; installagent myhuntinstance myregkey }
:: Change "myhuntinstance" to your cname
:: Change "myregkey" to your registration key made in the Infocyte HUNT admin panel (or leave blank if not using)
