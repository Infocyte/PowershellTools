@echo off
:: Run manual scan and upload results to hunt instance from the surveyed host
:: Can use manually, in a schedule task (SYSTEM level), or GPO Startup Script (Note: Logon script will not work as it operates with the user's non-admin permissions)
:: Best Reference for steps: https://www.petri.com/run-startup-script-batch-file-with-administrative-privileges
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-objectNet.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/manualscan/survey.ps1") | iex; survey -instancename <myhuntinstance> -apikey <apikey> }
:: Change "myhuntinstance" to your cname
:: Change "myapikey" to your registration key made in the Infocyte HUNT admin panel (or leave blank if not using)

:: You can also download the script and run it manually or in a scheduled task
::
::C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command { get-content "C:\<path to survey>\survey.ps1" | iex; survey -instancename <myhuntinstance> -apikey <apikey> }
