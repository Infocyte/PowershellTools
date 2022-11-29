$attackDir = "$env:TEMP\AttackSim"

Write-Host "Cleaning up persistence from the Attack Script..."
Stop-Process -Name AttackSim* -ea 0

Write-Host "Removing Run Key Persistence"
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /f >nul 2>&1

Write-Host "Removing RunOnce Key Persistence"
Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "NextRun" -Force -ErrorAction Ignore

Write-Host "Removing Startup Link Persistence"
Remove-Item "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil_calc.lnk" -ErrorAction Ignore

Write-Host "Removing Scheduled Task Persistence"
schtasks /delete /tn "T1053_005_OnLogon" /f >nul 2>&1
schtasks /delete /tn "T1053_005_OnStartup" /f >nul 2>&1

Write-Host "Restarting Defender..."
sc config WinDefend start= Auto
sc start WinDefend
Set-MpPreference -DisableRealtimeMonitoring $false

Remove-Item -Path $attackDir -Recurse -force -ea 0