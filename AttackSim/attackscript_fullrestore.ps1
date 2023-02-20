$attackDir = "$env:TEMP\AttackSim"

Write-Host "Cleaning up persistence from the Attack Script..."
Stop-Process -Name AttackSim* -Force -ea 0

Write-Host "Removing Run Key Persistence - Calc.exe"
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /f >nul 2>&1

Write-Host "Removing Run Key Persistence - EICAR"
Remove-Item "$AttackDir\EICAR.exe" -force -ea 0


Write-Host "Removing RunOnce Key Persistence"
Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "NextRun" -Force -ea 0

Write-Host "Removing Startup Link Persistence - EICAR"
Remove-Item "$attackDir\EICAR.exe" -Force -ea 0
Remove-Item "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil_calc.lnk" -ea 0
Remove-Item "$home\Desktop\evil_calc.lnk" -ea 0

Write-Host "Removing Scheduled Task Persistence"
schtasks /delete /tn "T1053_005_OnLogon" /f >nul 2>&1
schtasks /delete /tn "T1053_005_OnStartup" /f >nul 2>&1

Write-Host "Restarting Defender..."
sc config WinDefend start= Auto
sc start WinDefend
Set-MpPreference -DisableRealtimeMonitoring $false

Remove-Item -Path $attackDir -Recurse -force -ea 0