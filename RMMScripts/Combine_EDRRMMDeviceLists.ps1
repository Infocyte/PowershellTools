Write-Host -ForegroundColor Cyan Use this procedure to get a list of devices that are online in RMM but offline in EDR
Write-Host -ForegroundColor Cyan Step 1: Export CSV from RMM Device List
Write-Host -ForegroundColor Cyan Step 2: Export CSV from EDR Device List
Write-Host -ForegroundColor Cyan step 3: Specify the paths below to those downloaded CSVs
Write-Host -ForegroundColor Cyan Step 4: Run Comamand: Combine-RMMEDRDeviceLists
Write-Host -ForegroundColor Cyan @'
Example:
. .\Combine_EDRRMMDeviceLists.ps1
Combine-RMMEDRDeviceLists -RMMDeviceListCSV "~\Downloads\Devices.csv" -EDRDeviceListCSV "~\Downloads\DeviceDetail.csv" -exportPath "~\Downloads\devices_combined.csv"
'@

# CODE -------
function Combine-RMMEDRDeviceLists {
	Param(
		[String]$RMMDeviceListCSV = "~\Downloads\Devices.csv", # Default
		[String]$EDRDeviceListCSV = "~\Downloads\DeviceDetail (1).csv", # Default
		[String]$exportPath = "~\Downloads\devices_combined.csv" # Default
	)

	$RMMDeviceList = Import-CSV $RMMDeviceListCSV | Where { $_.status -eq "Online" }
	$EDRDeviceList = Import-CSV $EDRDeviceListCSV | where { $_.status -ne "Active" }
	
	$NewList = @()
	$RMMDeviceList | foreach {
		$name = $_.hostname
		$EDREntry = $EDRDeviceList | where { $_.hostname -eq $name }
		if ($EDREntry) {
			$newobj = [PSCustomObject]@{
				agentId 			= $EDREntry.id
				deviceId			= $EDREntry.deviceId
				organizationName 	= $EDREntry.organizationName
				locationName 		= $EDREntry.locationName
				hostname			= $_.hostname
				type				= $_.type
				os					= $_.os
				RMMStatus 			= $_.status
				EDRStatus 			= $EDREntry.status
				authorized 			= $EDREntry.authorized
				isolated 			= $EDREntry.Isolated
				lastHeartbeat 		= ([DateTime]"$($EDREntry.heartbeat.TrimEnd("GMT+0000 (Coordinated Universal Time)")) GMT")
				dattoAvEnabled 		= $EDREntry.dattoAvEnabled
				hasEdrLicense 		= $EDREntry.hasEdrLicense
				hasAvLicense 		= $EDREntry.hasAvLicense
				version 			= $EDREntry.version
				markedForUninstall 	= $EDREntry.markedForUninstall
				markedForUpdate 	= $EDREntry.markedForUpdate
				
			}
			$NewList += $newobj
		}
	}
	Write-Host `n
	$NewList | ft hostname, EDRStatus, lastHeartBeat, authorized, isolated, hasEdrLicense, markedForUninstall
	
	Write-Host "Devices Online in RMM: $($RMMDeviceList.count)"
	Write-Host "Devices Online in RMM but inactive in EDR: $($NewList.count)"
	
	$NewList | Export-CSV $exportPath
	Write-Host "Exported results to $exportPath"
	& $exportPath
}


