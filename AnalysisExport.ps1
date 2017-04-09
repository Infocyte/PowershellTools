<#

#>
Param(
	[Parameter()]
	[Int]$Days = 0, # Age of new data to pull from HUNT (in days)
	
	[Parameter()]
	[String]$HuntServer = "https://localhost:4443",
	
	[Parameter()]
	[String]$OutPath = "C:\Program Files\Infocyte\SplunkData\", # Output Path of SplunkData json files
	
	[Parameter()]
	[Switch]$Replace,
	
	[Parameter()]
	[PSCredential]$HuntCredential
)

# $Script:HuntServer = 'https://demo.infocyte.com'

if (-NOT $HuntCredential.username) {
	#Use Default Infocyte Credentials
	$username = 'infocyte'
	$password = 'pulse' | ConvertTo-SecureString -asPlainText -Force
	$Script:HuntCredential = New-Object System.Management.Automation.PSCredential($username,$password)
}

if (-NOT (Test-Path $OutPath)) {
	New-Item $OutPath -ItemType "directory"
}

# MAIN
New-ICToken $Credential $HuntServer

# splunkscan
$AllScans = Get-ICScans

# Create Time Box
if ($Days -ne 0 -AND $AllScans) {
	$CurrentDT = Get-Date
	$FirstDT = $CurrentDT.AddDays(-$Days)
	$Scans = $AllScans | where { $_.scancompletedon } | where { [datetime]$_.scancompletedon -gt $FirstDT -AND $_.hostCount -gt 0 }
} else {
	$Scans = $AllScans
}

if (-NOT $Scans) {
	Write-Warning "No Scans were found for the given date range"
	exit
}

# splunkscans
$itemtype = "Scans"
if (Test-Path $OutPath\$itemtype.json) {
	if ($Replace) {
		Remove-Item $OutPath\$itemtype.json
		Write-Host "Requesting data from $($Scans.count) Scans."
	} else {
		#Check latest, only append new scanids
		$old = gc $OutPath\$itemtype.json | convertfrom-JSON
		$scanIds = $old.scanid
		Write-Host "$($Scans.count) Scans found. $($scanIds.count) scans have already been exported"
		$Scans = $Scans | where { $scanIds -notcontains $_.scanid }
		Write-Host "Requesting $($Scans.count) new Scans."
		
	}
}
$Scans | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$itemtype.json -Append }


if ((Test-Path $OutPath\$scanname.json) -AND $Replace) {
	Remove-Item $OutPath\$scanname.json
}
$Scans | % {
	$scanname = "$($_.targetlist)-$($_.scanname)"
	
	# splunkprocesses
	$itemtype = "Processes"
	Write-Host "[] Exporting $itemtype from $scanname"
	$time = Measure-Command { $obj = Get-ICProcesses $_.id }
	Write-Host "Received $($obj.count) $itemtype from Hunt server in $($time.TotalSeconds) seconds"
	$obj | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$scanname.json -Append }

	# splunkmodules
	$itemtype = "Modules"
	Write-Host "[] Exporting $itemtype from $scanname"
	$time = Measure-Command { $obj = Get-ICModules $_.id }
	Write-Host "Received $($obj.count) $itemtype from Hunt server in $($time.TotalSeconds) seconds"	
	$obj | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$scanname.json -Append }

	
	# splunkdrivers
	$itemtype = "Drivers"
	Write-Host "[] Exporting $itemtype from $scanname"
	$time = Measure-Command { $obj = Get-ICDrivers $_.id }
	Write-Host "Received $($obj.count) $itemtype from Hunt server in $($time.TotalSeconds) seconds"
	$obj | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$scanname.json -Append }

	# splunkautostarts
	$itemtype = "Autostarts"
	Write-Host "[] Exporting $itemtype from $scanname"
	$time = Measure-Command { $obj = Get-ICAutostarts $_.id }
	Write-Host "Received $($obj.count) $itemtype from Hunt server in $($time.TotalSeconds) seconds"
	$obj | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$scanname.json -Append }

	# splunkmemscans
	$itemtype = "Memscans"
	Write-Host "[] Exporting $itemtype from $scanname"
	$time = Measure-Command { $obj = Get-ICMemscans $_.id }
	Write-Host "Received $($obj.count) $itemtype from Hunt server in $($time.TotalSeconds) seconds"
	$obj | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$scanname.json -Append }

	# splunkconnections
	$itemtype = "Connections"
	Write-Host "[] Exporting $itemtype from $scanname"
	$time = Measure-Command { $obj = Get-ICConnections $_.id }
	Write-Host "Received $($obj.count) $itemtype from Hunt server in $($time.TotalSeconds) seconds"
	$obj | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$scanname.json -Append }

	# splunkhosts
	$itemtype = "Hosts"
	Write-Host "[] Exporting $itemtype from $scanname"
	$time = Measure-Command { $obj = Get-ICHosts $_.id }
	Write-Host "Received $($obj.count) $itemtype from Hunt server in $($time.TotalSeconds) seconds"
	$obj | % { $_ | ConvertTo-Json -compress | Out-File $OutPath\$scanname.json -Append }
}


