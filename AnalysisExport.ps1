<#

#>
Param(
	[Parameter()]
	[Int]$Days = 7, # Age of new data to pull from HUNT (in days)
	
	[Parameter()]
	[String]$HuntServer = "https://localhost:4443"
	
	[Parameter()]
	[String]$OutPath = "C:\Program Files\Infocyte\SplunkData\" # Output Path of SplunkData json files
	
	[Parameter()]
	[ValidateNotNull()]
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
$LastScan = $Scans[-1]

# Create Time Box
$CurrentDT = Get-Date
$FirstDT = $CurrentDT.AddDays(-$Days)
$Scans = $AllScans | where { $_.completedOn } | where { [datetime]$_.completedOn -gt $FirstDT -AND $_.hostCount -gt 0 }


# splunkprocesses
Write-Host "[] Exporting Processes"
$Scans | % {
	$n = 0
	Write-Progress -Activity "[1/7] Exporting Processes" -status "Requesting Process Instances from Hunt Server"
	$scan = $_
	$time = Measure-Command { $obj = Get-ICProcessInstances $_.id }
	$nt = $obj.count
	Write-Host "[$n] Received ProcessInstances from Hunt server in $($time.TotalSeconds)"
	Write-Progress -Activity "[1/7] Exporting Processes" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
	$time = @()
	$obj | % {
		$n += 1
		if ($n%10 -eq 0) {
			Write-Progress -Activity "[1/7] Exporting Processes" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
		}
		$time += (Measure-Command { $filerep = Get-ICFileReport $_.fileRepId }).TotalSeconds
		$_ | Add-Member -Type NoteProperty -Name 'type' -Value "Process" 
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $scan.targetListName
		$_ | Add-Member -Type NoteProperty -Name 'avpositives' -Value $filerep.avpositives
		$_ | Add-Member -Type NoteProperty -Name 'avtotal' -Value $filerep.avtotal
		$_ | Add-Member -Type NoteProperty -Name 'synapse' -Value $filerep.synapse
		$_ | Add-Member -Type NoteProperty -Name 'md5' -Value $filerep.md5
		$_ | Add-Member -Type NoteProperty -Name 'sha1' -Value $filerep.sha1
		$_ | Add-Member -Type NoteProperty -Name 'sha256' -Value $filerep.sha256
		$_ | Add-Member -Type NoteProperty -Name 'ssdeep' -Value $filerep.ssdeep
	}
	$Processes += $obj
	Write-Host "[$n] Received FileReps for $nt objects in average time of $($a = 0; $time | % { $a += $_ }; $a/$nt) seconds each"
}
$obj = $null
$exportparams = @(
  "scancompletedon",
  "hostname",
  "ip",
  "targetlist",
  "scanId",
  "type",
  "name",
  "path",
  "md5",
  "sha1",
  "sha256",
  "ssdeep",
  "pid",
  "ppid",
  "commandLine",
  "hostCount",
  "failed",
  "managed",
  "signed",
  "threatName",
  "threatScore",
  "synapse",
  "avpostives",
  "avtotal",
  "flagName"
)
$Processes | Select $exportparams | ConvertTo-JSON | Out-File Processes.json


# splunkmodules
Write-Host "[] Exporting Modules"
$Scans | % {
	$n = 0
	Write-Progress -Activity "[1/7] Exporting Modules" -status "Requesting Instances from Hunt Server"
	$scan = $_
	$time = Measure-Command { $obj = Get-ICModuleInstances $_.id }
	$nt = $obj.count
	Write-Host "[$n] Received ModuleInstances from Hunt server in $($time.TotalSeconds)"
	Write-Progress -Activity "[1/7] Exporting Modules" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
	$obj | % {
		$n += 1
		if ($n%10 -eq 0) {
			Write-Progress -Activity "[1/7] Exporting Modules" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
		}
		$filerep = Get-ICFileReport $_.fileRepId
		$_ | Add-Member -Type NoteProperty -Name 'type' -Value "Module" 
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $scan.targetListName
		$_ | Add-Member -Type NoteProperty -Name 'avpositives' -Value $filerep.avpositives
		$_ | Add-Member -Type NoteProperty -Name 'avtotal' -Value $filerep.avtotal
		$_ | Add-Member -Type NoteProperty -Name 'synapse' -Value $filerep.synapse
		$_ | Add-Member -Type NoteProperty -Name 'md5' -Value $filerep.md5
		$_ | Add-Member -Type NoteProperty -Name 'sha1' -Value $filerep.sha1
		$_ | Add-Member -Type NoteProperty -Name 'sha256' -Value $filerep.sha256
		$_ | Add-Member -Type NoteProperty -Name 'ssdeep' -Value $filerep.ssdeep
	}
	$Modules += $obj
}
$obj = $null
$exportparams = @(
  "scancompletedon",
  "hostname",
  "ip",
  "targetlist",
  "scanId",
  "type",
  "name",
  "path",
  "md5",
  "sha1",
  "sha256",
  "ssdeep",
  "hostCount",
  "failed",
  "managed",
  "signed",
  "threatName",
  "threatScore",
  "synapse",
  "avpostives",
  "avtotal",
  "flagName"
)
$Modules | ConvertTo-JSON | Out-File Modules.json

# splunkdrivers
Write-Host "[] Exporting Drivers"
$Scans | % {
	$n = 0
	Write-Progress -Activity "[1/7] Exporting Drivers" -status "Requesting Instances from Hunt Server"
	$scan = $_
	$time = Measure-Command { $obj = Get-ICDriverInstances $_.id }
	$nt = $obj.count
	Write-Host "[$n] Received DriverInstances from Hunt server in $($time.TotalSeconds)"
	Write-Progress -Activity "[1/7] Exporting Drivers" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
	$obj | % {
		$n += 1
		if ($n%10 -eq 0) {
			Write-Progress -Activity "[1/7] Exporting Drivers" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
		}
		$filerep = Get-ICFileReport $_.fileRepId
		$_ | Add-Member -Type NoteProperty -Name 'type' -Value "Driver" 
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $scan.targetListName
		$_ | Add-Member -Type NoteProperty -Name 'avpositives' -Value $filerep.avpositives
		$_ | Add-Member -Type NoteProperty -Name 'avtotal' -Value $filerep.avtotal
		$_ | Add-Member -Type NoteProperty -Name 'synapse' -Value $filerep.synapse
		$_ | Add-Member -Type NoteProperty -Name 'md5' -Value $filerep.md5
		$_ | Add-Member -Type NoteProperty -Name 'sha1' -Value $filerep.sha1
		$_ | Add-Member -Type NoteProperty -Name 'sha256' -Value $filerep.sha256
		$_ | Add-Member -Type NoteProperty -Name 'ssdeep' -Value $filerep.ssdeep
	}
	$Driver += $obj
}
$obj = $null
$exportparams = @(
  "scancompletedon",
  "hostname",
  "ip",
  "targetlist",
  "scanId",
  "type",
  "name",
  "path",
  "md5",
  "sha1",
  "sha256",
  "ssdeep",
  "hostCount",
  "failed",
  "managed",
  "signed",
  "threatName",
  "threatScore",
  "synapse",
  "avpostives",
  "avtotal",
  "flagName"
)
$Driver | Select $exportparams | ConvertTo-JSON | Out-File Modules.json

	
# splunkautostarts
Write-Host "[] Exporting Autostarts"
$Scans | % {
	$n = 0
	Write-Progress -Activity "[1/7] Exporting Autostarts" -status "Requesting Instances from Hunt Server"
	$scan = $_
	$time = Measure-Command { $obj = Get-ICAutostartInstances $_.id }
	$nt = $obj.count
	Write-Host "[$n] Received AutostartInstances from Hunt server in $($time.TotalSeconds)"
	Write-Progress -Activity "[1/7] Exporting Autostarts" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
	$obj | % {
		$n += 1
		if ($n%10 -eq 0) {
			Write-Progress -Activity "[1/7] Exporting Autostarts" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
		}
		$filerep = Get-ICFileReport $_.fileRepId
		$_ | Add-Member -Type NoteProperty -Name 'type' -Value "Autostart" 
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $scan.targetListName
		$_ | Add-Member -Type NoteProperty -Name 'avpositives' -Value $filerep.avpositives
		$_ | Add-Member -Type NoteProperty -Name 'avtotal' -Value $filerep.avtotal
		$_ | Add-Member -Type NoteProperty -Name 'synapse' -Value $filerep.synapse
		$_ | Add-Member -Type NoteProperty -Name 'md5' -Value $filerep.md5
		$_ | Add-Member -Type NoteProperty -Name 'sha1' -Value $filerep.sha1
		$_ | Add-Member -Type NoteProperty -Name 'sha256' -Value $filerep.sha256
		$_ | Add-Member -Type NoteProperty -Name 'ssdeep' -Value $filerep.ssdeep
	}
	$Autostarts += $obj
}
$obj = $null
$exportparams = @(
  "scancompletedon",
  "hostname",
  "ip",
  "targetlist",
  "scanId",
  "type",
  "autostarttype",
  "regpath",
  "value",
  "name",
  "path",
  "md5",
  "sha1",
  "sha256",
  "ssdeep",
  "hostCount",
  "failed",
  "managed",
  "signed",
  "threatName",
  "threatScore",
  "synapse",
  "avpostives",
  "avtotal",
  "flagName"
)
$Autostarts | Select $exportparams | ConvertTo-JSON | Out-File Autostarts.json

# splunkmemscans
Write-Host "[] Exporting MemoryObjects"
$Scans | % {
	$n = 0
	Write-Progress -Activity "[1/7] Exporting MemoryObjects" -status "Requesting Instances from Hunt Server"
	$scan = $_
	$time = Measure-Command { $obj = Get-ICMemscanInstances $_.id }
	$nt = $obj.count
	Write-Host "[$n] Received MemoryInstances from Hunt server in $($time.TotalSeconds)"
	Write-Progress -Activity "[1/7] Exporting MemoryObjects" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
	$obj | % {
		$n += 1
		if ($n%1 -eq 0) {
			Write-Progress -Activity "[1/7] Exporting MemoryObjects" -status "Getting FileReps on $nt objects" -percentComplete ($n * 100 / $nt)
		}

		$_ | Add-Member -Type NoteProperty -Name 'processname' -Value $_.name
		$_ | Add-Member -Type NoteProperty -Name 'processpath' -Value $_.path

		$filerep = Get-ICFileReport $_.fileRepId
		$_ | Add-Member -Type NoteProperty -Name 'type' -Value "MemoryObject" 
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $scan.targetListName
		$_ | Add-Member -Type NoteProperty -Name 'avpositives' -Value $filerep.avpositives
		$_ | Add-Member -Type NoteProperty -Name 'avtotal' -Value $filerep.avtotal
		$_ | Add-Member -Type NoteProperty -Name 'synapse' -Value $filerep.synapse
		$_ | Add-Member -Type NoteProperty -Name 'ssdeep' -Value $filerep.ssdeep
	}
	$Memscans += $obj
}
$obj = $null
$exportparams = @(
  "scancompletedon",
  "hostname",
  "ip",
  "targetlist",
  "scanId",
  "type",
  "memscanid",
  "filerepid",
  "processname",
  "processpath",
  "address",
  "size",
  "protection",
  "threatName",
  "threatScore",
  "synapse",
  "avpostives",
  "avtotal",
  "flagName"
)
$Memscans | Select $exportparams | ConvertTo-JSON | Out-File Memscans.json

# splunkconnections
Write-Host "[] Exporting Connections"
$Scans | % {
	$n = 0
	Write-Progress -Activity "[1/7] Exporting Connections" -status "Requesting Instances from Hunt Server"
	$scan = $_
	$time = Measure-Command { $obj = Get-ICConnectionInstances $_.id }
	$nt = $obj.count
	Write-Host "[$n] Received ConnectionInstances from Hunt server in $($time.TotalSeconds)"
	$obj | % {
		$_ | Add-Member -Type NoteProperty -Name 'type' -Value "Connection" 
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $scan.targetListName
	}
	$Connections += $obj
}
$obj = $null
$exportparams = @(
  "scancompletedon",
  "hostname",
  "ip",
  "targetListName",
  "scanId",
  "type",
  "pid",
  "processPath",
  "localAddr",
  "localPort",
  "remoteAddr",
  "remotePort",
  "proto",
  "state",
  "threatscore"
)
$Connections | Select $exportparams | ConvertTo-JSON | Out-File Connections.json


# splunkhosts
Write-Host "[] Exporting Hosts"
$Scans | % {
	$n = 0
	Write-Progress -Activity "[1/7] Exporting Hosts" -status "Requesting Instances from Hunt Server"
	$scan = $_
	$time = Measure-Command { $obj = Get-ICHosts $_.id }
	$nt = $obj.count
	Write-Host "[$n] Received Hosts from Hunt server in $($time.TotalSeconds)"
	$obj | % {
		$_ | Add-Member -Type NoteProperty -Name 'type' -Value "Host" 
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $scan.targetListName
	}
	$Hosts += $obj
}
$obj = $null
$exportparams = @(
  "scancompletedon",
  "hostname",
  "ip",
  "targetListName",
  "scanId",
  "type",
  "domain",
  "osVersion",
  "architecture",
  "failed",
  "compromised"
)
$Hosts | Select $exportparams | ConvertTo-JSON | Out-File Hosts.json