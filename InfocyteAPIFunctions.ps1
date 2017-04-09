
## FUNCTIONS

#Get Login Token (required)
function New-ICToken ([PSCredential]$Credential, [String]$HuntServer = "https://localhost:4443" ) {
	Write-Verbose "Requesting new Token from $HuntServer using account $($Credential.username)"
	Write-Verbose "Credentials and Hunt Server Address are stored in global variables for use in all IC cmdlets"
	if (-NOT ([System.Net.ServicePointManager]::ServerCertificateValidationCallback)) { 
		#Accept Unsigned CERTS
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	}
	if (-NOT $Credential) {
		# Default Credentials
		$username = 'infocyte'
		$password = 'pulse' | ConvertTo-SecureString -asPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential($username,$password)
	}
	
	$Global:HuntServerAddress = $HuntServer
	
	$data = @{
		username = $Credential.GetNetworkCredential().username
		password = $Credential.GetNetworkCredential().password
	}
	$i = $data | ConvertTo-JSON
	try {
		$response = Invoke-RestMethod "$HuntServerAddress/api/users/login" -Method POST -Body $i -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($response -match "Error") {
		Write-Warning "Error: Unauthorized"
		return "ERROR: $($_.Exception.Message)"
	} else {
		# Set Token to global variable
		$Global:ICToken = $response.id
		Write-Verbose 'New token saved to global variable: $Global:ICToken'
		$response
	}
}


# Get Scan Metadata
function Get-ICTargetList {
	Write-Verbose "Requesting TargetLists from $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"order":["name","id"]}')
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets") -Headers $headers -Method GET -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects
}

function Get-ICScans {
	$skip = 0
	Write-Verbose "Exporting Scans from $HuntServerAddress"
	Write-Progress -Activity "Exporting Scans from Hunt Server" -status "Requesting Scans from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/SplunkScans" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Scans from Hunt Server" -status "Requesting Scans from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkScans") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
			# $objects += $moreobjects
		} else {
			$more = $false
		}
	}
}


# Get Full FileReports on all Suspicious and Malicious objects by scanid
function Get-ICFileReports ($scanid) {
	$skip = 0
	Write-Verbose "Exporting FileReports from $HuntServerAddress"
	Write-Progress -Activity "Exporting FileReports from Hunt Server" -status "Requesting FileReports from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$scan = Invoke-RestMethod ("$HuntServerAddress/api/scans/$scanid") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	
	$skip = 0
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/ScanReportFiles") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {}
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting FileReports from Hunt Server" -status "Requesting FileReports from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/ScanReportFiles") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	
	$objects | % {
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'targetlist' -Value $scan.targetlist
			
		# Add Signature
		$signatureId = $_.signatureId
		try {
			$sig = Invoke-RestMethod ("$HuntServerAddress/api/Signatures/$signatureId") -Headers $headers -Method GET -ContentType 'application/json'
			$_ | Add-Member -Type NoteProperty -Name 'signature' -Value $sig
		} catch {}

		# Add FileRep
		$fileRepId = $_.fileRepId
		try {
			$filerep = Invoke-RestMethod ("$HuntServerAddress/api/FileReps/$fileRepId") -Headers $headers -Method GET -ContentType 'application/json'
			$_ | Add-Member -Type NoteProperty -Name 'fileReps' -Value $filerep
		} catch {}
	}
	$objects
}


# Get objects by scanid
function Get-ICProcesses ($scanid){
	$skip = 0
	Write-Verbose "Exporting Processes from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Process Instances from Hunt Server" -status "Requesting Processes from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkProcesses") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Process Instances from Hunt Server" -status "Requesting Processes from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkProcesses") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}	
	}
}

function Get-ICModules ($scanid){
	$skip = 0
	Write-Verbose "Exporting Modules from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Module Instances from Hunt Server" -status "Requesting Modules from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkModules") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Module Instances from Hunt Server" -status "Requesting Modules from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkModules") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
			#$objects += $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICDrivers ($scanid){
	$skip = 0
	Write-Verbose "Exporting Drivers from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Driver Instances from Hunt Server" -status "Requesting Drivers from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkDrivers") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Driver Instances from Hunt Server" -status "Requesting Drivers from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkDrivers") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			#$objects += $moreobjects
			write-output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICAutostarts ($scanid){
	$skip = 0
	Write-Verbose "Exporting Autostarts from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Autostart Instances from Hunt Server" -status "Requesting Autostarts from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkAutostarts") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Autostart Instances from Hunt Server" -status "Requesting Autostarts from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkAutostarts") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICMemscans ($scanid){
	$skip = 0
	Write-Verbose "Exporting Memscans from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Memscan Instances from Hunt Server" -status "Requesting Memscans from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/SplunkMemscans" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Memscan Instances from Hunt Server" -status "Requesting Memscans from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkMemscans") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			#$objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICConnections ([String]$scanid, [Switch]$All) {
	$skip = 0
	Write-Verbose "Exporting Connections from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Connection Instances from Hunt Server" -status "Requesting Connections from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"and":[{"scanid":"'+$scanid+'"},{"or":[{"state":"SYN-SENT"},{"state":"ESTABLISHED"}]}]},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = (Invoke-RestMethod ("$HuntServerAddress/api/SplunkConnections") -Headers $headers -Method GET -ContentType 'application/json') | where { $_.localaddr -ne $_.remoteaddr }
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Connection Instances from Hunt Server" -status "Requesting Connections from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"and":[{"scanid":"'+$scanid+'"},{"or":[{"state":"SYN-SENT"},{"state":"ESTABLISHED"}]}]},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkConnections") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICAccounts ($scanid) {
	$skip = 0
	Write-Verbose "Exporting Accounts from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Account Instances from Hunt Server" -status "Requesting Accounts from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/SplunkAccounts" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	write-output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Account Instances from Hunt Server" -status "Requesting Accounts from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkAccounts") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
			#$objects += $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICHosts ($scanid) {
	$skip = 0
	Write-Verbose "Exporting Hosts from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Host Instances from Hunt Server" -status "Requesting Hosts from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkHosts") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Host Instances from Hunt Server" -status "Requesting Hosts from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/SplunkHosts") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICAccounts ($scanid) {
	$skip = 0
	Write-Verbose "Exporting Accounts from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Account Instances from Hunt Server" -status "Requesting Accounts from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/ScanAccountInstances" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Account Instances from Hunt Server" -status "Requesting Accounts from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanid":"'+$scanid+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/ScanAccountInstances") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	
	$skip = 0
	$headers.remove('filter') | Out-Null
	$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
	try {
		$Accounts = Invoke-RestMethod ("$HuntServerAddress/api/Accounts") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/Accounts") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$Accounts += $moreobjects
		} else {
			$more = $false
		}
	}
	
	$Hosts = Get-ICHosts $scanid
	$objects | % {
		# Add Host Info
		$hostId = $_.hostId
		$hostinfo = $Hosts | where { $_.hostId -eq $hostId }
		$_ | Add-Member -Type NoteProperty -Name 'hostname' -Value $hostinfo.hostname
		$_ | Add-Member -Type NoteProperty -Name 'ip' -Value $hostinfo.ip
		
		# Add account Info
		$accountId = $_.accountId
		$acctinfo = $Accounts | where { $_.accountId -eq $accountId }
		$_ | Add-Member -Type NoteProperty -Name 'fullname' -Value $acctinfo.fullname		
	}
	
	$objects
}

function Get-ICAddresses ($TargetId) {
	$skip = 0
	Write-Verbose "Exporting Addresses from $scanid [$skip]" 
	Write-Progress -Activity "Exporting Address Instances from Hunt Server" -status "Requesting Addresses from $scanid [$skip]" 
	
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"and":[{"targetid":"'+$targetid+'"}]},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/Addresses") -Headers $headers -Method GET -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Address Instances from Hunt Server" -status "Requesting Addresses from $scanid [$skip]" 
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"and":[{"targetid":"'+$targetid+'"}]},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/Addresses") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}	
	$objects
}


# Get Full FileReport on an object by sha1
function Get-ICFileReport ($sha1){
	Write-Verbose "Requesting FileReport on file with SHA1: $sha1"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/FileReps/$sha1" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	
	$objects | % {
		$_ | Add-Member -Type NoteProperty -Name 'avpositives' -Value $_.avResults.positives
		$_ | Add-Member -Type NoteProperty -Name 'avtotal' -Value $_.avResults.total	
	}
	$objects
}


# Get Job Functions
function Get-ICActiveTasks {
	Write-Verbose "Getting Active Tasks from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)	
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/usertasks/active") -Headers $headers -Method GET -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects | where { $_.status -eq "Active" }
}

function Get-ICLastScanId {
	Write-Verbose "Getting last ScanId from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$Scans = Invoke-RestMethod ("$HuntServerAddress/api/Scans") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($Scans) {
		($Scans | sort-object completedOn -descending)[0].id
	} else {
		return $null
	}	
}

function Get-ICActiveJobs {
	Write-Verbose "Getting Active Jobs from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$Skip = 0
	#$headers.Add("filter", '{"where":{"or":[{"status":"Scanning"},{"status":"Scanning"}]},"order":["timestamp"],"limit":1000,"skip":'+$skip+'}')
	$headers.Add("filter", '{"where":{"or":[]},"order":["timestamp"],"limit":1000,"skip":'+$skip+'}')
	try {
		$Scans = Invoke-RestMethod ("$HuntServerAddress/api/CoreJobs") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($Scans) {
		$Scans | where { $_.status -ne "Complete" }
	} else {
		return $null
	}	
}


# Creation APIs
function New-ICTargetList ([String]$Name) {
	Write-Verbose "Creating new target list: $Name"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$body = '{"name":"'+$Name+'"}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets") -Headers $headers -Body $body -Method POST -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}

function New-ICQuery ([String]$TargetListId, [String]$query, [PSCredential]$Cred) {
	Write-Verbose "Creating new Query in TargetList $TargetListId ($query) using username $($Cred.Username)"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$user = $Cred.Username | ConvertTo-JSON
	$pass = $Cred.GetNetworkCredential().Password
	$body = '{"type":"custom","username":'+$user+',"password":"'+$pass+'","value":"'+$query+'","targetid":"'+$TargetListId+'"}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/queries") -Headers $headers -Body $body -Method POST -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects
}

function Invoke-ICEnumeration ($TargetListId, $QueryId) {
	Write-Verbose "Starting Enumeration of $TargetListId with Query $QueryId"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$body = '{"queries":["'+$QueryId+'"]}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets/$TargetListId/Enumerate") -Headers $headers -Body $body -Method POST -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects
}

function Invoke-ICScan ($TargetListId) {
	Write-Verbose "Starting Scan of targetlist $TargetListId"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)	
	$body = '{"options":{"EnableProcess":true,"EnableModule":true,"EnableDriver":true,"EnableMemory":true,"EnableAccount":true,"EnableAutostart":true,"EnableHook":true,"EnableNetwork":true,"EnableLog":true,"EnableDelete":true}}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets/$TargetListId/scan") -Headers $headers -Body $body -Method POST -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects
}

function Remove-ICAddresses ($TargetListId) {
	Write-Verbose "Removing all addresses from TargetList $TargetListId"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$data = 'where=%7B%22and%22:%5B%7B%22targetid%22:%22'+$TargetListId+'%22%7D%5D%7D'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/Addresses?$data") -Headers $headers -Method DELETE -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects
}

