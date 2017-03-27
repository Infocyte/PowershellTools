
## FUNCTIONS

#Get Login Token
function New-ICToken ([PSCredential]$Credential, [String]$HuntServer = "https://localhost:4443" ) {
	
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

function Get-ICScans {
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
	try {
		$TargetLists = Invoke-RestMethod "$HuntServerAddress/api/Targets" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/Targets") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$TargetLists += $moreobjects
		} else {
			$more = $false
		}
	}
	
	$skip = 0
	$headers.remove('filter') | Out-Null
	$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')	
	try {
		$Scans = Invoke-RestMethod ("$HuntServerAddress/api/Scans") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/Targets") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$Scans += $moreobjects
		} else {
			$more = $false
		}
	}
	
	$Scans | % {
		$targetId = $_.targetId
		$targetList = $TargetLists | where { $_.id -eq $targetId }
		$_ | Add-Member -Type NoteProperty -Name 'targetListName' -Value $targetList.name
	}
	$Scans
}

# Get Full FileReport on an object by sha1
function Get-ICFileReport ($sha1){
	
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

# Get Full FileReports on all Suspicious and Malicious objects by scanId
function Get-ICFileReports ($scanId) {
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$scan = Invoke-RestMethod ("$HuntServerAddress/api/scans/$scanId") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/ScanReportFiles") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
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

# Get objects by scanId
function Get-ICProcessInstances ($scanId){
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/scanProcessInstances") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/scanProcessInstances") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	
	# Add Host Info
	$Hosts = Get-ICHosts $scanId
	$objects | % {
		$hostId = $_.hostId
		$hostinfo = $Hosts | where { $_.hostId -eq $hostId }
		$_ | Add-Member -Type NoteProperty -Name 'ip' -Value $hostinfo.ip
	}
	
	$objects
}

function Get-ICModuleInstances ($scanId){
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/scanModuleInstances") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/scanModuleInstances") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}

	# Add Host Info
	$Hosts = Get-ICHosts $scanId
	$objects | % {
		$hostId = $_.hostId
		$hostinfo = $Hosts | where { $_.hostId -eq $hostId }
		$_ | Add-Member -Type NoteProperty -Name 'ip' -Value $hostinfo.ip
	}
	$objects
}

function Get-ICDriverInstances ($scanId){
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/scanDriverInstances") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/scanDriverInstances") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	
	# Add Host Info
	$Hosts = Get-ICHosts $scanId
	$objects | % {
		$hostId = $_.hostId
		$hostinfo = $Hosts | where { $_.hostId -eq $hostId }
		$_ | Add-Member -Type NoteProperty -Name 'ip' -Value $hostinfo.ip
	}
	
	$objects
}

function Get-ICAutostartInstances ($scanId){
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/scanAutostartInstances") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/scanAutostartInstances") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	
	# Add Host Info
	$Hosts = Get-ICHosts $scanId
	$objects | % {
		$hostId = $_.hostId
		$hostinfo = $Hosts | where { $_.hostId -eq $hostId }
		$_ | Add-Member -Type NoteProperty -Name 'ip' -Value $hostinfo.ip
	}
	
	$objects
}

function Get-ICMemscanInstances ($scanId){
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/scanMemscanInstances" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/scanMemscanInstances") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	
	if ($objects) {
		# Add Host Info
		$Hosts = Get-ICHosts $scanId
		$objects | % {
			$hostId = $_.hostId
			$hostinfo = $Hosts | where { $_.hostId -eq $hostId }
			$_ | Add-Member -Type NoteProperty -Name 'ip' -Value $hostinfo.ip
		}
	}

	$objects
}

function Get-ICConnectionInstances ([String]$scanId, [Switch]$All) {
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"and":[{"scanId":"'+$scanId+'"},{"or":[{"state":"SYN-SENT"},{"state":"ESTABLISHED"}]}]},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = (Invoke-RestMethod ("$HuntServerAddress/api/scanConnectionInstances") -Headers $headers -Method GET -ContentType 'application/json') | where { $_.localaddr -ne $_.remoteaddr }
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"and":[{"scanId":"'+$scanId+'"},{"or":[{"state":"SYN-SENT"},{"state":"ESTABLISHED"}]}]},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/scanConnectionInstances") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"	
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	
	# Add Host Info
	$Hosts = Get-ICHosts $scanId
	$objects | % {
		$hostId = $_.hostId
		$hostinfo = $Hosts | where { $_.hostId -eq $hostId }
		$_ | Add-Member -Type NoteProperty -Name 'hostname' -Value $hostinfo.hostname
		$_ | Add-Member -Type NoteProperty -Name 'ip' -Value $hostinfo.ip
	}

	$objects
}

function Get-ICAccountInstances ($scanId) {
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/ScanAccountInstances" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"	
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
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
	
	$Hosts = Get-ICHosts $scanId
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

function Get-ICHosts ($scanId) {
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/ScanHosts") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/ScanHosts") -Headers $headers -Method GET -ContentType 'application/json'
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

function Get-ICAddresses ($TargetId) {
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$skip = 0
	$headers.Add("filter", '{"where":{"and":[{"targetId":"'+$targetId+'"}]},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/Addresses") -Headers $headers -Method GET -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"and":[{"targetId":"'+$targetId+'"}]},"limit":1000,"skip":'+$skip+'}')
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


function Get-ICTargetList {
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

function New-ICTargetList ([String]$Name) {
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
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$user = $Cred.Username | ConvertTo-JSON
	$pass = $Cred.GetNetworkCredential().Password
	$body = '{"type":"custom","username":'+$user+',"password":"'+$pass+'","value":"'+$query+'","targetId":"'+$TargetListId+'"}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/queries") -Headers $headers -Body $body -Method POST -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects
}

function Remove-ICAddresses ($TargetListId) {
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$data = 'where=%7B%22and%22:%5B%7B%22targetId%22:%22'+$TargetListId+'%22%7D%5D%7D'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/Addresses?$data") -Headers $headers -Method DELETE -ContentType 'application/json'		
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}	
	$objects
}

function Invoke-ICEnumeration ($TargetListId, $QueryId) {
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

function Get-ICActiveTasks {
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
