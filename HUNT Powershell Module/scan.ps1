# Scan APIs

# Needs more testing, may not work.
function Invoke-ICEnumeration ($TargetGroupId, $QueryId) {
	Write-Warning "This function has not passed QA checks so may not work perfectly (or at all)"
	$Endpoint = "targets/$TargetGroupId/Enumerate"
	Write-Verbose "Starting Enumeration of $TargetGroupId with Query $QueryId"
	$data = @{
    queries = $QueryId
  }
  $body = @{
    data = $data
  }
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

# Needs more testing, may not work.
function Invoke-ICScan ($TargetGroupId) {
	Write-Warning "This function has not passed QA checks so may not work perfectly (or at all)"
	$Endpoint = "targets/$TargetGroupId/scan"
	Write-Verbose "Starting Scan of TargetGroup $TargetGroupId"
	$options = @{
  	EnableProcess = $true
		EnableModule = $true
		EnableDriver = $true
		EnableMemory = $true
		EnableAccount = $true
		EnableAutostart = $true
		EnableHook = $true
		EnableNetwork = $true
		EnableLog = $true
		EnableDelete = $true
  }
  $body = @{
    data = @{ options = $options }
  }
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

<#
function Import-ICSurvey {
  # example script to upload a survey file to HUNT (2.10+)
  # Script to upload manual .bz2 file to hunt server.
  Param(
  	[Parameter(Mandatory = $false,
  			ValueFromPipeline=$true)]
  	[String[]]
  	$Path, # <folder containing the survey results (.bz2) files to upload>

  	[String]
  	$TargetGroup = "OfflineScans"
  )

  BEGIN{
  	# INITIALIZE
  	$survey = "HostSurvey.json.bz2"
  	$surveyext = "*.json.bz2"
  	$api = "$HuntServer/api"

  	function Send-ICSurveys ([String]$File, [String]$ScanId){
  		Write-Verbose "Uploading Surveys"

  		$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  		$headers.Add("Authorization", $Global:ICToken)
  		$headers.Add("scanid", $ScanId)
  		try {
  			$objects = Invoke-RestMethod ("$HuntServerAddress/api/survey") -Headers $headers -Method POST -InFile $File -ContentType "application/octet-stream"
  		} catch {
  			Write-Warning "Error: $_"
  			return "ERROR: $($_.Exception.Message)"
  		}
  		$objects
  	}

  	# MAIN
  	Write-Host "Acquiring token..."
  	$Token = New-ICToken $Credential $HuntServer

  	Write-Host "Checking for '$TargetGroup' target group..."
  	$TargetGroups = Get-ICTargetGroup
  	if ($TargetGroups.name -contains $TargetGroup) {
  		Write-Host "$TargetGroup Exists"
  		$TargetGroupObj = $targetGroups | where { $_.name -eq $TargetGroup}
  	} else {
  			Write-Host "$TargetGroup does not exist. Creating new Target Group '$TargetGroup'"
  			New-ICTargetGroup $TargetGroup
  	}

  	if($ScanName -eq $null) {
  		$ScanName = (get-date).toString("yyyy-MM-dd HH:mm")
  	}

  	if ($ScanId -eq $null) {
  		Write-Host "Creating scan..."
  		$ScanId = New-ICScanId $ScanName $TargetId
  	}

  }

  PROCESS{

  	if ($Search -eq "Path") {
  		foreach ($file in $Path) {
  				if (Test-Path $file -type Leaf -AND $file -like "*.json.bz2") {
  					Write-Host "Uploading survey [$file]..."
  					Upload-ICSurveys $_ $ScanId
  				} else {
  					Write-Verbose "$file does not exist or is not a .json.bz2 file"
  				}
  		}
  	}
  	elseif ($Search -eq "Directory") {
  		Write-Host "Recursing through Directory $Directory "
  		Get-ChildItem $Directory -recurse -filter $surveyext | foreach {
  			Write-Host "Uploading $($_.FullName)"
  			Send-ICSurveys $($_.FullName) $ScanId
  		}
  	}

  }

  END{
  	# TODO: detect when scan is no longer processing submissions, then mark as completed
  	Write-Host $(Get-ICActiveTasks)
  	#Write-Host "Closing scan..."
  	#Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/scans/$scanId/complete" -Method Post
  }

}
#>
