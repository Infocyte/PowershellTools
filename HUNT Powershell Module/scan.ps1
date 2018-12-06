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

function New-ICScanSchedule ($TargetGroupId, $CronExpression) {
	$tgname = Get-ICTargetGroups | where { $_.targetId -eq $TargetGroupId }
	$Endpoint = "scheduledJobs"
	Write-Verbose "Creating new schedule for TargetGroup: $TargetGroupId with Cron Express: $CronExpression"
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
		name = 'scan-scheduled'
		relatedId = $TargetGroupId
		schedule = $CronExpression
		data = @{
			targetId = $TargetGroupId
		}
  }
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Get-ICScanSchedule {
  $Endpoint = "ScheduledJobs"
  $filter =  @{
    order = @("relatedId")
    limit = $resultlimit
    skip = 0
  }
  $ScheduledJobs = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
	$TargetGroups = Get-ICTargetGroups
	$ScheduledJobs | % {
		if ($_.relatedId) {
			 $tgid = $_.relatedId
			 $tg = $TargetGroups | where { $_.id -eq $tgid }
			 if ($tg) {
				 $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value $tg.name
			 } else {
				 $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value $Null
			 }
		}
	}
	$ScheduledJobs | where { $_.targetGroup -ne $Null }
}

function Remove-ICScanSchedule ($TargetGroupId, $ScheduleId) {
	$Schedules = Get-ICScanSchedule
	if ($ScheduleId) {
		$schedule = $Schedules | where { $_.id -eq $ScheduleId}
	}
	elseif ($TargetGroupId) {
		$schedule = $Schedules | where { $_.relatedId -eq $TargetGroupId}
		$ScheduleId	= $schedule.id
	} else {
		throw "Incorrect input!"
	}
	$tgname = $schedule.targetGroup
	if (-NOT $tgname) { throw "TargetGroupId not found!"}
	$Endpoint = "scheduledJobs/$ScheduleId"
	Write-Verbose "Unscheduling collection for Target Group $tgname"
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method DELETE
}

function _Get-ICTimeStampUTC {
  return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Import-ICSurvey {
  # example script to upload a survey file to HUNT (2.10+)
  # Script to upload manual .bz2 file to hunt server.
	[cmdletbinding(DefaultParameterSetName = 'Path')]
	param(
		[parameter(
				Mandatory,
				ParameterSetName  = 'Path',
				Position = 0,
				ValueFromPipeline,
				ValueFromPipelineByPropertyName
		)]
		[ValidateNotNullOrEmpty()]
		[SupportsWildcards()]
		[string[]]$Path, # <paths of the survey results (.bz2) files to upload>

		[parameter(
				Mandatory,
				ParameterSetName = 'LiteralPath',
				Position = 0,
				ValueFromPipelineByPropertyName
		)]
		[ValidateNotNullOrEmpty()]
		[Alias('PSPath')]
		[string[]]$LiteralPath,

		[String]
		$ScanId,

		[String]
		$TargetGroupId,

  	[String]
  	$TargetGroupName = "OfflineScans"
  )

  BEGIN {
  	# INITIALIZE
  	$survey = "HostSurvey.json.gz"
  	$surveyext = "*.json.gz"

  	function Upload-ICSurveys ([String]$FilePath, [String]$ScanId){
  		Write-Verbose "Uploading Surveys"
			$headers = @{
		    Authorization = $Global:ICToken
				scanid = $ScanId
		  }
  		try {
  			$objects = Invoke-RestMethod $HuntServerAddress/api/survey -Headers $headers -Method POST -InFile $FilePath -ContentType "application/octet-stream"
  		} catch {
  			Write-Warning "Error: $_"
  			throw "ERROR: $($_.Exception.Message)"
  		}
  		$objects
  	}

		if ($ScanId) {
			# Check for existing ScanId and use it
			$scans = Get-ICScans -NoLimit
			if ($scans.id -contains $ScanId) {
				$TargetGroupName = ($Scans | where { $_.scanId -eq $ScanId}).targetList
			} else {
				Throw "No scan exists with ScanId $ScanId. Specify an existing ScanId to add this survey result to or use other parameters to generate one."
			}
		}
		elseif ($TargetGroupId) {
			# Check TargetGroupId and create new ScanId for that group
			Write-Host "Checking for existance of target group with TargetGroupId: '$TargetGroupId' and generating new ScanId"
			$TargetGroups = Get-ICTargetGroups
			if ($TargetGroups.id -contains $TargetGroupId) {
				$TargetGroupName = ($TargetGroups | where { $_.id -eq $TargetGroupId }).name
			} else {
				Throw "No Target Group exists with TargetGroupId $TargetGroupId. Specify an existing TargetGroupId to add this survey to or use other parameters to generate one."
			}
		}
		else {
			Write-Host "No ScanId or TargetGroupId specified. Checking for existance of target group: '$TargetGroupName'"
	  	$TargetGroups = Get-ICTargetGroups
	  	if ($TargetGroups.name -contains $TargetGroupName) {
	  		Write-Host "$TargetGroupName Exists."
				$TargetGroupId = ($targetGroups | where { $_.name -eq $TargetGroupName}).id
	  	} else {
	  			Write-Host "$TargetGroupName does not exist. Creating new Target Group '$TargetGroupName'"
	  			New-ICTargetGroup -Name $TargetGroupName
					Start-Sleep 1
					$TargetGroupId = ($targetGroups | where { $_.name -eq $TargetGroupName}).id
	  	}
		}

		# Creating ScanId
		if (-NOT $ScanId) {
			$ScanName = "Offline-" + (get-date).toString("yyyyMMdd-HHmm")
			Write-Host "Creating scan named $ScanName [$TargetGroupName-$ScanName]..."
			$StartTime = _Get-ICTimeStampUTC
			$body = @{
				name = $scanName;
				targetId = $TargetGroupId;
				startedOn = $StartTime
			}
			$newscan = _ICRestMethod -url $HuntServerAddress/api/scans -body $body -Method 'POST'
			Start-Sleep 1
			$ScanId = $newscan.id
		}


		Write-Host "Importing Survey Results into $TargetGroupName-$ScanName [ScanId: $ScanId] [TargetGroupId: $TargetGroupId]"
  }

  PROCESS {
		# Resolve path(s)
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $resolvedPaths = Resolve-Path -Path $Path | Select-Object -ExpandProperty Path
        } elseif ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $resolvedPaths = Resolve-Path -LiteralPath $LiteralPath | Select-Object -ExpandProperty Path
        }

				# Process each item in resolved paths
				foreach ($file in $resolvedPaths) {
		 			Write-Host "Uploading survey [$file]..."
		 			if ((Test-Path $file -type Leaf) -AND ($file -like $surveyext)) {
		 				Upload-ICSurveys -FilePath $file -ScanId $ScanId
		   		} else {
		   			Write-Warning "$file does not exist or is not a $surveyext file"
		   		}
		   	}
	}

  END {
  	# TODO: detect when scan is no longer processing submissions, then mark as completed
  	#Write-Host "Closing scan..."
  	#Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$HuntServerAddress/api/scans/$scanId/complete" -Method Post
  }

}
