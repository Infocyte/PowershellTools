# Scan APIs

function New-ICQuery {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$True)]
        [String]$TargetGroupId,

        [parameter(Mandatory=$True)]
        [String]$credentialId,

        [String]$sshCredentialId,

        [parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]$Query,

    	[String]$QueryName
    )

    $Credential = Get-ICCredential -CredentialId $CredentialId
    $TargetGroup = Get-ICTargetGroup -TargetGroupId $TargetGroupId
	Write-Host "Creating new Query ($query) in TargetGroup $TargetGroup.name  using credential $($Credential.name) [$($Credential.username)]"
    $Endpoint = "queries"
    $data = @{
        value = $query
        targetId = $TargetGroupId
    	name = $QueryName
    }
    if ($credentialId) {
        $data['credentialId'] = $CredentialId
    }
    if ($sshCredentialId) {
        $data['sshCredential'] = $sshCredentialId
    }
    $body = @{
        data = $data
    }
    _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Get-ICQuery {
    [cmdletbinding()]
    param(
        [String]$TargetGroupId
    )
    $Endpoint = "queries"
    $filter =  @{
        limit = $resultlimit
        skip = 0
    }
    if ($TargetGroupId) {
        $filter['where'] = @{ targetId = $TargetGroupId }
        Write-Verbose "Getting Queries for Target Group Id: $TargetGroupId"
    }
    #Write-Verbose "Getting all Queries from TargetGroup $TargetGroup"
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
}

function Remove-ICQuery {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$QueryId
    )

    $Endpoint = "queries/$QueryId"
    Write-Warning "Removing query [$HuntServerAddress/api/$Endpoint]."
    _ICRestMethod -url $HuntServerAddress/api/$Endpoint -method 'DELETE'
}

function Invoke-ICFindHosts {
	[cmdletbinding()]
	param(
		[parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String]$TargetGroupId,

		[String]$QueryId
	)
	$TargetGroup = Get-ICTargetGroup -TargetGroupId $TargetGroupId
	$Queries = Get-ICQuery -TargetGroupId $TargetGroupId
	if (-NOT $Queries) {
		Throw "Target Group not found or does not have any Queries associated with it"
	}
	$Endpoint = "targets/$TargetGroupId/Enumerate"
	$body = @{
		queries = @()
	}
	if ($QueryId) {
		Write-Verbose "Starting Enumeration of $($TargetGroup.name) with Query $QueryId"
		$body['queries'] += $QueryId
		_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
	} else {
		$Queries | foreach {
			Write-Verbose "Starting Enumeration of $($TargetGroup.name) with Query $($Queries.id)"
			$body['queries'] += $Queries.Id
		}
		_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
	}
}

function Invoke-ICScan {
	[cmdletbinding()]
	param(
		[parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[Alias("targetId")]
		[String]$TargetGroupId,

		[PSObject]$ScanOptions,

		[Switch]$PerformDiscovery
	)
	$TargetGroup = Get-ICTargetGroup -TargetGroupId $TargetGroupId
	if (-NOT $TargetGroup) {
		Throw "TargetGroup with id $TargetGroupId does not exist!"
	}
	if ($PerformDiscovery) {
		Write-Host "Performing discovery on $($TargetGroup.name)"
		$stillactive = $true
		$UserTask = Invoke-ICFindHosts -TargetGroupId $TargetGroupId
		While ($stillactive) {
			Start-Sleep 10
			$taskstatus = Get-ICUserTask -UserTaskId $UserTask.userTaskId
			if ($taskstatus.status -eq "Active") {
					Write-Host "Waiting on Discovery. Progress: $($taskstatus.progress)%"
			} elseif ($taskstatus.status -eq "Completed") {
					$stillactive = $false
			} else {
				Throw "Something went wrong in enumeration. Last Status: $($taskstatus.status)"
			}
		}

	}
	$Endpoint = "targets/$TargetGroupId/scan"
	Write-Verbose "Starting Scan of TargetGroup $($TargetGroup.name)"
  $body = @{ options = $ScanOptions }
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Invoke-ICScanTarget {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$target,

		[String]$TargetGroupId,
		[String]$TargetGroupName = "OnDemand",

		[String]$CredentialId,
		[String]$CredentialName = "DefaultCredential",

        [String]$sshCredentialId,
		[String]$sshCredentialName,

        [PSObject]$ScanOptions
	)

    $body = @{
        target = $target
    }

	# Select Target targetgroup
	if ($TargetGroupId) {
		$TargetGroup = Get-ICTargetGroup -TargetGroupId $TargetGroupId
		if (-NOT $TargetGroup) {
			Throw "TargetGroup with id $TargetGroupid does not exist!"
		} else {
            $body['targetGroup'] = @{id = $targetGroupId}
        }
	} else {
        Write-Verbose "Using Target Group Name [$TargetGroupName] -- will be created if it does not exist."
        $body['targetGroup'] = @{name = $TargetGroupName}
    }

	# Select Credential
	if ($CredentialId) {
		$Credential = Get-ICCredential -CredentialId $credentialId
		if (-NOT $Credential) {
			Throw "Credential with id $credentialId does not exist!"
		} else {
        $body['credential'] = @{ id = $credentialId }
        }
	} else {
        # Use Credentialname
        $Credential =  Get-ICCredential | where { $_.name -eq $CredentialName }
		if (-NOT $CredentialName) {
			Throw "Credential with name [$CredentialName] does not exist! Please create it or specify a different credential (referenced by id or name)"
            $body['credential'] = @{ name = $CredentialName }
  	    }
    }

    # Select Credential
    if ($sshCredentialId) {
        $body['sshcredential'] = @{ id = $credentialId }
    } elseif ($sshCredentialName) {
        $body['sshcredential'] = @{ name = $sshCredentialName }
    }

    if ($ScanOptions) {
    	$body['options'] = $ScanOptions
    }

	# Initiating Scan
	$Endpoint = "targets/scan"
	Write-Verbose "Starting Scan of target $($target)"
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function New-ICScanOptions {
    param(
        [parameter(ValueFromPipeLine=$true)]
        [String[]]$ExtensionIds,

        [Switch]$ExtensionsOnly
    )
    BEGIN {
        $Ids = @()
    }
    PROCESS {
        $Ids += $_
    }
    END {
        if (-NOT $Ids) {
            $Ids = $ExtensionIds
        }
    	Write-Host 'ScanOption object properties should be set ($True or $False) and then passed into Invoke-ICScan or Add-ICScanSchedule'
        if ($ExtensionsOnly) {
            $default = $false
        } else {
            $default = $true
        }
    	$options = @{
      	    EnableProcess = $default
    		EnableAccount = $default
    		EnableMemory = $default
    		EnableModule = $default
    		EnableDriver = $default
    		EnableArtifact = $default
    		EnableAutostart = $default
    		EnableApplication = $default
    		EnableHook = $default
    		EnableNetwork = $default
            EnableEventLog = $default
    		EnableLogDelete = $true
        }
        if ($ExtensionIds) {
            $options['extensionIds'] = $Ids
        }
    	return $options
    }
}

function Add-ICScanSchedule {
	[cmdletbinding()]
	param(
		[parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String]$TargetGroupId,

		[parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String]$CronExpression,

		[PSObject]$ScanOptions
	)
	$TargetGroup = Get-ICTargetGroup -TargetGroupId $TargetGroupId
	if (-NOT $TargetGroup) {
		Throw "No such target group with id $TargetGroupId"
	}
	$Endpoint = "scheduledJobs"
	Write-Verbose "Creating new schedule for TargetGroup: $($TargetGroup.name) with Cron Express: $CronExpression"
    $body = @{
		name = 'scan-scheduled'
		relatedId = $TargetGroupId
		schedule = $CronExpression
		data = @{
			targetId = $TargetGroupId
		}
	}
	if ($ScanOptions) {
		if ($ScanOptions.EnableProcess -eq $True) {
				$body.data['options'] = $ScanOptions
		} else {
			Throw "ScanScheduleOptions format is invalid -- use New-ICScanScheduleOptions to create an options object"
		}
	}
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Get-ICScanSchedule {
    [cmdletbinding()]
    param(
        [String]$TargetGroupId
    )
    $Endpoint = "ScheduledJobs"
    $filter =  @{
        order = @("relatedId")
        limit = $resultlimit
        skip = 0
    }
	if ($TargetGroupId) {
		$TargetGroups = Get-ICTargetGroup -TargetGroupId $TargetGroupId
		$ScheduledJobs = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true | where { $_.relatedId -eq $TargetGroupId}
	} else {
		$TargetGroups = Get-ICTargetGroup
		$ScheduledJobs = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
	}

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
	$ScheduledJobs
}

function Remove-ICScanSchedule {
	[cmdletbinding(DefaultParameterSetName = 'scheduleId')]
	param(
		[parameter(
			Mandatory,
			ParameterSetName  = 'scheduleId',
			Position = 0,
			ValueFromPipeline,
			ValueFromPipelineByPropertyName
		)]
		[ValidateNotNullOrEmpty()]
		[string]$scheduleId,

		[parameter(
			Mandatory,
			ParameterSetName  = 'TargetGroupId'
		)]
		[ValidateNotNullOrEmpty()]
		[Alias("targetId")]
		$targetGroupId
	)

	$Schedules = Get-ICScanchedule
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
	Write-Host "Unscheduling collection for Target Group $tgname"
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method DELETE
}

function Import-ICSurvey {
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

		[String]$ScanId,

		[String]$TargetGroupId,

      	[String]$TargetGroupName = "OfflineScans"
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
		$scans = Get-ICScan -NoLimit
		if ($scans.id -contains $ScanId) {
			$TargetGroupName = ($Scans | where { $_.scanId -eq $ScanId}).targetList
		} else {
			Throw "No scan exists with ScanId $ScanId. Specify an existing ScanId to add this survey result to or use other parameters to generate one."
		}
	}
	elseif ($TargetGroupId) {
		# Check TargetGroupId and create new ScanId for that group
		Write-Host "Checking for existance of target group with TargetGroupId: '$TargetGroupId' and generating new ScanId"
		$TargetGroups = Get-ICTargetGroup
		if ($TargetGroups.id -contains $TargetGroupId) {
			$TargetGroupName = ($TargetGroups | where { $_.id -eq $TargetGroupId }).name
		} else {
			Throw "No Target Group exists with TargetGroupId $TargetGroupId. Specify an existing TargetGroupId to add this survey to or use other parameters to generate one."
		}
	}
	else {
		Write-Host "No ScanId or TargetGroupId specified. Checking for existance of target group: '$TargetGroupName'"
  	    $TargetGroups = Get-ICTargetGroup
  	    if ($TargetGroups.name -contains $TargetGroupName) {
  		    Write-Host "$TargetGroupName Exists."
			$TargetGroupId = ($targetGroups | where { $_.name -eq $TargetGroupName}).id
  	    } else {
            Write-Host "$TargetGroupName does not exist. Creating new Target Group '$TargetGroupName'"
            $g = Get-ICControllerGroup
            if ($g.id.count -eq 1) {
                $ControllerGroupId = $g.id
            } else {
                $ControllerGroupId = $g[0].id
            }
            $TargetGroupId = (New-ICTargetGroup -Name $TargetGroupName -ControllerGroupId $ControllerGroupId).id
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
