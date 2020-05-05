# Scan APIs


function Get-ICScan {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('scanId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$TargetGroupId,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order = "completedOn desc",
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "scans"

        if ($Id -AND (-NOT $_.targetId)) {
            Write-Verbose "Getting Scan with Id $Id"
            $CountOnly = $false
            $order = $null
            $Endpoint += "/$Id"
        }
        elseif ($TargetGroupId) {
            $tg = Get-ICTargetGroup -Id $TargetGroupId
            if ($tg) {
                Write-Verbose "Getting Scans against Target Group $TargetGroup [$TargetGroupId]"
                $where += @{ targetId = TargetGroupId }
            } else {
                Write-Error "TargetGroup with Id $TargetGroupId does not exist."
                return
            }
        }

        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Invoke-ICScan {
	[cmdletbinding(DefaultParameterSetName = 'extensionIds')]
	param(
		[parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[Alias("targetId")]
		[String]$TargetGroupId,

		[Switch]$FindHosts,

		[parameter(
			Mandatory=$false, 
			ParameterSetName = 'options')]
		[PSCustomObject]$ScanOptions,

		[parameter(
			Mandatory=$false, 
			ParameterSetName = 'extensionIds')]
		[String[]]$ExtensionIds = @()
	)
	$TargetGroup = Get-ICTargetGroup -Id $TargetGroupId
	if (-NOT $TargetGroup) {
		Throw "TargetGroup with id $TargetGroupId does not exist!"
	}
	if ($FindHosts) {
		Write-Progress -Activity "Performing discovery on $($TargetGroup.name)"
		$stillactive = $true
		$UserTask = Invoke-ICFindHosts -TargetGroupId $TargetGroupId
		While ($stillactive) {
			Start-Sleep 10
			$taskstatus = Get-ICUserTask -Id $UserTask.userTaskId -where @{ createdOn = @{ gt = (Get-Date).AddHours(-10) }; name = @{ regexp = $TargetGroup.name } } | Select-Object -first 1
			if ($taskstatus.status -eq "Active") {
				Write-Progress -Activity "Performing discovery on $($TargetGroup.name)" -PercentComplete $($taskstatus.progress)
			} elseif ($taskstatus.status -eq "Completed") {
				Write-Progress -Activity "Performing discovery on $($TargetGroup.name)" -Completed
				$stillactive = $false
			} else {
				Throw "Something went wrong in enumeration. Last Status: $($taskstatus.status)"
			}
		}

	}
	$Endpoint = "targets/$TargetGroupId/scan"
	Write-Verbose "Starting Scan of TargetGroup $($TargetGroup.name)"

    if ($ScanOptions) {
        $body = @{ options = $ScanOptions }
	} 
	elseif ($ExtensionIds -AND $ExtensionIds.count -gt 0) {
		$ScanOptions = New-ICScanOptions -ExtensionIds $ExtensionIds
		$body = @{ options = $ScanOptions }
	}
	Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
}

function Invoke-ICFindHosts {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[alias('targetId')]
		[String]$TargetGroupId,

        [parameter()]
		[String[]]$queryId
	)
	$TargetGroup = Get-ICTargetGroup -Id $TargetGroupId
	$Queries = Get-ICQuery -TargetGroupId $TargetGroupId
	if (-NOT $Queries) {
		Throw "Target Group not found or does not have any Queries associated with it"
	}
	$Endpoint = "targets/$TargetGroupId/Enumerate"
	$body = @{
		queries = @()
	}
    if ($QueryId) {
        $QueryId | ForEach-Object {
    		$body['queries'] += $_
        }
	} else {
		$Queries | ForEach-Object {
			$body['queries'] += $Queries.Id
		}
        Write-Verbose "Starting Enumeration of $($TargetGroup.name) with all associated queries.`n$($body['queries'] | convertto-json)"
	}
    Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
}

function Invoke-ICScanTarget {
	[cmdletbinding(DefaultParameterSetName = 'extensionIds')]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[String]$target,

		[String]$TargetGroupId,
		[String]$TargetGroupName = "OnDemand",

		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[String]$CredentialId,
		[String]$CredentialName,

		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$sshCredentialId,
		[String]$sshCredentialName,

		[parameter(
			Mandatory=$false, 
			ParameterSetName = 'options')]
		[PSCustomObject]$ScanOptions,

		[parameter(
			Mandatory=$false, 
			ParameterSetName = 'extensionIds')]
		[String[]]$ExtensionIds
	)
	PROCESS {
		if (-NOT $target -AND $_) {
			Write-Debug "Taking input from raw pipeline (`$_): $_."
			$target = $_
		}
		$body = @{
	        target = $target
	    }

		# Select Target targetgroup
		if ($TargetGroupId) {
			$TargetGroup = Get-ICTargetGroup -Id $TargetGroupId
			if (-NOT $TargetGroup) {
				Throw "TargetGroup with id $TargetGroupid does not exist!"
			} else {
	            $body['targetGroup'] = @{ id = $targetGroupId}
	        }
		} else {
	        Write-Verbose "Using Target Group Name [$TargetGroupName] -- will be created if it does not exist."
            $tg = Get-ICTargetGroup -where @{ name = $TargetGroupName}
            if (-NOT $tg) {
                $tg = New-ICTargetGroup -Name $TargetGroupName -Force
            }
	        $body['targetGroup'] = @{ id = $tg.id }
	    }

		# Select Credential
		if ($CredentialId) {
			$Credential = Get-ICCredential -Id $credentialId
			if (-NOT $Credential) {
				Throw "Credential with id $credentialId does not exist!"
			} else {
	            $body['credential'] = @{ id = $credentialId }
	        }
		} elseif ($CredentialName) {
	        # Use Credentialname
	        $Credential =  Get-ICCredential | Where-Object { $_.name -eq $CredentialName }
			if ($Credential) {
				$body['credential'] = @{ name = $CredentialName }
				Write-Error "Credential with name [$CredentialName] does not exist!"
				Write-Warning "Please create it or specify a different credential (referenced by id or name)"
				return
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
		elseif ($ExtensionIds -AND $ExtensionIds.count -gt 0) {
			$ScanOptions = New-ICScanOptions -ExtensionIds $ExtensionIds
			$body['options'] = $ScanOptions
		}

		# Initiating Scan
		$Endpoint = "targets/scan"
		Write-Verbose "Starting Scan of target $($target)"
		Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
	}
}

function New-ICScanOptions {
    param(
		[parameter(Mandatory=$false,
			ValueFromPipeLine)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String[]]$ExtensionIds,

        [Switch]$ExtensionsOnly
    )
    BEGIN {
        $ExtIds = @()
    }
    PROCESS {
		if ($_) { $ExtIds += $_.ToString() }
    }
    END {
        if (-NOT $ExtIds) {
            $ExtIds = $ExtensionIds
        }
    	Write-Verbose 'ScanOption object properties should be set ($True or $False) and then passed into Invoke-ICScan or Add-ICScanSchedule'
        if ($ExtensionsOnly) {
            $default = $false
        } else {
            $default = $true
        }
    	$options = @{
			process = $default
			module = $default
			driver = $default
			memory = $default
			account = $default
    		artifact = $default
    		autostart = $default
			application = $default
			installed = $false
    		hook = $false
    		network = $default
            events = $default
			extensionIds = @()
        }
        if ($ExtIds) {
            $options['extensionIds'] = $ExtIds
        }
    	return [PSCustomObject]$options
    }
}


function Invoke-ICResponse {
	[cmdletbinding(DefaultParameterSetName = 'ByName')]
	param(
		[parameter(
			Mandatory=$true, 
			ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Target,

		[parameter()]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		#[ValidatePattern("^(([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12})$")]
		[String]$TargetGroupId,
		[parameter()]
		[String]$TargetGroupName = "OnDemand",

		[parameter(
			Mandatory=$true, 
			ParameterSetName = 'ById')]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[String]$ExtensionId,
		[parameter(
			Mandatory=$true, 
			ParameterSetName = 'ByName')]
		[ValidateNotNullOrEmpty()]
		[String]$ExtensionName
	)
	PROCESS {
		if (-NOT $target -AND $_) {
			Write-Debug "Taking input from raw pipeline (`$_): $_."
			$target = $_
		}
		$body = @{
	        target = $target
		}
		
		# Select Target targetgroup
		if ($TargetGroupId) {
			$TargetGroup = Get-ICTargetGroup -Id $TargetGroupId
			if (-NOT $TargetGroup) {
				Throw "TargetGroup with id $TargetGroupid does not exist!"
			} else {
	            $body['targetGroup'] = @{ id = $targetGroupId}
	        }
		} else {
	        Write-Verbose "Using Target Group Name [$TargetGroupName] -- will be created if it does not exist."
            $tg = Get-ICTargetGroup -where @{ name = $TargetGroupName}
            if (-NOT $tg) {
                $tg = New-ICTargetGroup -Name $TargetGroupName -Force
            }
	        $body['targetGroup'] = @{ id = $tg.id }
		}
		
		if ($ExtensionId) {
			$Ext = Get-ICExtension -Id $ExtensionId
			if (-NOT $Ext) {
				Write-Error "Extension with id $ExtensionId does not exist!"
				return
			}
			$ExtensionName = $Ext.name
		}
		else {
			$Ext = Get-ICExtension -where @{ name = $ExtensionName } | Select-Object -First 1
			if (-NOT $Ext) {
				Write-Error "Extension with name $ExtensionName does not exist!"
				return
			}
			$ExtensionId = $Ext.Id
		}
		
		$ScanOpts = New-ICScanOptions -ExtensionsOnly -ExtensionIds $ExtensionId
		$Body['options'] = $ScanOpts
		
		# Initiating Scan
		$Endpoint = "targets/scan"
		Write-Verbose "Executing response action $ExtensionName on target: $target"
		Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
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
	Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
}

function Get-ICScanSchedule {
    [cmdletbinding()]
    param(
		[String]$Id,
        [String]$TargetGroupId,
        [HashTable]$where=@{},
        [String[]]$order = @("relatedId")
    )
    $Endpoint = "ScheduledJobs"
	if ($TargetGroupId) {
		$TargetGroups = Get-ICTargetGroup -TargetGroupId $TargetGroupId
		$ScheduledJobs = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$true | Where-Object { $_.relatedId -eq $TargetGroupId}
	} else {
		$TargetGroups = Get-ICTargetGroup
		$ScheduledJobs = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$true
	}

	$ScheduledJobs | % {
		if ($_.relatedId) {
			 $tgid = $_.relatedId
			 $tg = $TargetGroups | Where-Object { $_.id -eq $tgid }
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
	[cmdletbinding(SupportsShouldProcess, DefaultParameterSetName = 'scheduleId')]
	param(
		[parameter(
			Mandatory,
			ParameterSetName  = 'scheduleId',
			Position = 0,
			ValueFromPipeline,
			ValueFromPipelineByPropertyName
		)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('scheduleId')]
		[string]$Id,

		[parameter(Mandatory, ParameterSetName  = 'targetGroupId')]
		[ValidateNotNullOrEmpty()]
		[Alias("targetId")]
		$targetGroupId
	)
	PROCESS {
		if (-NOT $Id -AND $_ ) {
			Write-Debug "Taking input from raw pipeline (`$_): $_."
			$Id = $_
		}
		$Schedules = Get-ICScanSchedule
		if ($Id) {
			$schedule = $Schedules | Where-Object { $_.id -eq $Id}
		}
		elseif ($TargetGroupId) {
			$schedule = $Schedules | Where-Object { $_.relatedId -eq $TargetGroupId}
			$ScheduleId	= $schedule.id
		} else {
			throw "Incorrect input!"
		}
		$tgname = $schedule.targetGroup
		if (-NOT $tgname) { throw "TargetGroupId not found!"}
		$Endpoint = "scheduledJobs/$ScheduleId"
	    if ($PSCmdlet.ShouldProcess($Id, "Will remove schedule from $tgname")) {
	    	Write-Warning "Unscheduling collection for Target Group $tgname"
	    	Invoke-ICAPI -Endpoint $Endpoint -method DELETE
	    }
	}
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
		[alias('TargetGroupName')]
      	[String]$DefaultTargetGroupName = "OfflineScans"
    )

    BEGIN {
  	# INITIALIZE
  	$survey = "HostSurvey.json.gz"
  	$surveyext = "*.json.gz"

  	function Send-ICSurveys ([String]$FilePath, [String]$ScanId){
  		Write-Verbose "Uploading Surveys"
			$headers = @{
		    Authorization = $Global:ICToken
				scanid = $ScanId
		    }
  		try {
  			Invoke-RestMethod $HuntServerAddress/api/survey -Headers $headers -Method POST -InFile $FilePath -ContentType "application/octet-stream"
  		} catch {
  			throw "$($_.Exception.Message)"
  		}
  	}

	if ($ScanId) {
		# Check for existing ScanId and use it
		$scan = Get-ICScan -Id $ScanId
		if ($scan) {
			$ScanName = $scan.name
			$TargetGroupName = $Scan.targetList
		} else {
			Write-Warning "No scan exists with ScanId $ScanId. Generating one."
		}
	}

	if ($TargetGroupId) {
		# Check TargetGroupId and create new ScanId for that group
		Write-Verbose "Checking for existance of target group with TargetGroupId: '$TargetGroupId' and generating new ScanId"
		$TargetGroup = Get-ICTargetGroup -id $TargetGroupId
		if ($TargetGroup) {
			$TargetGroupName = ($TargetGroups | Where-Object { $_.id -eq $TargetGroupId }).name
		} else {
			Throw "No Target Group exists with TargetGroupId $TargetGroupId. Specify an existing TargetGroupId to add this survey to or use other parameters to generate one."
		}
	}
	else {
		Write-Verbose "No ScanId or TargetGroupId specified. Checking for existance of target group: '$TargetGroupName'"
  	    $TargetGroups = Get-ICTargetGroup
  	    if ($TargetGroups.name -contains $TargetGroupName) {
  		    Write-Verbose "$TargetGroupName Exists."
			$TargetGroupId = ($targetGroups | Where-Object { $_.name -eq $TargetGroupName}).id
  	    } else {
            Write-Warning "$TargetGroupName does not exist. Creating new Target Group '$TargetGroupName'"
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
	if (-NOT $ScanName) {
		$ScanName = "Offline-" + (get-date).toString("yyyyMMdd-HHmm")
		Write-Verbose "Creating scan named $ScanName [$TargetGroupName-$ScanName]..."
		$StartTime = _Get-ICTimeStampUTC
		$body = @{
			name = $scanName;
			targetId = $TargetGroupId;
			startedOn = $StartTime
		}
		$newscan = Invoke-ICAPI -Endpoint $Endpoint -body $body -Method 'POST'
		$ScanId = $newscan.id
	}

	Write-Verbose "Importing Survey Results into $TargetGroupName-$ScanName [ScanId: $ScanId] [TargetGroupId: $TargetGroupId]"
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
 			Write-Verbose "Uploading survey [$file]..."
 			if ((Test-Path $file -type Leaf) -AND ($file -like $surveyext)) {
 				Send-ICSurveys -FilePath $file -ScanId $ScanId
   		    } else {
   			    Write-Warning "$file does not exist or is not a $surveyext file"
   		    }
	   	}
	}

    END {
	    # TODO: detect when scan is no longer processing submissions, then mark as completed
        #Write-Verbose "Closing scan..."
        #Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$HuntServerAddress/api/scans/$scanId/complete" -Method Post
    }

}
