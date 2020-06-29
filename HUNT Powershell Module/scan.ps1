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
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "scans"

        if ($Id -AND (-NOT $_.targetId)) {
            Write-Verbose "Getting Scan with Id $Id"
            $CountOnly = $false
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

        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
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
		[String[]]$ExtensionIds = @(),

		
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where
	)

	$TargetGroup = Get-ICTargetGroup -Id $TargetGroupId
	if (-NOT $TargetGroup) {
		Throw "TargetGroup with id $TargetGroupId does not exist!"
	}

	if ($FindHosts) {
		Write-Progress -Activity "Performing discovery on $($TargetGroup.name)"
		$stillactive = $true
		$UserTask = Invoke-ICFindHosts -TargetGroupId $TargetGroupId -where $where
		While ($stillactive) {
			Start-Sleep 20
			# -where @{ createdOn = @{ gt = (Get-Date).AddHours(-10) }; name = @{ regexp = $TargetGroup.name } } 
			$taskstatus = Get-ICUserTask -Id $UserTask.userTaskId
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
	if ($where) {
		$body += @{ where = $where }
	}
	try {
		Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
	} catch {
		Write-Warning "Server Error. Could not find accessible targets with given filters: $($where | convertto-json -compress): [$($_.Message)]"
		return
	}
}

function Invoke-ICFindHosts {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[alias('targetId')]
		[String]$TargetGroupId,

        [parameter()]
		[String[]]$queryId,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where
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
	if ($where) {
		$body['where'] += $where
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
		[String[]]$ExtensionIds,

		[Switch]$Wait
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
			$tg = Get-ICTargetGroup -Id $TargetGroupId
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
			$targetGroupId = $tg.id
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
				Throw "Credential with name [$CredentialName] does not exist! Please create it or specify a different credential (referenced by id or name)"
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

		# Check for active agent
		if (-NOT $body['credential']) {
			$agent = Get-ICAgent -where @{ authorized = $true; or = @(  @{ hostname = $target }, @{ ipstring = $target }) }
			if (-NOT $agent.active) {
				Write-Verbose "No active agent found, looking for existing address entry in target group $tg"
				#Check Address Table
				$Addr = Get-ICAddress -targetId $targetGroupId -where @{ accessible = $true; or = @(  @{ hostname = $target }, @{ ipstring = $target }) } | Sort-Object lastAccessedOn -Descending | Select-Object -Last 1
				if (-NOT $addr) {
					Write-Verbose "No accessible address entry in target group $tg, looking at all target groups"
					$Addr2 = Get-ICAddress -where @{ accessible = $true; or = @(  @{ hostname = $target }, @{ ipstring = $target }) } | Sort-Object lastAccessedOn -Descending | Select-Object -Last 1
					if ($Addr2) {
						# Transfer over an existing accessible address entry
						Write-Verbose "Found accessible address entry, transfering it over to target group $tg"
						$existingAddr = Get-ICAddress -targetId $targetGroupId -where @{ or = @(  @{ hostname = $target }, @{ ipstring = $target }) }
						if ($existingAddr) { $existingAddr | Remove-ICAddress }
						$ht = @{ }
						$addr2.psobject.properties | ForEach-Object { $ht[$_.Name] = $_.Value }
						$ht.Remove('id')
						$ht.Remove('queryId')
						$ht.Remove('taskId')
						$ht['targetId'] = $TargetGroupId
						$Addr = Invoke-ICAPI -Endpoint "Addresses" -Method POST -Body $ht			
					} else {
						Write-Verbose "No accessible address entry found for $target"
					}
				}

				if ($Addr) {
					$where = @{ id = $Addr.id }
					$scan = Invoke-ICScan -TargetGroupId $TargetGroupId -ScanOptions $ScanOptions -where $where 
					$task = Get-ICTask -id $scan.userTaskId
					if ($Wait) {
						$timer = [system.diagnostics.stopwatch]::StartNew()
						while ($task.status -eq "Active"){
							$t = $timer.Elapsed
							Write-Progress -Activity "Scanning $target" -Status "[$($t.TotalSeconds.ToString("#.#"))] Status=$($task.message)"
							Start-Sleep 5
							$task = Get-ICTask -id $scan.userTaskId
						}
						$timer.Stop()
						$TotalTime = $timer.Elapsed
						Write-Progress -Activity "Scanning $target" -Status "[$($TotalTime.TotalSeconds.ToString("#.#"))] Status=$($task.message)" -Completed
						Write-Verbose "Task $($task.status). Completed in $($TotalTime.TotalSeconds.ToString("#.#")) Seconds."
					}
					return $scan
				} 
			}
		}

		# Initiating Scan
		$Endpoint = "targets/scan"
		Write-Verbose "Starting Scan of target $($target)"
		try {
			$scan = Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
			$scan = [PSCustomObject]@{ userTaskId = $scan.scanTaskId } 
			if ($Wait) {
				$timer = [system.diagnostics.stopwatch]::StartNew()
				$task = Get-ICTask -id $scan.userTaskId
				while ($task.status -eq "Active"){
					$t = $timer.Elapsed
					Write-Progress -Activity "Scanning $target" -Status "[$($t.TotalSeconds.ToString("#.#"))] Status=$($task.message)"
					Start-Sleep 5
					$task = Get-ICTask -id $scan.userTaskId
				}
				$timer.Stop()
				$TotalTime = $timer.Elapsed
				Write-Progress -Activity "Scanning $target" -Status "[$($TotalTime.TotalSeconds.ToString("#.#"))] Status=$($task.message)" -Completed
				Write-Verbose "Task $($task.status). Completed in $($TotalTime.TotalSeconds.ToString("#.#")) Seconds."
			}
			return $scan
		} catch {
			$statuscode = $_.Exception.Response.StatusCode.value__
			Switch -regex ($statuscode) {
				"5\d\d" {
					Write-Warning "No active agent or accessible address entry found for '$target' [error=$statuscode - $($_.Exception.Message)]"
					return
				}
				default {
					Throw $_.Exception.Message
				}
			}
		}
	}
}

enum ScanOptions {
	process     
	module       
	driver       
	memory       
	account  
	artifact
	autostart
	application
	installed
	hook
	network
	events
}

function New-ICScanOptions {
	[cmdletbinding(DefaultParameterSetName = 'Options')]
    param(
		[parameter(Mandatory=$false)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String[]]$ExtensionIds,

		[Parameter(ParameterSetName="Empty")]
		[Switch]$Empty,

		[parameter(ParameterSetName="Options")]
		[ScanOptions[]]$Options

	)

	END {
		Write-Verbose 'ScanOption object properties should be set ($True or $False) and then passed into Invoke-ICScan or Add-ICScanSchedule'
		if ($Empty -OR $Options) {
			$default = $false
		}
		else {
			$default = $true
		}
		$opts = @{
			process      = $default
			module       = $default
			driver       = $default
			memory       = $default
			account      = $default
			artifact     = $default
			autostart    = $default
			application  = $default
			installed    = $false
			hook         = $false
			network      = $default
			events       = $default
			extensionIds = @()
		}
	
		if ($Options) {
			$Options | ForEach-Object {
				Write-Verbose "Changing $_ to True"
				$opts["$_"] = $true
			}
		}

		if ($ExtensionIds) {
			$opts['extensionIds'] = $ExtensionIds
		}
	
		return [PSCustomObject]$opts
	}
}


function Invoke-ICResponse {
	[cmdletbinding(DefaultParameterSetName = 'ByName')]
	param(
		[parameter(
			Mandatory, 
			ValueFromPipeline,
			ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
		[alias("ip")]
		[alias("hostname")]
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
		[String]$ExtensionName,

		[Switch]$Wait
	)

	BEGIN {
		if ($ExtensionId) {
			$Ext = Get-ICExtension -Id $ExtensionId
			if (-NOT $Ext) {
				Throw "Extension with id $ExtensionId does not exist!"
			}
			$ExtensionName = $Ext.name
		}
		else {
			$Ext = Get-ICExtension -where @{ name = $ExtensionName } | Select-Object -Last 1
			if (-NOT $Ext) {
				Throw "Extension with name $ExtensionName does not exist!"
			}
			$ExtensionId = $Ext.Id
		}
		
		$ScanOptions = New-ICScanOptions -Empty -ExtensionIds $ExtensionId
		$ScanOptions.process = $true # remove when bug fixed
		$ScanOptions.account = $true
	}

	PROCESS {
		$task = Invoke-ICScanTarget -target $target -TargetGroupId $TargetGroupId -TargetGroupName $TargetGroupName -ScanOptions $ScanOptions -Wait:$Wait
		return $task
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
        [HashTable]$where=@{}
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