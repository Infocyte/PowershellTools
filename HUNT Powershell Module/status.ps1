
# Status and Progress APIs

# Get Infocyte HUNT Jobs (Active jobs or all jobs)
function Get-ICJob {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipelineByPropertyName)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('jobId')]
		[String]$Id,

		[Switch]$All,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$endpoint = 'jobs'
		if ($Id) {
			$CountOnly = $false
			$endpoint += "/$Id"
			$where = $null
			$NoLimit = $false
		} else {
			if ($All) {
				Write-Verbose "Getting All Jobs."
			} else {
				Write-Verbose "Getting Active Jobs."
				if (-NOT $where['state']) {
					$where['state'] = "active"
				}
			}
		}
		Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}

# Get Infocyte HUNT User Audit Logs
function Get-ICAuditLog {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipeline)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[String]$Id,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)
	PROCESS {
		$endpoint = 'useractivities'
		if ($Id) {
			$CountOnly = $false
			$endpoint += "/$Id"
		}
		Write-Verbose "Getting User Activity Logs"
		Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}

# Get Infocyte HUNT User Tasks. These are the items in the task dropdown in the UI.
function Get-ICTask {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('id')]
		[alias('userTaskId')]
		[String]$TaskId,

		[Switch]$All,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$endpoint = "usertasks"
		if ($TaskId) {
			$CountOnly = $false
			$endpoint += "/$TaskId"
		} else {
			if (-NOT $All -AND $where.keys.count -eq 0) {
				Write-Verbose "Filtering for running and recently ended tasks (Default)."
				$where = @{ and = @() }
				$where['and'] += @{ type = @{ neq = "RTS"} }
				$where['and'] += @{ or = @( 
						@{ status = "Active" },
						@{ endedOn = @{ gte = (Get-Date).ToUniversalTime().AddDays(-1).ToString() } }
					)}
				$where['and'] += @{ archived = $false }
				Write-Verbose "Using filter: $($Where | convertto-json)"
			}
		}
		$Tasks = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
		$Tasks | ForEach-Object {
			$_ | Add-Member -Type NoteProperty -Name totalSeconds -Value $null
			if ($_.endedOn) {
				$_.totalSeconds = [math]::round(([datetime]$_.endedOn - [DateTime]$_.createdOn).TotalSeconds)
			}
		}
		Write-Output $Tasks
	}
}

function Get-ICTaskItems {
	[cmdletbinding()]
	param(
		[parameter(
			Mandatory,
			ValueFromPipeline,
			ValueFromPipelineByPropertyName)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('id')]
		[alias('userTaskId')]
		[String]$TaskId,

		[parameter()]
		[Switch]$IncludeProgress,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$Where=@{},
		[String[]]$Fields,
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$Endpoint = "userTaskItems"
		$where['userTaskId'] = $TaskId
		
		if ($CountOnly) {
			return (Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly)
		}

		Write-Verbose "Getting All TaskItems with TaskId $TaskId."
		$Items = Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
		ForEach ($item in $items) {
			$item | Add-Member -Type NoteProperty -Name totalSeconds -Value $null
			if ($item.endedOn) {
				$item.totalSeconds = [math]::round(([datetime]$item.endedOn - [DateTime]$item.createdOn).TotalSeconds)
			}

			if ($item.type -eq "host-access" -OR $item.type -eq "enumeration") {
				$type = $item.type
				$item | Add-Member -Type NoteProperty -Name queryId -Value $null
				$item | Add-Member -Type NoteProperty -Name queryName -Value $null
				
				if ($type -eq "enumeration") {
					$item.queryId = $item.result.queryId
				} 
				elseif ($type -eq "host-access") {
					Write-Verbose "Getting QueryId from job"
					try { $j = Get-ICJob -Id $item.jobId } catch { }
					$item.queryId = $j.data.queryId
				}

				if ($item.queryId) {
					Write-Verbose "Getting QueryName"
					$q = Get-ICQuery -Id $item.queryId
					$item.queryName = $q.Name
				}
			}
		}

		if (-NOT $IncludeProgress) {
			 
			Write-Output $Items

		} else {
			$n = 0
			if ($Id) {
				$cnt = 1
			} else {
				$cnt = Get-ICAPI -Endpoint $Endpoint -where $where -CountOnly
			}
			Write-Verbose "Found $cnt TaskItems. Getting progress for each."
			ForEach ($item in $items) {
				$item | Add-Member -Type NoteProperty -Name lastMessage -Value $null
				if ($item.type -eq "host-access") {
					$item | Add-Member -Type NoteProperty -Name accessible -Value $null
				}

				$n += 1
				try { $pc = [math]::floor($n*100/$cnt); if ($pc -gt 100) { $pc = 100 } } catch { $pc = -1 }
				if ($item.id) {
					Write-Progress -Id 101 -Activity "Enriching with Task Progress Information" -status "Getting progress on $($item.name) [$n of $cnt]" -PercentComplete $pc
					$progresstext = @()
					_Get-ICTaskItemProgress -taskItemId $item.id | ForEach-Object {
						$p = $_
						$p | foreach-object {
							$progresstext += "$($_.createdOn) - $($_.text)"	
							if (-NOT $LastProgressMsg) {
								$LastProgressMsg = "$($_.createdOn) - $($_.text)"
							}
							if ($type -eq "host-access" -AND $_.text -match "^ACCESSIBLE:") { 
								$item.accessible = $true
								$item.lastMessage = $_.text
							}
							elseif ($type -eq "host-access" -AND $_.text -match "^INACCESSIBLE:") { 
								$item.accessible = $false
								$item.lastMessage = $_.text
							}																
						}
					}
					if ($item.status -ne "complete" -AND -NOT $item.message) {
						$item.lastMessage = $LastProgressMsg
					}
					$item | Add-Member -MemberType "NoteProperty" -name "progress" -value ([string[]]$progresstext)
				}
			}
			Write-Output $items
		}
	}
}

function _Get-ICTaskItemProgress {
	[cmdletbinding()]
	param(
		[parameter(
			Mandatory=$true, 
			ValueFromPipeline,
			ValueFromPipelineByPropertyName)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('userTaskItemId')]
		[alias('id')]
		[String]$taskItemId,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
		[HashTable]$where=@{},
		
        [Switch]$NoLimit
	)

	PROCESS {
		$Endpoint = "userTaskItemProgresses"
		if ($_.id -AND $_.taskItemId) {
			# disambuguation
			$where['taskItemId'] = $_.taskItemId
		} else {
			$where['taskItemId'] = $taskItemId
		}
		Get-ICAPI -Endpoint $Endpoint -where $where -fields @("createdOn", "text") -NoLimit:$NoLimit | Sort-Object createdOn -Descending
	}
}

function Wait-ICTask {
	[cmdletbinding()]
	param(
		[parameter(
			Mandatory,
			ValueFromPipeline,
			ValueFromPipelineByPropertyName)]
		[ValidateScript( { if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
		[alias('id')]
		[alias('userTaskId')]
		[String]$TaskId
	)

	BEGIN {}
	PROCESS {
		$Task = Get-ICTaskItems -TaskId $TaskId -IncludeProgress
		while (-NOT $Task.complete) {
			Start-Sleep 20
			$Task = Get-ICTaskItems -TaskId $TaskId -IncludeProgress
		}
		return $true
	}
	END{}
}

function Get-ICLastScanTask {
	[cmdletbinding()]
	param(
		[parameter(Mandatory, Position=0)]
		[ValidateSet("Scan", "Enumerate")]
		[String]$Type,

		[parameter(Position=1)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[String]$targetGroupId
	)

	if ($targetGroupId) {
		$Task = Get-ICTask -where @{ targetGroupId = $targetGroupId; type = $Type } | Select-Object -Last 1
		if (-NOT $Task) {
			Write-Error "No $Type task was found within target group with Id: $targetGroupId"
			return
		}
	}
	else {
		$where = @{ and = @()}
		#$where['and'] += @{ endedOn = @{ gte = (Get-Date).ToUniversalTime().AddDays(-1).ToString() } }
		$where['and'] += @{ type = $Type; }
		$where['and'] += @{ archived = $false }
		$Task = Get-ICTask -where $where  | Select-Object -Last 1
		if (-NOT $Task) {
			Write-Error "No task was found with type: $Type"
			return
		}
	}

	$Progress = Get-ICTaskItems -TaskId $Task.id -IncludeProgress -NoLimit

	$result = @{
		userTaskId = $Task.Id
		name = $Task.name
		createdOn = $Task.createdOn
		endedOn = $Task.endedOn
		totalSeconds = $task.totalSeconds
		status = $Task.status
		type = $Task.type
		accessibleCount 	= ([Array]($Progress | Where-Object { $_.Accessible })).count
		inaccessibleCount 	= ([Array]($Progress | Where-Object { -NOT $_.Accessible })).count
		totalItems        	= ([Array]$Progress).count
		items = $Progress
	}
	$result['coverage'] = try { [math]::Round(($($result.accessibleCount)/$($result.totalItems)), 2) } catch { $null }
	return [PSCustomObject]$result
}