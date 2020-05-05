
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
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
		[String[]]$order = "createdOn",
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$endpoint = 'jobs'
		if ($Id) {
			$CountOnly = $false
			$order = $null
			$endpoint += "/$Id"
		}
		if ($All) {
			Write-Verbose "Getting All Jobs."
		} else {
			Write-Verbose "Getting Active Jobs."
			if (-NOT $where['state']) {
				$where['state'] = "active"
			}
		}
		Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
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
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
		[String[]]$order = "createdOn DESC",
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)
	PROCESS {
		$endpoint = 'useractivities'
		if ($Id) {
			$CountOnly = $false
			$order = $null
			$endpoint += "/$Id"
		}
		Write-Verbose "Getting User Activity Logs"
		Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}

# Get Infocyte HUNT User Tasks. These are the items in the task dropdown in the UI.
function Get-ICTask {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipelineByPropertyName)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('TaskId')]
		[String]$Id,

		[Switch]$All,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
		[String[]]$order = "endedOn Desc",
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$endpoint = "usertasks"
		if ($Id) {
			$CountOnly = $false
			$order = $null
			$endpoint += "/$Id"
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
		Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}

function Get-ICTaskItems {
	[cmdletbinding()]
	param(
		[parameter(
			Mandatory,
			ValueFromPipeline)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[String]$TaskId,

		[parameter()]
		[Switch]$IncludeProgress,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
		[String[]]$order = "updatedOn Desc",
		[String[]]$fields,
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$Endpoint = "userTaskItems"
		$where['userTaskId'] = $TaskId
		Write-Verbose "Getting All TaskItems with TaskId $TaskId."
	
		if ($IncludeProgress -AND (-NOT $CountOnly)) {
			$n = 1
			if ($Id) {
				$cnt = 1
			} else {
				$cnt = Get-ICAPI -Endpoint $Endpoint -where $where -CountOnly
			}
			Write-Verbose "Found $cnt TaskItems. Getting progress for each."
			$items = Get-ICAPI -Endpoint $Endpoint -where $where -order $order -fields $fields -NoLimit:$NoLimit
			$items | ForEach-Object {
				$n += 1
				try { $pc = [math]::floor($n*100/$cnt); if ($pc -gt 100) { $pc = 100 } } catch { $pc = -1 }
				if ($_.id) {
					$progress = @()
					Write-Progress -Id 101 -Activity "Enriching with Task Progress Information" -status "Getting progress on $($_.name) [$n of $cnt]" -PercentComplete $pc
					Get-ICTaskItemProgress -taskItemId $_.id -fields "createdOn","text" -order "createdOn desc" | ForEach-Object {
						$progress += [PSCustomObject]@{
							createdOn = $_.createdOn
							text = $_.text
						}
					}
					$_ | Add-Member -MemberType "NoteProperty" -name "progress" -value $progress
				}
			}
			Write-Output $items
		} else {
			Get-ICAPI -Endpoint $Endpoint -where $where -order $order -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
		}
	}
}

function Get-ICTaskItemProgress {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[alias('id')]
		[String]$taskItemId,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
		[String[]]$order = "createdOn desc",
		[String[]]$fields,
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$Endpoint = "userTaskItemProgresses"
		if ($_.id -AND $_.taskItemId) {
			# disambuguation
			$where['taskItemId'] = $_.taskItemId
		} else {
			$where['taskItemId'] = $taskItemId
		}
		Get-ICAPI -Endpoint $Endpoint -where $where -order $order -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}

function Get-ICLastScanTask {
	[cmdletbinding()]
	param(
		[parameter()]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
		[String]$taskItemId,

		[parameter()]
		[ValidateSet("Scan", "Enumerate")]
		[String]$Type = "Enumerate"
	)

	if ($taskItemId) {
		$Task = Get-ICTask -id $TaskItemId | Select-Object -Last 1
		if (-NOT $Task -OR $Task.type -notin @("Enumerate", "Scan")) {
			Write-Error "No task was found with Id: $taskItemId"
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

	$Progress = Get-ICTaskItems -TaskId $Task.id -IncludeProgress -NoLimit | Select-Object name, createdOn, endedOn, progress
	$Progress | % {
		$accessible = $false
		if ($_.endedOn) {
			$totalSeconds = [math]::round(([datetime]$_.endedOn - [DateTime]$_.createdOn).TotalSeconds)
		}
		$_ | Add-Member -MemberType NoteProperty -Name "totalSeconds" -Value $totalSeconds
		try {
			$Message = ($_.progress.text | select-string "ACCESSIBLE").ToString()
			if ($Message -match "^ACCESSIBLE") {
				$accessible = $true
			}
		} catch {}	
		$_ | Add-Member -MemberType NoteProperty -Name "message" -Value $Message
		$_ | Add-Member -MemberType NoteProperty -Name "accessible" -Value $accessible
	}

	if ($Task.endedOn) {
		$totalTime = [math]::round(([datetime]$Task.endedOn - [DateTime]$Task.createdOn).TotalSeconds)
	}

	$result = [PSCustomObject]@{
		taskId = $Task.Id
		name = $Task.name
		createdOn = $Task.createdOn
		endedOn = $Task.endedOn
		totalSeconds = $totalTime
		status = $Task.status
		type = $Task.type
		accessibleCount = ($Progress | Where-Object { $_.Accessible }).count
		inaccessibleCount = ($Progress | Where-Object { -NOT $_.Accessible }).count
		totalItems = $Progress.count
		items = $Progress
	}
	$result['coverage'] = try { [math]::Round(($($result.accessibleCount)/$($result.totalItems)), 2) } catch { $null }
	return $result
}