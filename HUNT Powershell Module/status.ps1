
# Status and Progress APIs

# Get Infocyte HUNT Jobs (Active jobs or all jobs)
function Get-ICJob {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipelineByPropertyName)]
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
function Get-ICUserAuditLog {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipeline)]
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
function Get-ICUserTask {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipelineByPropertyName)]
		[alias('UserTaskId')]
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
			if (-NOT $All -AND -NOT $where) {
				Write-Verbose "Filtering for running and recently ended tasks (Default)."
				$where['or'] = @(
					@{ status = "Active" },
					@{ endedOn = @{ gte = (Get-Date).ToUniversalTime().AddDays(-1).ToString() } }
				)
			}
		}
		Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}

function Get-ICUserTaskItem {
	[cmdletbinding(DefaultParameterSetName='userTasks')]
	param(
		[parameter(Mandatory,
			ParameterSetName="userTaskItem")]
		[alias('userTaskItemId')]
		[String]$Id,

		[parameter(Mandatory,
			ParameterSetName="userTasks",
			ValueFromPipeline,
			ValueFromPipelineByPropertyName)]
		[ValidatePattern("[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}")]
		[String]$userTaskId,

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

		if ($PsCmdlet.ParameterSetName -eq 'userTaskItem') {
			$Endpoint += "/$Id"
		} else {
			Write-Verbose $userTaskId
			if ($userTaskId.GetType().name -eq "PSCustomObject") {
				Write-Debug "Taking input from raw pipeline (`$_): $_."

				if ($_.userTaskId -match "[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}") {
					$userTaskId = $_.userTaskId
				}
				elseif ($_.id -match "[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}") {
					$userTaskId = $_.id
				}
				else {
					Write-Error "Can't parse pipeline input for a userTaskId."
					return
				}
			}
			$where['userTaskId'] = $userTaskId
			Write-Verbose "Getting All UserTaskItems with userTaskId $userTaskId."
		}

		if ($IncludeProgress -AND (-NOT $CountOnly)) {
			$n = 1
			if ($Id) {
				$cnt = 1
			} else {
				$cnt = Get-ICAPI -Endpoint $Endpoint -where $where -CountOnly
			}
			Write-Verbose "Found $cnt userTaskItems. Getting progress for each."
			$items = Get-ICAPI -Endpoint $Endpoint -where $where -order $order -fields $fields -NoLimit:$NoLimit
			$items | foreach {
				$n += 1
				try { $pc = $n/$cnt } catch { $pc = -1 }
				if ($_.id) {
					$progress = @()
					Write-Progress -Id 2 -Activity "Enriching with Task Progress Information" -status "[$n of $cnt] Getting progress on $($_.name)" -PercentComplete $pc
					Get-ICUserTaskItemProgress -taskItemId $_.id -fields "createdOn","text" -order "createdOn desc" | foreach {
						$progress += New-Object PSObject -Property @{
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

function Get-ICUserTaskItemProgress {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
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
