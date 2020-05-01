
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
				$where['and'] = @(
					@{ or = @( 
						@{ status = "Active" },
						@{ endedOn = @{ gte = (Get-Date).ToUniversalTime().AddDays(-1).ToString() } }
					)},
					@{ archived = $false }
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
		[String]$Id,

		[parameter(Mandatory,
			ParameterSetName="userTasks",
			ValueFromPipeline,
			ValueFromPipelineByPropertyName)]
		[ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
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
		$PsCmdlet.ParameterSetName
		if ($PsCmdlet.ParameterSetName -eq 'userTaskItem') {
			$Endpoint += "/$Id"
			Write-Verbose "Getting UserTaskItem with userTaskItemId $Id."
		} else {
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
			$items | ForEach-Object {
				$n += 1
				try { $pc = [math]::floor($n*100/$cnt) } catch { $pc = -1 }
				if ($_.id) {
					$progress = @()
					Write-Progress -Id 1 -Activity "Enriching with Task Progress Information" -status "Getting progress on $($_.name) [$n of $cnt]" -PercentComplete $pc
					Get-ICUserTaskItemProgress -taskItemId $_.id -fields "createdOn","text" -order "createdOn desc" | ForEach-Object {
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
