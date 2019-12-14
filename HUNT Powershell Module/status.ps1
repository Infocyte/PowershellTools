
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

		[Switch]$Active,
		[Switch]$IncludeArchived,

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
			if ($IncludeArchived) {
				Write-Verbose "Getting All User Tasks"
			} else {
				Write-Verbose "Getting Active User Tasks"
				$endpoint += "/active"
			}
			if ($Active) {
				Write-Verbose "Filtering for Running Tasks Only."
				$where['status'] = "Active"
			}
		}

		Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}

function Get-ICUserTaskItem {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
		[alias('id')]
		[String]$userTaskId,

		[Switch]$IncludeProgress,

		[parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
		[String[]]$order = "updatedOn Desc",
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$Endpoint = "userTaskItems"
		if ($_.id -AND $_.userTaskId) {
			# disambuguation
			$where['userTaskId'] = $_.userTaskId
		} else {
			$where['userTaskId'] = $userTaskId
		}

		Write-Verbose "Getting All UserTaskItems with userTaskId $userTaskId."

		if ($IncludeProgress -AND (-NOT $CountOnly)) {
			$items = Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit
			$items | foreach {
				if ($_.id) {
					$progress = @()
					Get-ICUserTaskItemProgress -taskItemId $_.id | foreach { $progress += "$($_.createdOn) $($_.text)" }
					$_ | Add-Member -MemberType "NoteProperty" -name "progress" -value $progress
				}
			}
			Write-Output $items
		} else {
			Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
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
		Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
	}
}
