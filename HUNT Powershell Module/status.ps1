
# Status and Progress APIs

# Get Infocyte HUNT Jobs (Active jobs or all jobs)
function Get-ICJob {
	[cmdletbinding()]
	param(
		[parameter(ValueFromPipelineByPropertyName)]
		[alias('jobId')]
		[String]$Id,

		[Switch]$All,

		[HashTable]$where=@{},
		[String[]]$order = "createdOn",
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$endpoint = 'jobs'
		if ($Id) {
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

		[HashTable]$where=@{},
		[String[]]$order = "createdOn",
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)
	PROCESS {
		$endpoint = 'useractivities'
		if ($Id) {
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

		[HashTable]$where=@{},
		[String[]]$order = "endedOn",
		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$endpoint = "usertasks"
		if ($Id) {
			$endpoint += "/$Id"
		} else {
			if ($IncludeArchived) {
				Write-Verbose "Getting All User Tasks"
			} else {
				Write-Verbose "Getting Active User Tasks"
				$endpoint += "/active"
			}
		}
		if ($Active) {
			Write-Verbose "Filtering for Running Tasks Only."
			$where['status'] = "Active"
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

		[HashTable]$where=@{},

		[String[]]$order = "updatedOn",

		[Switch]$NoLimit,
		[Switch]$CountOnly
	)

	PROCESS {
		$Endpoint = "userTaskItems"
		if ($_.id -AND $_.userTaskId) {
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

		[HashTable]$where=@{},
		[String[]]$order = @("createdOn desc", "id"),
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
