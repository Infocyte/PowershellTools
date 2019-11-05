
# Status and Progress APIs

# Get Infocyte HUNT Jobs (Active jobs or all jobs)
function Get-ICJobs ([Switch]$All, [HashTable]$Where, [Switch]$NoLimit) {
	$url = ("$HuntServerAddress/api/jobs")
	$filter =  @{
		order = "createdOn"
		limit = $resultlimit
		skip = 0
		where = @{ and = @() }
	}

	if ($where.count -gt 0) {
		$where.GetEnumerator() | % {
			$filter['where']['and'] += @{ $($_.key) = $($_.value) }
		}
	}

	if ($All) {
		Write-Verbose "Getting All Jobs from Infocyte HUNT: $HuntServer"
	} else {
		Write-Verbose "Getting Active Jobs from Infocyte HUNT: $HuntServer"
		$filter['where']['and'] = @{ state = "active" }
	}
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

# Get Infocyte HUNT User Audit Logs
function Get-ICUserAuditLogs ([Switch]$NoLimit, [HashTable]$Where) {
	$url = ("$HuntServerAddress/api/useractivities")
	$filter =  @{
		order = "createdOn"
		limit = $resultlimit
		skip = 0
		where = @{ and = @() }
	}
	if ($where.count -gt 0) {
		$where.GetEnumerator() | % {
			$filter['where']['and'] += @{ $($_.key) = $($_.value) }
		}
	}
		Write-Verbose "Getting User Activity Logs from Infocyte HUNT: $HuntServer"
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

# Get Infocyte HUNT User Tasks. These are the items in the task dropdown in the UI.
function Get-ICUserTask {
	[cmdletbinding()]
	param(
		[String]$UserTaskId,
		[Switch]$Active,
		[Switch]$All,
		[HashTable]$Where,
		[Switch]$NoLimit
	)

	$filter =  @{
		order = "endedOn"
		limit = $resultlimit
		skip = 0
		where = @{ and = @() }
	}
	if ($where.count -gt 0) {
		$where.GetEnumerator() | % {
			$filter['where']['and'] += @{ $($_.key) = $($_.value) }
		}
	}

	if ($UserTaskId) {
		$url = ("$HuntServerAddress/api/usertasks/$UserTaskId")
	} else {
		if ($All) {
			Write-Verbose "Getting All User Tasks from Infocyte HUNT: $HuntServer"
			$url = ("$HuntServerAddress/api/usertasks")
		} else {
			Write-Verbose "Getting Active Tasks from Infocyte HUNT: $HuntServer"
			$url = ("$HuntServerAddress/api/usertasks/active")
		}
	}
	if ($Active) {
		Write-Verbose "Getting Running Tasks from Infocyte HUNT: $HuntServer"
		$filter['where']['and'] += @{ status = "Active" }
	}

	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

function Get-ICUserTaskItem {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$UserTaskId,

		[Switch]$IncludeProgress,

		[HashTable]$Where,

		[Switch]$NoLimit
	)

	$filter =  @{
		limit = $resultlimit
		skip = 0
		order = "updatedOn"
		where = @{
			and = @( @{ userTaskId = $UserTaskId } )
		}
	}
	if ($where.count -gt 0) {
		$where.GetEnumerator() | % {
			$filter['where']['and'] += @{ $($_.key) = $($_.value) }
		}
	}

	Write-Verbose "Getting All User Task Items from Infocyte HUNT: $HuntServer"
	$url = ("$HuntServerAddress/api/userTaskItems")
	if ($IncludeProgress) {
		$items = _ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
		$items | foreach {
			if ($_.id) {
				$progress = @()
				Get-ICUserTaskItemProgress -taskItemId $_.id | foreach { $progress += "$($_.createdOn) $($_.text)" }
				$_ | Add-Member -MemberType "NoteProperty" -name "progress" -value $progress
			}
		}
		$items
	} else {
		_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
	}
}

function Get-ICUserTaskItemProgress {
	param(
		[parameter(Mandatory=$true, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$taskItemId,
		[HashTable]$Where,
		[Switch]$NoLimit
	)

	$url = ("$HuntServerAddress/api/userTaskItemProgresses")
	$filter =  @{
		order = @("createdOn desc", "id")
		limit = $resultlimit
		skip = 0
		where = @{
			and = @( @{ taskItemId = $taskItemId} )
		}
	}
	if ($where.count -gt 0) {
		$where.GetEnumerator() | % {
			$filter['where']['and'] += @{ $($_.key) = $($_.value) }
		}
	}
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}
