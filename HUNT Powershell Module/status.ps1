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
		$where | % {
			$filter['where']['and'] += $_
		}
	}

	if ($All) {
		Write-Verbose "Getting All Jobs from Infocyte HUNT: $HuntServer"
	} else {
		Write-Verbose "Getting Active Jobs from Infocyte HUNT: $HuntServer"
		$filter['and']['where'] = @{ state = "active" }
	}
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

# Get Infocyte HUNT Jobs (Active jobs or all jobs)
function Get-ICUserActivity ([Switch]$NoLimit) {
	$url = ("$HuntServerAddress/api/useractivities")
	$filter =  @{
		order = "createdOn"
		limit = $resultlimit
		skip = 0
		where = @{ and = @() }
	}
	if ($where.count -gt 0) {
		$where | % {
			$filter['where']['and'] += $_
		}
	}
		Write-Verbose "Getting User Activity from Infocyte HUNT: $HuntServer"
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

# Get Infocyte HUNT User Tasks. These are the items in the task dropdown in the UI.
function Get-ICUserTasks ([String]$UserTaskId, [Switch]$Active,	[Switch]$All, [HashTable]$Where, [Switch]$NoLimit) {

	$filter =  @{
		order = "startedOn"
		limit = $resultlimit
		skip = 0
		where = @{ and = @() }
	}
	if ($where.count -gt 0) {
		$where | % {
			$filter['where']['and'] += $_
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
		Write-Verbose "Getting All Tasks from Infocyte HUNT: $HuntServer"
	} else {
		Write-Verbose "Getting Active Tasks from Infocyte HUNT: $HuntServer"
		$filter['where'] = @{ status = "Active" }
	}

	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

function Get-ICUserTaskItems {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true, Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$UserTaskId,

		[Switch]$Detailed,

		[HashTable]$Where,

		[Switch]$NoLimit
	)

	$filter =  @{
		limit = $resultlimit
		skip = 0
		where = @{
			and = @( @{ userTaskId = $UserTaskId } )
		}
	}
	if ($where.count -gt 0) {
		$where | % {
			$filter['where']['and'] += $_
		}
	}

	Write-Verbose "Getting All User Task Items from Infocyte HUNT: $HuntServer"
	$url = ("$HuntServerAddress/api/userTaskItems")
	if ($Detailed) {
		# TODO
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
		order = @("createdOn asc", "id")
		limit = $resultlimit
		skip = 0
		where = @{
			and = @( @{ taskItemId = $taskItemId} )
		}
	}
	if ($where.count -gt 0) {
		$where | % {
			$filter['where']['and'] += $_
		}
	}
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}
