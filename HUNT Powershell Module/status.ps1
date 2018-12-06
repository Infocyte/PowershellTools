# Status and Progress APIs

# Get Infocyte HUNT Jobs (Active jobs or all jobs)
function Get-ICJobs ([Switch]$Active, [Switch]$NoLimit){
	$url = ("$HuntServerAddress/api/jobs")
	$filter =  @{
		order = "createdOn"
		limit = $resultlimit
		skip = 0
	}
	if ($Active) {
		Write-Verbose "Getting Active Jobs from Infocyte HUNT: $HuntServer"
		$filter['where'] = @{ state = "active" }
	} else {
		Write-Verbose "Getting All Jobs from Infocyte HUNT: $HuntServer"
	}
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

# Get Infocyte HUNT Jobs (Active jobs or all jobs)
function Get-ICUserActivity ([Switch]$NoLimit){
	$url = ("$HuntServerAddress/api/useractivities")
	$filter =  @{
		order = "createdOn"
		limit = $resultlimit
		skip = 0
	}
		Write-Verbose "Getting User Activity from Infocyte HUNT: $HuntServer"
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

# Get Infocyte HUNT User Tasks. These are the items in the task dropdown in the UI.
function Get-ICUserTasks ([Switch]$Active, [Switch]$IncludeArchived, [Switch]$NoLimit){
	if ($IncludeArchived) {
		Write-Verbose "Getting All User Tasks from Infocyte HUNT: $HuntServer"
		$url = ("$HuntServerAddress/api/usertasks")
	} else {
		$url = ("$HuntServerAddress/api/usertasks/active")
	}
	$filter =  @{
		order = "startedOn"
		limit = $resultlimit
		skip = 0
	}
	if ($Active) {
		Write-Verbose "Getting Active Tasks from Infocyte HUNT: $HuntServer"
		$filter['where'] = @{ status = "Active" }
	} else {
		Write-Verbose "Getting All Tasks from Infocyte HUNT: $HuntServer"
	}
	_ICGetMethod -url $url -filter $filter -NoLimit:$NoLimit
}

# Get the scanId of the last scan that was kicked off
function Get-ICLastScanid {
	Write-Verbose "Getting last scanId from Infocyte HUNT: $HuntServerAddress"
	$url = ("$HuntServerAddress/api/Scans")
	$filter =  @{
		order = "startedOn desc"
		limit = 1
		skip = 0
	}
	$body = @{
		access_token = $Global:ICToken
		filter = $filter | ConvertTo-JSON
	}

	try {
		$Objects = Invoke-RestMethod $url -body $body -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($Objects) {
		return $Objects.id
	} else {
		return $null
	}
}
