# Setup APIs
function New-ICTargetGroup {
  param(
    [parameter(Mandatory=$true, Position=0)]
    [String]
    $Name
  )

  $Endpoint = "targets"
  $body = @{
    name = $Name
  }
  Write-Verbose "Creating new target group: $Name [$HuntServerAddress/api/$Endpoint]"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method 'POST'
}

function Get-ICTargetGroups {
  $Endpoint = "targets"
  $filter =  @{
    order = @("name", "id")
    limit = $resultlimit
    skip = 0
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
}

function Remove-ICTargetGroup {
  param(
    [parameter(Mandatory=$true, Position=0)]
    [String]
    $TargetGroupId
  )

  $Endpoint = "targets/$TargetGroupId"
  Write-Warning "Removing target group [$HuntServerAddress/api/$Endpoint]."
  Write-Warning "This will remove access to all scan data within this target group and is only reversible for the next 7 days"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -method 'DELETE'
}

function New-ICCredential {
  Param(
    [parameter(Mandatory=$True, Position=0)]
    [String]
    $Name,

    [parameter(Mandatory=$True)]
    [PSCredential]$Cred
  )

  $Endpoint = "credentials"
  $data = @{
    name = $Name
    username = $Cred.Username
    password = $Cred.GetNetworkCredential().Password
  }
  Write-Verbose "Adding new Credential to the Credential Manager"
  $body = @{
    data = $data
  }
	#$body = '{"type":"login","name":"'+$Name+'","username":'+$user+',"password":"'+$pass+'"}'
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Get-ICCredentials {
	Write-Verbose "Getting Credential Objects from Infocyte HUNT: $HuntServerAddress"
  $Endpoint = "credentials"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter
}

function New-ICQuery {
  Param(
    [parameter(Mandatory=$True)]
    [String]
    $TargetGroupId,

    [String]
    $credentialId = $null,

    [String]
    $sshCredentialId = $null,

    [ValidateNotNullorEmpty]
    [String]
    $query
    )

  if (-NOT ($credentialId -AND $sshCredentialId)) {
    Throw "CredentialId and/or sshCredentialId must be specified"
  }
	Write-Verbose "Creating new Query in TargetGroup $TargetGroupId ($query) using username $($Cred.Username)"
  $Endpoint = "queries"
  $data = @{
    value = $query
    targetId = $TargetGroupId
  }
  if ($credentialId) {
    $data['credentialId'] = $CredentialId
  }
  if ($sshCredentialId) {
    $data['sshCredential'] = $sshCredentialId
  }
  $body = @{
    data = $data
  }
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Get-ICQueries ([String]$TargetGroupId) {
  $Endpoint = "queries"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  if ($TargetGroupId) {
    $filter['where'] = @{ targetId = $TargetGroupId }
    Write-Verbose "Getting Queries for Target Group Id: $TargetGroupId"
  }
  #Write-Verbose "Getting all Queries from TargetGroup $TargetGroup"
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
}

function Get-ICAddresses ([String]$TargetGroupId, [Switch]$NoLimit) {
  $Endpoint = "Addresses"
	$filter =  @{
		order = "lastAccessedOn"
		limit = $resultlimit
		skip = 0
	}
  if ($TargetGroupId) {
    $filter['where'] = @{ targetid = $TargetGroupId }
    Write-Verbose "Getting all addresses from TargetGroup $TargetGroupId"
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Remove-ICAddresses {
  Param(
    [ValidateNotNullorEmpty]
    [String]
    $TargetGroupId
  )

	Write-Warning "Clearing all Addresses from TargetGroup $TargetGroupId"
  $Endpoint = "Addresses"
  $where = @{
    targetId = $TargetGroupId
  }
  $body = @{
    where = $where
  }
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method DELETE
}

function Get-ICScans ([String]$TargetGroupId, $TargetGroupName, [Switch]$NoLimit) {
  $Endpoint = "IntegrationScans"
  $filter =  @{
    order = "scanCompletedOn desc"
    limit = $resultlimit
    skip = 0
  }
  if ($TargetGroupId) {
    $tgname = (Get-ICTargetGroups | where { $_.id -eq $TargetGroupId }).name
    $filter['where'] = @{ targetList = $tgname }
    Write-Verbose "Getting Scans against Target Group $TargetGroup [$TargetGroupId] from $HuntServerAddress"
  } elseif ($TargetGroupName) {
      $filter['where'] = @{ targetList = $TargetGroupName }
      Write-Verbose "Getting Scans against $TargetGroupName from $HuntServerAddress"
  } else {
    Write-Verbose "Getting Scans from $HuntServerAddress"
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Get-ICBoxes ([Switch]$Last90, [Switch]$Last7, [Switch]$Last30, [Switch]$IncludeDeleted, [String]$targetGroupId, [Switch]$NoLimit) {
  $Endpoint = "Boxes"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  $where = @{}

  if ($Last90) { $where['name'] = "Last 90 days" }
  elseif ($Last30) { $where['name'] = "Last 30 days" }
  elseif ($Last7) { $where['name'] = "Last 7 days" }
  if ($targetGroupId) { $where['targetId'] = $targetGroupId }
  elseif ($where['name'] -AND (-NOT $targetGroupId)) { $where['targetId'] = $null }
  $filter['where'] = $where
  $boxes = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
  $TargetGroups = Get-ICTargetGroups
  $boxes | % {
    if ($_.targetId) {
       $tgid = $_.targetId
       $tg = $TargetGroups | where { $_.id -eq $tgid }
       if ($tg) {
         $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value $tg.name
       } else {
         $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value "Deleted"
       }
    } else {
      $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value "All"
    }
  }
  if ($IncludeDeleted) {
    $boxes
  } else {
    $boxes | where { $_.targetGroup -ne "Deleted" }
  }

}
