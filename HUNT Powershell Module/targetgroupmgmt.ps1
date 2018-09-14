# Setup APIs
function New-ICTargetGroup ([String]$Name) {
  $Endpoint = "targets"
  $body = @{
    data = @{ name = $Name }
  }
  Write-Verbose "Creating new target group: $Name [$HuntServerAddress/api/$Endpoint]"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Get-ICTargetGroups {
  $Endpoint = "targets"
  $filter =  @{
    order = @("name", "id")
    limit = 1000
    skip = 0
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter
}

function New-ICCredential ([String]$Name, [PSCredential]$Cred) {
  $Endpoint = "credentials"
  $data = @{
    name = $Name
    username = $Cred.Username
    password = $Cred.GetNetworkCredential().Password
  }
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
    limit = 1000
    skip = 0
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter
}

function New-ICQuery ([String]$TargetGroupId, [String]$credentialId = $null, [String]$sshCredentialId = $null, [String]$query) {
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
    limit = 1000
    skip = 0
  }
  if ($TargetGroupId) {
    $filter['where'] = @{ targetId = $TargetGroupId }
    Write-Verbose "Getting Queries for Target Group Id: $TargetGroupId"
  }
  #Write-Verbose "Getting all Queries from TargetGroup $TargetGroup"
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter
}

function Get-ICAddresses ([String]$TargetGroupId, [Switch]$NoLimit) {
  $Endpoint = "Addresses"
	$filter =  @{
		order = "lastAccessedOn"
		limit = 1000
		skip = 0
	}
  if ($TargetGroupId) {
    $filter['where'] = @{ targetid = $TargetGroupId }
    Write-Verbose "Getting all addresses from TargetGroup $TargetGroupId"
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Remove-ICAddresses ($TargetGroupId) {
	Write-Verbose "Clearing all resolved hosts from TargetGroup $TargetGroupId"
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
    limit = 1000
    skip = 0
  }
  if ($TargetGroupName) {
    $filter['where'] = @{ targetList = $TargetGroupName }
    Write-Verbose "Getting Scans against $TargetGroupName from $HuntServerAddress"
  } elseif ($TargetGroupId) {
    $tgname = (Get-ICTargetGroup | where { $_.id -eq $TargetGroupId }).name
    $filter['where'] = @{ targetList = $tgname }
    Write-Verbose "Getting Scans against Target Group $TargetGroup [$TargetGroupId] from $HuntServerAddress"
  } else {
    Write-Verbose "Getting Scans from $HuntServerAddress"
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Get-ICBoxes ([Switch]$AllScans, [Switch]$Last7, [Switch]$Last30, [String]$targetGroupId, [Switch]$NoLimit) {
  $Endpoint = "Boxes"
  $filter =  @{
    limit = 1000
    skip = 0
  }
  $where = @{}

  if ($AllScans) { $where['name'] = "All scans" }
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
         $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value "Old"
       }
    } else {
      $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value "All"
    }
  }
  $boxes | where { $_.targetGroup -ne "Old" }
}
