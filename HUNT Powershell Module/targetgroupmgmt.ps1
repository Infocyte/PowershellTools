# Setup APIs
function New-ICTargetGroup {
  param(
    [parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]$Name,

	[parameter(Mandatory=$false, Position=1)]
    [String]$ControllerGroupId
  )

  if (-NOT $ControllerGroupId) {
    $g = Get-ICControllerGroup
    if (($g.id.count -gt 1) -AND (-NOT $ControllerGroupId)) {
        Write-Error "More than one Controller Group. Please specify ControllerGroupId."
    }
    $ControllerGroupId = $g.id
  }

  $Endpoint = "targets"
  $body = @{
    name = $Name
	controllerGroupId = $ControllerGroupId
  }
  Write-Host "Creating new target group: $Name [$HuntServerAddress/api/$Endpoint]"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method 'POST'
}

function New-ICControllerGroup {
  param(
    [parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]$Name
  )

  $Endpoint = "controllergroups"
  $body = @{
    name = $Name;
  }
  Write-Host "Creating new Controller Group: $Name [$HuntServerAddress/api/$Endpoint]"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method 'POST'
}

function Get-ICTargetGroup ([String]$TargetGroupId) {
  $Endpoint = "targets"
  $filter =  @{
    order = @("name", "id")
    limit = $resultlimit
    skip = 0
  }
  if ($TargetGroupId) {
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true | where { $_.id -eq $TargetGroupId}
  } else {
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
  }
}

function Get-ICControllerGroup ([String]$ControllerGroupId) {
  $Endpoint = "controllergroups"
  $filter =  @{
    order = @("name", "id")
    limit = $resultlimit
    skip = 0
  }
  if ($TargetGroupId) {
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true | where { $_.id -eq $ControllerGroupId}
  } else {
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
  }
}


function Remove-ICTargetGroup {
  param(
    [parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]$TargetGroupId
  )

  $Endpoint = "targets/$TargetGroupId"
  Write-Warning "Removing target group [$HuntServerAddress/api/$Endpoint]."
  Write-Warning "This will remove access to all scan data within this target group and is only reversible for the next 7 days"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -method 'DELETE'
}

function Remove-ICControllerGroup {
  param(
    [parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]$ControllerGroupId
  )

  $Endpoint = "controllergroups/$ControllerGroupId"
  Write-Warning "Removing Controller Group [$HuntServerAddress/api/$Endpoint]."
 # Write-Warning "This will remove access to all scan data within this target group and is only reversible for the next 7 days"
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
  $body = @{
    data = $data
  }
  Write-Host "Adding new Credential $Name [$($Cred.Username)] to the Credential Manager"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}

function Get-ICCredential ($CredentialId) {
	Write-Verbose "Getting Credential Objects from Infocyte HUNT: $HuntServerAddress"
  $Endpoint = "credentials"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  if ($CredentialId) {
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter | where { $_.id -eq $CredentialId }
  } else {
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter
  }
}

function Remove-ICCredential {
  param(
    [parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [String]$CredentialId
  )

  $Endpoint = "credentials/$CredentialId"
  Write-Warning "Removing credential [$HuntServerAddress/api/$Endpoint]."
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -method 'DELETE'

}


function Get-ICAddress ([String]$TargetGroupId, [HashTable]$Where, [Switch]$NoLimit) {
  $Endpoint = "Addresses"
	$filter =  @{
		order = "lastAccessedOn"
		limit = $resultlimit
		skip = 0
    where = @{
      and = @()
    }
	}
  if ($where.count -gt 0) {
    $where.GetEnumerator() | % {
      $filter['where']['and'] += @{ $($_.key) = $($_.value) }
    }
  }

  if ($TargetGroupId) {
    $filter['where']['and'] += @{ targetId = $TargetGroupId }
    Write-Verbose "Getting all addresses from TargetGroup $TargetGroupId"
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Remove-ICAddress {
  Param(
    [ValidateNotNullorEmpty()]
    [String]$TargetGroupId
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


function Get-ICScan ([String]$TargetGroupId, $TargetGroupName, [HashTable]$Where, [Switch]$NoLimit) {
  $Endpoint = "IntegrationScans"
  $filter =  @{
    order = "scanCompletedOn desc"
    limit = $resultlimit
    skip = 0
    where = @{
      and = @()
    }
  }
  if ($where.count -gt 0) {
    $where | % {
      $filter['where']['and'] += $_
    }
  }

  if ($TargetGroupId) {
    $tgname = (Get-ICTargetGroup -TargetGroupId $TargetGroupId).name
    $filter['where']['and'] += @{ targetList = $tgname }
    Write-Verbose "Getting Scans against Target Group $TargetGroup [$TargetGroupId] from $HuntServerAddress"
  } elseif ($TargetGroupName) {
      $filter['where']['and'] += @{ targetList = $TargetGroupName }
      Write-Verbose "Getting Scans against $TargetGroupName from $HuntServerAddress"
  } else {
    Write-Verbose "Getting Scans from $HuntServerAddress"
  }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Get-ICBox ([Switch]$Last90, [Switch]$Last7, [Switch]$Last30, [Switch]$IncludeDeleted, [Switch]$Global, [String]$targetGroupId, [Switch]$NoLimit) {
  $Endpoint = "Boxes"
  $filter =  @{
    limit = $resultlimit
    skip = 0
    where = @{ and = @() }
  }


  if ($Last90) {
    $filter.where['and'] += @{ name = "Last 90 days" }
  }
  elseif ($Last30) {
    $filter.where['and'] += @{ name = "Last 30 days" }
  }
  elseif ($Last7) {
    $filter.where['and'] += @{ name = "Last 7 days" }
  }

  if ($targetGroupId) {
    $filter.where['and'] += @{ targetId = $targetGroupId }
  }
  elseif ($Global) {
    $filter.where['and'] += @{ targetId = $null }
  }

  $boxes = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
  $TargetGroups = Get-ICTargetGroup
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
