
<#
There are times when customers will want to add supplemental flags or even change the labels of existing flags. The flagging system has been architected to allow any number of flags.

This note has instructions on Adding a Custom Flag, Modifying an Existing Flag, and Deleting an Existing Flag using Powershell and some methods of a PowerShell object called Flags that can be downloaded here.

Flag Model

The Flag model has four properties:

id	         This is a unique identifier in a UUID (GUID) format with hyphens.
name	       The name of the flag
color	       The Color of the flag, noting that the name has dependencies in the app.css stylesheet.
weight	     This affects the sort-order that flags will show up in.

The product ships with 4 defaults and two supplemental Colors that can be used. Further default Color options will follow in a subsequent product release. The Verified Good and Verified Bad flags are special and should not be deleted or modified as they affect reporting and other aspects of scoring or overridding scoring (in cases of False Positives)

	Verified Good	   green
	Probably Good	   blue
	Probably Bad	   yellow
	Verified Bad	   red
	Unassigned	     purple
	Unassigned	     teal
#>

# Currently unused
$FlagColors = @{
  COLOR_RED = 0
  COLOR_BLUE = 1
  COLOR_YELLOW = 2
  COLOR_GREEN = 3
  COLOR_TEAL = 4
  COLOR_PURPLE = 5
}

function Get-ICFlagColorCodes {
  Write-Host -ForegroundColor Red "red"
  Write-Host -ForegroundColor Blue "blue"
  Write-Host -ForegroundColor Yellow "yellow"
  Write-Host -ForegroundColor Green "green"
  Write-Host -ForegroundColor Cyan "teal"
  Write-Host -ForegroundColor Magenta "purple"
}

#
function New-ICFlag {
  Param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$FlagName,

    [parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$FlagColor,

    [parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [int]$FlagWeight
  )

	$Endpoint = "flags"
	Write-Host "Adding new flag with Color $FlagColor named $FlagName [Weight: $FlagWeight]"
	$body = @{
  	name = $FlagName
		color = $FlagColor
		weight = $FlagWeight
  }
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}


function Get-ICFlags ([String]$FlagId) {
  if ($FlagId) {
    $Endpoint = "flags/$FlagId"
  } else {
    $Endpoint = "flags"
  }
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -method GET
}

function Update-ICFlag ([String]$FlagId, [String]$FlagName=$null, [String]$FlagColor, [int]$FlagWeight) {
  $Endpoint = "flags/$FlagId"
	Write-Verbose "Updating flag $FlagId with Color: $FlagColor, named: $FlagName, Weight: $FlagWeight"
	$body = @{}
  $n = 0
  if ($FlagName) { $body['name'] = $FlagName; $n+=1 }
  if ($FlagColor) { $body['color'] = $FlagColor; $n+=1 }
  if ($FlagWeight) { $body['weight'] = $FlagWeight; $n+=1 }
  if ($n -eq 0) { Write-Error "Not Enough Parameters"; return}
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method PUT
}

function Remove-ICFlag {
  Param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$FlagId
  )
  $Flags = get-ICFlags | where { ($_.FlagWeight -eq 0) -OR ($_.FlagWeight -eq 10)}
  if ($Flags) { Write-Warning "Cannot Delete Verified Good or Verified Bad flags. They are a special case and would break the user interface" }
  $flag = Get-Flags -FlagId $FlagId
  Write-Host "Removing $($Flag.name) [$($Flag.color)] with flagId '$FlagId'"
  $Endpoint = "flags/$FlagId"
  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -method DELETE
}

function Add-ICComment {
  Param(
    [parameter(Position=0, Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$Id,

    [parameter(Position=1, Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$Text
  )

  $Endpoint = "userComments"
	Write-Host "Adding new comment to item with id $id"
  $body = @{
    relatedId = $Id
    value = $Text
  }
	_ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}
