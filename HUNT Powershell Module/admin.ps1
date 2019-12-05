

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


function Get-ICFlag ([String]$FlagId) {
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
    if ($n -eq 0) { Write-Error "Not Enough Parameters"; return }
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

function Get-ICExtension {
    Param(
        [parameter(Position=0)]
        [String]$Id,

        [Switch]$IncludeBody,

        [Switch]$NoLimit
    )

    if ($Id) {
        $Endpoint = "extensions/$Id"
        if ($IncludeBody) {
            $Endpoint += "/latestVersion"
        }
    } else {
        $Endpoint = "extensions"
    }
    _ICRestMethod -url $HuntServerAddress/api/$Endpoint -method GET -NoLimit:$NoLimit
}


function New-ICExtension {
    Param(
        [parameter(mandatory=$false)]
        [String]$Id,

        [parameter(mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [String]$Name,

        [parameter(mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [String]$ScriptBody,

        [parameter(mandatory=$true)]
        [ValidateSet("collection","action")]
        [String]$Type
    )

    $Endpoint = "extensions"
    $body = @{
        name = $Name
        type = $Type
        body = $ScriptBody
        active = $true
    }
    if ($Id) {
        Write-Host "Updating Extension: $name"
        $body["id"] = $Id
    } else {
        Write-Host "Adding new Extension named: $name"
    }

    _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method POST
}
