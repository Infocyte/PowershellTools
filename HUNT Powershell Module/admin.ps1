
function Get-ICFlagColors {
    Write-Host -ForegroundColor Red "red"
    Write-Host -ForegroundColor Blue "blue"
    Write-Host -ForegroundColor Yellow "yellow"
    Write-Host -ForegroundColor Green "green"
    Write-Host -ForegroundColor Cyan "teal"
    Write-Host -ForegroundColor Magenta "purple"
}

#
function New-ICFlag {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [alias('FlagName')]
        [String]$Name,

        [parameter(Mandatory=$true)]
        [ValidateSet("red","blue","yellow","green", "teal", "purple")]
        [alias('FlagColor')]
        [String]$Color,

        [parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [alias('FlagWeight')]
        [int]$Weight
    )

    $Endpoint = "flags"
    Write-Host "Adding new flag with Color $Color named $Name [Weight: $Weight]"
    $body = @{
    	name = $Name
    	color = $Color
    	weight = $Weight
    }
    $f = Get-ICFlag -where @{ name = $Name; deleted = $False }
    if ($f) {
        Write-Error "There is already a flag named $Name"
    } else {
        Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
    }
}


function Get-ICFlag {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline=$true)]
        [alias('flagId')]
        [String]$Id,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order,
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($Id) {
            $Endpoint = "flags/$Id"
        } else {
            $Endpoint = "flags"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Update-ICFlag  {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [alias('flagId')]
        [String]$id,

        [alias('FlagName')]
        [String]$Name=$null,

        [alias('FlagColor')]
        [ValidateSet("red","blue","yellow","green", "teal", "purple", $null)]
        [String]$Color,

        [alias('FlagWeight')]
        [int]$Weight
    )
    PROCESS {
        $body = @{}
        $n = 0
        $Endpoint = "flags/$Id"
        $obj = Get-ICFlag -id $Id
        if (-NOT $obj) {
            Write-Error "Flag not found with id: $id"
        }
        if ($Name) { $body['name'] = $Name; $n+=1 }
        if ($Color) { $body['color'] = $Color; $n+=1 }
        if ($Weight) { $body['weight'] = $Weight; $n+=1 }
        if ($n -eq 0) { Write-Error "Not Enough Parameters"; return }

        Write-Verbose "Updating flag $Id with:`n$($body|convertto-json)"
        if ($PSCmdlet.ShouldProcess($($obj.name), "Will update flag $($obj.name) [$Id]")) {
            Invoke-ICAPI -Endpoint $Endpoint -body $body -method PUT
        }
    }
}

function Remove-ICFlag {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullorEmpty()]
        [alias('flagId')]
        [String]$id
    )
    PROCESS {
        $Endpoint = "flags/$Id"
        $obj = Get-Flags -Id $Id -where { }
        if ($obj) {
            if ($obj | where { ($_.name -eq "Verified Good") -OR ($_.name -eq "Verified Bad")}) {
                Write-Warning "Cannot Delete 'Verified Good' or 'Verified Bad' flags. They are a special case and would break the user interface"
                return
            }
            if ($PSCmdlet.ShouldProcess($obj.name, "Will remove $($obj.name) [$($obj.color)] with flagId '$Id'")) {
                Write-Host "Removing $($obj.name) [$($obj.color)] with flagId '$Id'"
                Invoke-ICAPI -Endpoint $Endpoint -method DELETE
            }
        } else {
            Write-Error "No Agent with id '$Id' exists."
        }
    }
}

function Add-ICComment {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline)]
        [ValidateNotNullorEmpty()]
        [String]$Id,

        [parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [String]$Text
    )

    PROCESS {
        $Endpoint = "userComments"
        Write-Host "Adding new comment to item with id $id"
        $body = @{
            relatedId = $Id
            value = $Text
        }
        Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
    }
}

function Get-ICExtension {
    [cmdletbinding()]
    Param(
        [parameter(ValueFromPipeline=$true)]
        [alias('extensionId')]
        [String]$Id,

        [Switch]$IncludeBody,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order,

        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($Id) {
            $Endpoint = "extensions/$Id"
            $CountOnly = $false
            $order = $null
            if ($IncludeBody) {
                $Endpoint += "/latestVersion"
            }
        } else {
            $Endpoint = "extensions"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function New-ICExtension {
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ParameterSetName = 'Path',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [alias('FullName')]
        [string]$Path, # <paths of the survey results (.bz2) files to upload>

        [parameter(
            mandatory = $true,
            ParameterSetName  = 'String'
        )]
        [ValidateNotNullorEmpty()]
        [String]$ScriptBody,

        [parameter(
            mandatory=$false,
            ParameterSetName = 'Path'
        )]
        [parameter(
            mandatory=$true,
            ParameterSetName  = 'String'
        )]
        [ValidateNotNullorEmpty()]
        [String]$Name,

        [parameter()]
        [String]$Description,

        [parameter()]
        [ValidateSet("collection","action")]
        [String]$Type='action',

        [Switch]$Active
    )

    PROCESS {
        $Endpoint = "extensions"
        $body = @{
            type = $Type
        }
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Write-Verbose "Testing path: $Path"
            if (Test-Path $Path) {
                $scriptfile = Get-Item $Path
                Write-Verbose "Using filename for Extension Name."
                $body['name'] = $scriptfile.BaseName
                $ScriptBody = Get-Content $Path -Raw
            } else {
                Write-Error "$Path does not exist!"
                return
            }
        } else {
            $body['name'] = $Name
        }
        $body['body'] = $ScriptBody
        if ($Active) {
            $body['active'] = $true
        }
        if ($Description) {
            $body['description'] = $Description
        }
        Write-Host "Adding new Extension named: $($body['name'])"
        $ext = Get-ICExtension -where @{ name = $($body['name']); deleted = $False }
        if ($ext) {
            Write-Error "There is already an extension named $($body['name'])"
        } else {
            Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
        }
    }

}

function Update-ICExtension {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(
            mandatory=$false,
            ParameterSetName = 'Path'
        )]
        [parameter(
            mandatory=$true,
            ParameterSetName  = 'String'
        )]
        [alias('extensionId')]
        [String]$Id,

        [parameter(
            Mandatory = $true,
            ParameterSetName = 'Path',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [alias('FullName')]
        [string]$Path, # <paths of the survey results (.bz2) files to upload>

        [parameter(
            mandatory = $true,
            ParameterSetName  = 'String'
        )]
        [ValidateNotNullorEmpty()]
        [String]$ScriptBody,

        [parameter(
            mandatory=$false,
            ParameterSetName = 'Path'
        )]
        [parameter(
            mandatory=$false,
            ParameterSetName  = 'String'
        )]
        [ValidateNotNullorEmpty()]
        [String]$Name,

        [parameter()]
        [String]$Description,

        [parameter()]
        [ValidateSet("collection","action")]
        [String]$Type,

        [Switch]$Active
    )

    PROCESS {
        $Endpoint = "extensions"
        $body = @{}
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Write-Verbose "Testing path: $Path"
            if (Test-Path $Path) {
                $scriptfile = Get-Item $Path
                $ScriptBody = Get-Content $Path -Raw
            } else {
                Write-Error "$Path does not exist!"
                return
            }
        } else {
            $body['name'] = $Name
        }
        $obj = Get-ICExtension -id $Id
        if ($obj) {
            Write-Verbose "Extension found: `n$($obj | converto-json)"
        } else {
            Write-Error "Extension with id $id not found!"
            return
        }

        if (-NOT $Id) {
            Write-Verbose "Using existing Id for Extension Id."
            $body['name'] = $scriptfile.BaseName
        }

        if (-NOT $Name) {
            Write-Verbose "Using filename for Extension Name."
            $body['name'] = $scriptfile.BaseName
        }

        if ($Name) { $b['name'] = $Name } else { $b['name'] = $ext.name}
        if ($Body) { $b['body'] = $Body } else { $b['body'] = $ext.body }
        if ($Description) { $b['description'] = $Description } else { $b['description'] = $ext.description }
        if ($Type) { $b['type'] = $Type } else { $b['type'] = $ext.type }
        if ($Active) { $b['active'] = $Active } else { $b['active'] = $ext.active }

        Write-Host "Updating Extension: $($obj.name) [$Id] with `n$($b|convertto-json)"
        if ($PSCmdlet.ShouldProcess($($obj.name), "Will update extension $($obj.name) [$Id]")) {

            Invoke-ICAPI -Endpoint $Endpoint -body $b -method POST
        }
    }
}

function Remove-ICExtension {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullorEmpty()]
        [alias('extensionId')]
        [String]$Id
    )
    PROCESS {
        $Endpoint = "extensions/$Id"
        $ext = Get-ICExtension -id $Id
        if (-NOT $ext) {
            Write-Error "Extension with id $id not found!"
            return
        }
        if ($PSCmdlet.ShouldProcess($Id, "Will remove $($ext.name) with extensionId '$Id'")) {
            Write-Host "Removing $($ext.name) with extensionId '$Id'"
            Invoke-ICAPI -Endpoint $Endpoint -method DELETE
        }
    }
}
