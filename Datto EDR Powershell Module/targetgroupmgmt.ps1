# Setup APIs
function New-ICTargetGroup {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        [parameter(Mandatory=$false)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$ControllerGroupId,

        [parameter(HelpMessage="Use first available ControllerGroupId if not provided.")]
        [Switch]$Force
    )

    $Endpoint = "targets"
    $body = @{
        name = $Name
    }

    if ($ControllerGroupId) {
        $body['controllerGroupId'] = $ControllerGroupId
    } else {
        $cg = Get-ICControllerGroup
        if ($cg.count -gt 1 -AND $Force) {
            $body['controllerGroupId'] = ($cg | Sort-Object createdOn -Desc)[0].id
        }
        elseif ($cg.count -gt 1) {
            Write-Error "More than one Controller Group. Recommend specifying a ControllerGroupId. Available Options: `n$($cg | Format-Table -auto | Out-String)"
            return
        } else {
            $body['controllerGroupId'] = $cg.id
        }
    }

    $tg = Get-ICTargetGroup -where @{ name = $Name }
    if ($tg) {
        Write-Error "There is already a Target Group named $Name"
    } else {
        Write-Verbose "Creating new target group: $Name"
        Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
    }
}

function Get-ICTargetGroup {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('TargetGroupId','targetId')]
        [String]$Id,

        [String]$Name,

        [Switch]$IncludeArchive,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "targets"

        if ($Id) {
            $Endpoint += "/$Id"
        } elseif ($Name) {
            $where = @{ name = $Name }
        }

        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICTargetGroup {
    [cmdletbinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('TargetGroupId','targetId')]
        [String]$Id,

        [Switch]$IncludeArchive
    )

    PROCESS {
        $obj = Get-ICTargetGroup -id $Id
        if (-NOT $obj) {
            Write-Error "No target group with id '$Id' exists."
            return
        }
        if ($IncludeArchive) {
            $Endpoint = "TargetsArchive/$Id"
        } else {
            $Endpoint = "targets/$Id"
        }

        Write-Warning "Careful. This will remove access to all scan data within this target group and is only reversible for the next 7 days"
        if ($PSCmdlet.ShouldProcess($tg.name, "Will remove target group: $($obj.name) [$Id]")) {
            Write-Warning "Removing target group: $($obj.name) [$Id]."
            Invoke-ICAPI -Endpoint $Endpoint -method 'DELETE'
        }
    }
}

function Get-ICAddress {
    [cmdletbinding()]
    param(
        [parameter()]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('addressId')]
        [String]$Id,

        [parameter(ValueFromPipeLine=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('targetId')]
        [String]$TargetGroupId,

        [String]$TargetGroupName,
        
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "Addresses"

        if ($Id) {
            Write-Verbose "Getting Address with id: $Id"
            $Endpoint += "/$Id"
        }
        elseif ($TargetGroupId) {
            Write-Verbose "Getting all Addresses from TargetGroup: $TargetGroupId"
            $where += @{ targetId = $TargetGroupId }
        }
        elseif ($TargetGroupName) {
            $tg = Get-ICTargetGroup -Name $TargetGroupName
            if ($tg) {
                Write-Verbose "Getting all Addresses from TargetGroup: $TargetGroupName"
                $where += @{ targetId = $TargetGroupId }
            } else {
                Write-Error "TargetGroup with name $TargetGroupName does not exist."
                return
            }
            
        }

        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICAddress {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(
            ValueFromPipelineByPropertyName,
            ValueFromPipeLine)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('AddressId')]
        [String]$id,

        [parameter(ValueFromPipelineByPropertyName=$true)]
        [alias('targetId')]
        [String]$TargetGroupId
    )

    PROCESS {
        $Endpoint = "Addresses"

        if ($Id) {
            $obj = Get-ICAddress -id $Id
            if (-NOT $obj) {
                Write-Error "No Address with id '$Id' exists."
                return
            }
            if ($PSCmdlet.ShouldProcess($obj.hostname, "Will remove Address: $($obj.hostname) [$Id]")) {
                Write-Warning "Removing Address $($obj.hostname) [$Id]."
                $Endpoint = "Addresses/$id"
            }
        }
        elseif ($TargetGroupId) {
            $obj = Get-ICTargetGroup -id $TargetGroupId
            if (-NOT $obj) {
                Write-Error "No Target Group with id '$TargetGroupId' exists."
                return
            }
            if ($PSCmdlet.ShouldProcess($obj.name , "Clearing ALL Addresses from Target Group: $($obj.name) [$TargetGroupId]")) {
                Write-Warning "Clearing all Addresses from TargetGroup: $($obj.name) [$TargetGroupId]"
                $body['where'] = @{ targetId = $TargetGroupId }
            }
        }
        else {
            Write-Error "Provide either an addressId or a targetGroupId."
            return
        }

        Invoke-ICAPI -Endpoint $Endpoint -body $body -method DELETE
    }
}

function Get-ICAgent {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('agentId')]
        [String]$Id,

        [String]$Hostname,

        [String]$TargetGroupId,

        [String]$TargetGroupName,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "Agents"
        
        if ($Id) {
            $CountOnly = $False
            $Endpoint = "Agents/$Id"
        }
        elseif ($Hostname) {
            $where += @{ hostname = $Hostname }
        }
        elseif ($TargetGroupId -OR $TargetGroupName) {
            if ($TargetGroupId) {
                $tg = Get-ICTargetGroup -id $TargetGroupId
            } else {
                $tg = Get-ICTargetGroup -Name $TargetGroupName
            }
            if ($tg) {
                Write-Verbose "Getting all Agents from TargetGroup: $($tg.name) [$($tg.id)]"
                $addresses = Get-ICAddress -TargetGroupId $($tg.id) -where @{ agentId = @{ neq = $null }} -NoLimit:$NoLimit -CountOnly:$CountOnly
                if ($CountOnly) {
                    return $addresses
                } else {
                    $Addresses | Where-Object { $_.targetId } | ForEach-Object {
                        Get-ICAgent -id $_.targetId
                    }
                    return
                }
            } else {
                Write-Error "TargetGroup $TargetGroupName [$TargetGroupId] does not exist."
                return
            }
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly -ea 0
    }
}

function Remove-ICAgent {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('AgentId')]
        [String]$Id
    )

    PROCESS {
        $Endpoint = "agents/uninstall"
        $obj = Get-ICAgent -id $Id
        if (-NOT $obj) {
            Write-Error "No Agent exists with id: $Id"
            return
        }

        $body = @{
            where = @{ id = $Id }
        }

        if ($PSCmdlet.ShouldProcess($obj.hostname, "Will uninstall agent: $($obj.hostname) [$Id]")) {
            Write-Verbose "Uninstalling Agent $($obj.hostname) [$Id]."
            Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
            Write-Verbose "Uninstall pending for Agent on $($obj.hostname) [$Id]."
            return $true
        }
    }
}
