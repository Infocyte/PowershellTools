# Setup APIs
function New-ICTargetGroup {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        [parameter(Mandatory=$false)]
        [String]$ControllerGroupId
    )

    $Endpoint = "targets"
    $body = @{
        name = $Name
    }

    if ($ControllerGroupId) {
        $body['controllerGroupId'] = $ControllerGroupId
    } else {
        $cg = Get-ICControllerGroup
        if ($cg.count -gt 1) {
            Write-Error "More than one Controller Group. Recommend specifying a ControllerGroupId."
            Write-Warning "$($cg | ft -auto | out-string)"
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
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('TargetGroupId')]
        [String]$Id,
        [Switch]$IncludeArchive,

        [HashTable]$where=@{},
        [String[]]$order="name",
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($IncludeArchive) {
            $Endpoint = "TargetsArchive"
        } else {
            $Endpoint = "targets"
        }

        Write-Debug "`$_=$_; `$Id=$Id"
        if ($Id) {
            $Endpoint += "/$Id"
        }

        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICTargetGroup {
    [cmdletbinding(SupportsShouldProcess)]
    param(
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [alias('TargetGroupId')]
        [String]$Id,

        [Switch]$IncludeArchive
    )

    PROCESS {
        if ($IncludeArchive) {
            $Endpoint = "TargetsArchive/$Id"
        } else {
            $Endpoint = "targets/$Id"
        }

        $obj = Get-ICTargetGroup -id $Id
        if (-NOT $obj) {
            Write-Error "No target group with id '$Id' exists."
            return
        }
        Write-Warning "Careful. This will remove access to all scan data within this target group and is only reversible for the next 7 days"
        if ($PSCmdlet.ShouldProcess($tg.name, "Will remove target group: $($obj.name) [$Id]")) {
            Write-Warning "Removing target group: $($obj.name) [$Id]."
            Invoke-ICAPI -Endpoint $Endpoint -method 'DELETE'
        }
    }
}

function New-ICControllerGroup {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )

    $Endpoint = "controllergroups"
    $body = @{
        name = $Name;
    }
    $cg = Get-ICControllerGroup -where @{ name = $Name; deleted = $False }
    if ($cg) {
        Write-Error "There is already a Controller Group named $Name"
    } else {
        Write-Verbose "Creating new Controller Group: $Name [$HuntServerAddress/api/$Endpoint]"
        Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
    }
}

function Get-ICControllerGroup {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('ControllerGroupId')]
        [String]$Id,

        [HashTable]$where=@{},
        [String[]]$order=@("name", "id"),
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "controllergroups"
        if ($Id) {
            $Endpoint += "/$id"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICControllerGroup {
    [cmdletbinding(SupportsShouldProcess)]
    param(
        [parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [alias('ControllerGroupId')]
        [String]$Id
    )

    PROCESS {
        $Endpoint = "controllergroups/$Id"
        $obj = Get-ICControllerGroup -id $Id
        if (-NOT $obj) {
            Write-Error "No Controller Group with id '$Id' exists."
            return
        }
        if ($PSCmdlet.ShouldProcess($obj.name, "Will remove target group: $($obj.name) [$Id]")) {
            Write-Warning "Removing Controller Group $Id."
            Invoke-ICAPI -Endpoint $Endpoint -method 'DELETE'
        }
    }
}


function New-ICCredential {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$True)]
        [String]$Name,

        [parameter(Mandatory=$True)]
        [PSCredential]$Cred,

        [parameter()]
        [ValidateSet("windowsLocal","windowsDomain","aws","ssh","login","linuxSudo")]
        [String]$AccountType="login"
    )

    $Endpoint = "credentials"
    $body = @{
        name = $Name
        username = $Cred.Username
        password = $Cred.GetNetworkCredential().Password
        byok = $False
        login = $AccountType
    }
    $c = Get-ICCredential -where @{ name = $Name; deleted = $False }
    if ($c) {
        Write-Error "There is already a credential object named $Name"
    } else {
        Write-Verbose "Adding new Credential $Name [$($Cred.Username)] to the Credential Manager"
        Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
    }
}

function Get-ICCredential {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('CredentialId')]
        [String]$id,

        [HashTable]$where=@{},
        [String[]]$order,
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "credentials"
        if ($id) {
            $Endpoint += "/$id"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICCredential {
    [cmdletbinding(SupportsShouldProcess)]
    param(
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [alias('CredentialId')]
        [String]$Id
    )

    PROCESS {
        $Endpoint = "credentials/$Id"
        $obj = Get-ICCredential -id $Id
        if (-NOT $obj) {
            Write-Error "No target group with id '$Id' exists."
            return
        }
        if ($PSCmdlet.ShouldProcess($obj.name, "Will remove Credential Object: $($obj.name) [$Id]")) {
            Write-Warning "Removing Credential $($obj.name) [$Id]."
            Invoke-ICAPI -Endpoint $Endpoint -method 'DELETE'
        }
    }
}

function Get-ICAddress {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('AddressId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$TargetGroupId,

        [HashTable]$where=@{},
        [String[]]$order="lastAccessedOn",
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
            $where += @{ targetId = $Id }
            Write-Verbose "Getting all Addresses from TargetGroup: $Id"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICAddress {
    [cmdletbinding(SupportsShouldProcess)]
    Param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('AddressId')]
        [String]$id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$TargetGroupId
    )

    PROCESS {
        $Endpoint = "Addresses"

        if ($id) {
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
            Write-Error "No inputs selected."
            return
        }

        Invoke-ICAPI -Endpoint $Endpoint -body $body -method DELETE
    }
}


function Get-ICScan {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('scanId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$TargetGroupId,

        [String]$TargetGroupName,

        [HashTable]$where=@{},
        [String[]]$order = "scanCompletedOn desc",
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "IntegrationScans"

        if ($Id) {
            Write-Verbose "Getting Scan with Id $Id"
            $where['scanId'] = $Id
        }
        elseif ($TargetGroupId) {
            $tg = Get-ICTargetGroup -Id $TargetGroupId
            if ($tg) {
                Write-Verbose "Getting Scans against Target Group $TargetGroup [$TargetGroupId]"
                $where += @{ targetList = $tg.name }
            } else {
                Write-Error "TargetGroup with Id $TargetGroupId does not exist."
                return
            }
        }
        elseif ($TargetGroupName) {
            $tg = Get-ICTargetGroup -where @{ name = $TargetGroupName }
            if ($tg) {
                Write-Verbose "Getting Scans against Target Group $TargetGroupName [$($tg.id)]"
                $where += @{ targetList = $TargetGroupName }
            } else {
                Write-Error "TargetGroup with name $TargetGroupName does not exist."
                return
            }
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICBox {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('BoxId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$targetGroupId,

        [Switch]$Global,
        [Switch]$Last7,
        [Switch]$Last30,
        [Switch]$Last90,

        [Switch]$IncludeDeleted,
        [Switch]$NoLimit
    )

    PROCESS {
        $Endpoint = "Boxes"
        if ($Id -AND (-NOT $_.targetId) ) {
            $Endpoint += "/$Id"
        } else {
            if ($Last90) {
                $where += @{ name = "Last 90 days" }
            }
            elseif ($Last30) {
                $where += @{ name = "Last 30 days" }
            }
            elseif ($Last7) {
                $where += @{ name = "Last 7 days" }
            }

            if ($targetGroupId) {
                $where += @{ targetId = $targetGroupId }
            }
            elseif ($Global) {
                $where += @{ targetId = $null }
            }
        }

        $boxes = Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit
        if (-NOT $boxes -AND $Id) {
            Write-Error "No Box with id $Id"
            return
        }
        $TargetGroups = Get-ICTargetGroup -NoLimit:$NoLimit
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
            Write-Verbose "Including deleted Target Groups"
            $boxes
        } else {
            $boxes | where { $_.targetGroup -ne "Deleted" }
        }
    }
}


function Get-ICAgent {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('AgentId')]
        [String]$Id,

        [HashTable]$where=@{},
        [String[]]$order,
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($Id) {
            $Endpoint = "Agents/$Id"
        } else {
            $Endpoint = "Agents"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICAgent {
    [cmdletbinding(SupportsShouldProcess)]
    Param(
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [alias('AgentId')]
        [String]$Id
    )

    PROCESS {
        $Endpoint = "Agents/$Id"
        $obj = Get-ICAgent -id $Id
        if (-NOT $obj) {
            Write-Error "No Agent with id '$Id' exists."
            return
        }
        if ($PSCmdlet.ShouldProcess($obj.hostname, "Will uninstall agent: $($obj.hostname) [$Id]")) {
            Write-Warning "Uninstalling Agent $Endpoint $($obj.hostname) [$Id]."
            Invoke-ICAPI -Endpoint "$Endpoint/uninstall" -method POST
            Start-Sleep 2
            Invoke-ICAPI -Endpoint $Endpoint -method DELETE
            Write-Host "Agent Uninstalled and Deleted."
        }
    }
}

function New-ICQuery {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [alias('QueryName')]
        [String]$Name,

        [parameter(Mandatory=$True)]
        [String]$TargetGroupId,

        [parameter(Mandatory=$True)]
        [String]$credentialId,

        [String]$sshCredentialId,

        [parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]$Query
    )

    $Credential = Get-ICCredential -Id $CredentialId
    if (-NOT $Credential) {
        Throw "Credential with CredentialId $CredentialId does not exist."
    }
    $TargetGroup = Get-ICTargetGroup -Id $TargetGroupId
    if (-NOT $TargetGroup) {
        Throw "Credential with TargetGroup $TargetGroupId does not exist."
    }
	Write-Verbose "Creating new Query $Name ($query) in TargetGroup $($TargetGroup.name) using credential $($Credential.name) [$($Credential.username)]"
    $Endpoint = "queries"
    $body = @{
        name = $Name
        value = $query
        targetId = $TargetGroupId
        credentialId = $CredentialId
    }
    if ($sshCredentialId) {
        $body['sshCredential'] = $sshCredentialId
    }
    Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
}

function Get-ICQuery {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('QueryId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$TargetGroupId,

        [HashTable]$where=@{},
        [String[]]$order,
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "queries"
        if ($Id -AND (-NOT $_.targetId)) {
            Write-Verbose "Getting Query: $Id"
            $Endpoint += "/$Id"
        }
        elseif ($TargetGroupId) {
            Write-Verbose "Getting Queries for Target Group Id: $TargetGroupId"
            $where += @{ targetId = $TargetGroupId }
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$true -CountOnly:$CountOnly
    }
}

function Remove-ICQuery {
    [cmdletbinding(SupportsShouldProcess)]
    param(
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [alias('QueryId')]
        [String]$Id
    )

    PROCESS {
        $Endpoint = "queries/$Id"
        if ($PSCmdlet.ShouldProcess($Id, "Will remove this query")) {
            Write-Warning "Removing query $Id"
            Invoke-ICAPI -Endpoint $Endpoint -method 'DELETE'
        }
    }
}
