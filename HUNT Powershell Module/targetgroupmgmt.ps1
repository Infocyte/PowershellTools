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
        [alias('TargetGroupId','targetId')]
        [String]$Id,
        [Switch]$IncludeArchive,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
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
        [alias('TargetGroupId','targetId')]
        [String]$Id,

        [Switch]$IncludeArchive
    )

    PROCESS {
        if ($Id -AND $_.Id -AND $_.targetId) {
            $obj = Get-ICTargetGroup -id $Id
            if (-NOT $obj) {
                Write-Error "No target group with id '$Id' exists. Trying targetId."
                $obj = Get-ICTargetGroup -id $_.targetId
                if (-NOT $obj) {
                    Write-Error "No target group with id '$Id' exists."
                    return
                }
                $Id = $_.targetId
            }
        }

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
        [alias('controllerGroupId')]
        [String]$Id,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order="name",
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
        [alias('credentialId')]
        [String]$id,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
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
        [alias('credentialId')]
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
        [alias('addressId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$TargetGroupId,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order="lastAccessedOn",
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "Addresses"
        if ($Id -AND (-NOT $_.targetId)) {
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

        if ($Id -AND (-NOT $_.targetId)) {
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

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order = "completedOn desc",
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "scans"

        if ($Id -AND (-NOT $_.targetId)) {
            Write-Verbose "Getting Scan with Id $Id"
            $CountOnly = $false
            $order = $null
            $Endpoint += "/$Id"
        }
        elseif ($TargetGroupId) {
            $tg = Get-ICTargetGroup -Id $TargetGroupId
            if ($tg) {
                Write-Verbose "Getting Scans against Target Group $TargetGroup [$TargetGroupId]"
                $where += @{ targetId = TargetGroupId }
            } else {
                Write-Error "TargetGroup with Id $TargetGroupId does not exist."
                return
            }
        }

        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICAgent {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('agentId')]
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
            $Order = $null
            $CountOnly = $False
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
        [alias('targetId')]
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
        [alias('queryId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('targetId')]
        [String]$TargetGroupId,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
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
        [alias('queryId')]
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
