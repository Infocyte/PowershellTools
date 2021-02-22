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

        [Switch]$IncludeArchive,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
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

function New-ICControllerGroup {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
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
        [parameter(ValueFromPipeline=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('controllerGroupId')]
        [String]$Id,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "controllergroups"
        if ($Id) {
            $Endpoint += "/$id"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICControllerGroup {
    [cmdletbinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
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
        [parameter(ValueFromPipeline=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('credentialId')]
        [String]$id,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "credentials"
        if ($id) {
            $Endpoint += "/$id"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Remove-ICCredential {
    [cmdletbinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
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
        [parameter()]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('addressId')]
        [String]$Id,

        [parameter(ValueFromPipeLine=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('targetId')]
        [String]$TargetGroupId,

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

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($Id) {
            $CountOnly = $False
            $Endpoint = "Agents/$Id"
        } else {
            $Endpoint = "Agents"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
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

function New-ICQuery {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [alias('QueryName')]
        [String]$Name,

        [parameter(Mandatory=$True)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('targetId')]
        [String]$TargetGroupId,

        [parameter(Mandatory=$True)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$credentialId,

        [parameter()]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
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
        [parameter(ValueFromPipeline=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('queryId')]
        [String]$Id,

        [parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('targetId')]
        [String]$TargetGroupId,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "queries"
        if ($Id) {
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
    [cmdletbinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
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
