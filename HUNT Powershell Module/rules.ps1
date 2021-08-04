
function Import-ICRule {
    [cmdletbinding(DefaultParameterSetName = 'Rule')]
    Param(
        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ParameterSetName = 'Rule')]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Rule,

        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Path')]
        [ValidateNotNullorEmpty()]
        [String]$Path,

        [parameter(ParameterSetName = 'Rule')]
        [parameter(ParameterSetName = 'Path')]
        [Switch]$Active,

        [parameter(ParameterSetName = 'Rule')]
        [parameter(ParameterSetName = 'Path')]
        [Switch]$Force
    )

    PROCESS { 
        if ($Path) {
            $Body = Get-Content $Path -Raw
            #$reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $Path
            $rules = ConvertFrom-Yaml $Body | convertto-json | convertfrom-json | ForEach-Object {
                if ($null -eq $_.rule) {
                    Write-Error "Incorrect filetype. Not an Infocyte Rule"
                    continue
                }
                $_
            }
        } else {
            if ($null -eq $rule.rule) {
                Write-Error "Incorrect filetype. Not an Infocyte Rule"
                continue
            }
            $rules = $rule
        }
        

        $rules | Foreach-Object {
            $rule = $_
            if ($rule.guid) {

                if ($rule.guid -notmatch $GUID_REGEX) {
                    Write-Error "Incorrect guid format: $($rule.guid).  Should be a guid of form: $GUID_REGEX. 
                    Use the following command to generate a new one: [guid]::NewGuid().Guid"
                    $guid = [guid]::NewGuid().Guid
                    Write-Warning "Missing guid: Generating a new one prior to import: $guid" 
                    $rule.guid = $guid
                } 
                else {
                    $existingRule = Get-ICRule -where @{ guid = $rule.guid } -NoBody | Select-Object -First 1
                    if ($existingRule) {
                        if (-NOT $Force) {
                            Write-Warning "There is already an existing rule named $($existingRule.name) [$($existingRule.Id)] with guid $($rule.guid). Try using Update-ICRule or use -Force flag."
                            continue
                        }
                        Write-Warning "There is already an existing rule named $($existingRule.name) [$($existingRule.Id)] with guid $($rule.guid). Forcing update."
                        $id = $existingRule.id
                        Invoke-ICAPI -Endpoint rules -method POST -body @{
                            id          = $id
                            name        = $rule.name
                            short       = $rule.short
                            description = $rule.description
                            body        = $rule.rule
                        }
                        continue
                    }
                }            
            }
            else {
                $rule | Add-Member -TypeName NoteProperty -Name guid -Value ([guid]::NewGuid().Guid)
            }

            Write-Verbose "Adding new Rule named: $($rule.name)"
            Invoke-ICAPI -Endpoint rule -method POST -body @{ 
                name        = $rule.name
                short       = $rule.short
                description = $rule.description
                body        = $rule.rule
                guid        = $rule.guid
            }
        }
    }
}

function Get-ICRule {
    [cmdletbinding(DefaultParameterSetName = "List")]
    Param(
        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ParameterSetName = 'Id')]
        [ValidateScript( { if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [alias('ruleId')]
        [String]$Id,
        
        [parameter(
            ParameterSetName = 'List',
            HelpMessage = "This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where = @{},

        [parameter(
            ParameterSetName = 'List')]
        [Switch]$NoLimit,

        [parameter(
            ParameterSetName = 'List')]
        [Switch]$CountOnly,

        [Switch]$IncludeBody,

        [Switch]$Export
    )

    PROCESS {

        if ($Id) {
            Write-Verbose "Looking up rule by Id."
            $Endpoint = "rules/$Id"
            $rules = Get-ICAPI -Endpoint $Endpoint -ea 0
            if (-NOT $rules) {
                Write-Warning "Could not find rule with Id: $($Id)"
                return
            }
        }
        else {
            Write-Verbose "Getting rules"
            $Endpoint = "rules"
            $rules = Get-ICAPI -endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
            if (-NOT $rules) {
                Write-Verbose "Could not find any rules loaded with filter: $($where|convertto-json -Compress)"
                return
            }
            if ($CountOnly) { 
                return $rules 
            }
        }

        $n = 1
        if ($null -eq $rules.count) {
            $c = 1
        }
        else { 
            $c = $rules.count 
        }
        if ($IncludeBody -or $Export) {
            $rules | ForEach-Object {
                $rule = $_
                Write-Verbose "Getting Rule $($rule.name) [$($rule.id)]"
                try { $pc = [math]::Floor(($n / $c) * 100) } catch { $pc = -1 }
                Write-Progress -Id 1 -Activity "Getting Rule Body from Infocyte API" -Status "Requesting Body from Rule $n of $c" -PercentComplete $pc
                $ruleBody = Get-ICAPI -endpoint "rules/$($rule.id)/LatestVersion" -fields body, sha256
                $rule | Add-Member -MemberType NoteProperty -Name rule -Value $ruleBody.body 
                $rule | Add-Member -MemberType NoteProperty -Name sha256 -Value $ruleBody.sha256
                Write-Verbose "Looking up user: $($rule.createdBy) and $($rule.updatedBy)"
                $rule.createdBy = (Get-ICAPI -endpoint users -where @{ id = $rule.createdBy } -fields email -ea 0).email
                $rule.updatedBy = (Get-ICAPI -endpoint users -where @{ id = $rule.updatedBy } -fields email -ea 0).email
                $n += 1
            }  
            Write-Progress -Id 1 -Activity "Getting Rules from Infocyte API" -Status "Complete" -Completed
        }
        
        if ($Export) {
            $rules | ForEach-Object {
                $FilePath = "$($(Resolve-Path .\).Path)\$($($_.name).ToLower().Replace(' ','_')).yaml"
                $new_rule = [PSCustomObject][Ordered]@{
                    name = $_.name
                    guid = if ($_.guid) { $_.guid } else { $null }
                    rule = $_.body
                    author = $_.createdBy
                    description = $_.description
                    short = $_.short
                    severity = if ($_.severity) { $_.severity } else { "Medium" }
                    created = $_.created
                    updated = $_.updated
                    action = @{ alert = $true }
                }
                Write-Verbose "Exported Rule [$($_.name)] to $FilePath"
                $_ | Convertto-YAML -Force -OutFile $FilePath
            }
        }
        $rules
    }
}
function New-ICRule {
    [cmdletbinding()]
    param(
        [parameter(mandatory)]
        [String]$Name,
        
        [Parameter(Mandatory)]
        [String]$Rule,

        [Parameter()]
        [String]$Author = $env:Username,

        [Parameter()]
        [String]$Short,

        [Parameter()]
        [String]$Description,

        [Parameter()]
		[ValidateSet(
            "Critical",
            "High",
            "Medium",
            "Low"
        )]
        [String]$Severity = "Medium",
        
        [Switch]$Force
    )
	
    $today = Get-Date -UFormat "%F"
    
    $new_rule = [PSCustomObject][Ordered]@{
        name = $Name
        guid = [Guid]::NewGuid().guid
        rule = $Rule
        author = $Author
        description = $Description
        short = $Short
        severity = $Severity
        created = $today
        updated = $today
        action = @{ alert = $true }
    }

    $SavePath = (Resolve-Path .\).Path + "\new_rule.yaml"
    Write-Verbose "Created rule from template and saved to $SavePath"
    $new_rule | ConvertTo-YAML -OutFile $SavePath -Force
    Write-Output $new_rule
}
function Update-ICRule {
    <#
        Updates an existing rule with a new body from a file or string.
    #>
    [cmdletbinding(SupportsShouldProcess = $true)]
    Param(
        [parameter()]
        [ValidateScript( { if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [alias('ruleId')]
        [String]$Id,

        [parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [PSCustomObject]$Rule,

        [parameter(Mandatory)]
        [Switch]$Active
    )
    
    PROCESS {
        $Endpoint = "rules"

        $rule = ConvertFrom-Yaml $Body | convertto-json | convertfrom-json
        if ($null -eq $_.rule) {
            Write-Error "Incorrect filetype. Not an Infocyte Rule"
            return
        }

        $postbody = @{ 
            name        = $rule.name
            short       = $rule.short
            description = $rule.description
            body        = $rule.rule
            guid        = $rule.guid
            active      = $Active
        }

        if ($Id) {
            Write-Verbose "Looking up rule by Id"
            $existing_rule = Get-ICRule -id $Id -ea 0
            if ($existing_rule) {
                $Endpoint = "rules/$Id"
                Write-Verbose "Rule found: `n$($existing_rule | ConvertTo-Json)"
                if (-NOT $postbody['active']) { $postbody['active'] = $existing_rule.active }
                if (-NOT $postbody['name']) { $postbody['name'] = $existing_rule.name }
                if (-NOT $postbody['short']) { $postbody['short'] = $existing_rule.short }
                if (-NOT $postbody['description']) { $postbody['description'] = $existing_rule.description }
                if (-NOT $postbody['body']) { $postbody['body'] = $existing_rule.body }

                if (-NOT $postbody['guid']) { $postbody['guid'] = $existing_rule.guid }
                elseif ($rule.guid -AND $existing_rule.guid -ne $rule.guid) {
                    Write-Warning "Rule guids do not match. Cannot be updated, try importing the new rule!`nCurrent: $($existing_rule.guid)`nNew: $($rule.guid)"
                    return
                }
            } else {
                Write-Warning "Rule with id $id not found!"
                return
            }
        }
        else {
            Write-Verbose "Looking up rule by Guid"
            $existing_rule = Get-ICRule -ea 0 -where @{ guid = $rule.guid } -NoBody
            if ($existing_rule) {
                Write-Verbose "Found existing rule with matching guid $($existing_rule.guid). Updating id $($existing_rule.id)"
                $Endpoint = "rules/$($existing_rule.id)"
                $existing_rule = Get-ICRule -id $existing_rule.id
                if (-NOT $postbody['active']) { $postbody['active'] = $existing_rule.active }
                if (-NOT $postbody['name']) { $postbody['name'] = $existing_rule.name }
                if (-NOT $postbody['short']) { $postbody['short'] = $existing_rule.short }
                if (-NOT $postbody['description']) { $postbody['description'] = $existing_rule.description }
                if (-NOT $postbody['body']) { $postbody['body'] = $existing_rule.body }
            } 
            else {
                Write-Warning "Could not find existing rule with Guid: $($existing_rule.guid)"
                return
            }
        }

        Write-Verbose "Updating Rule: $($rule['name']) [Guid=$($rule.guid)] with `n$($postbody|convertto-json)"
        if ($PSCmdlet.ShouldProcess($($rule.name), "Will update rule $($postbody['name']) [$postbody['id'])]")) {
            Invoke-ICAPI -Endpoint $Endpoint -body $postbody -method POST
        }
    }
}

function Remove-ICRule {
    [cmdletbinding(SupportsShouldProcess = $true)]
    Param(
        [parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateScript( { if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [alias('ruleId')]
        [String]$Id
    )

    PROCESS {
        if ($Id) {
            $rule = Get-ICRule -id $Id
            if (-NOT $rule) {
                Write-Error "Rule with id $id not found!"
                return
            }
    
            $Endpoint = "rules/$Id"
            if ($PSCmdlet.ShouldProcess($($rule.Id), "Will remove $($rule.name) with ruleId '$($rule.id)'")) {
                try {
                    Invoke-ICAPI -Endpoint $Endpoint -Method DELETE
                    Write-Verbose "Removed rule $($rule.name) [$($rule.id)]"
                } catch {
                    Write-Warning "Rule $($rule.name) [$($rule.id)] could not be removed!"
                }
            }
        } else {
            $endpoint = "rules"
            Invoke-ICAPI -Endpoint $Endpoint -Method DELETE
            Write-Verbose "Removed all rules"
        }
    }
}
