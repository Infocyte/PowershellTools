
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from Infoyte
function Get-ICObject {
    [cmdletbinding()]
    [alias("Get-ICData","Get-ICObjects")]
    param(
        [parameter(ValueFromPipeline)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$Id,

        [parameter(
            Mandatory=$true,
            HelpMessage="Data is currently seperated into object-type tables. 'File' will perform a recursive call of all files.")]
        [ValidateSet(
          "Process",
          "Module",
          "Driver",
          "MemScan",
          "Artifact",
          "Autostart",
          "Host",
          "Connection",
          "Application",
          "Account",
          "Script",
          "File",
          "Extension"
        )]
        [String]$Type,

        [parameter(HelpMessage={"Boxes are the 7, 30, and 90 day views of target group or global data. Use Set-ICBox to set your default. CurrentDefault: $Global:ICCurrentBox"})]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$BoxId=$Global:ICCurrentBox,
        [parameter(HelpMessage="Defaults to hash+path aggregation (normalized). Use this switch to get all raw instances of the object found.")]
        [Switch]$AllInstances,

        [Switch]$CountOnly,
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter")]
        [HashTable]$where=@{},

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields,

        [Switch]$NoLimit
    )

    $Files = @(
        "Process",
        "Module",
        "Driver",
        "MemScan",
        "Artifact",
        "Autostart",
        "Script"
    )

    if ($where -AND $where['and']) {
        if (-NOT $where['and'].boxId) {
            $where['and'] += @{ 'boxId' = $BoxId }
        }
    }
    if ($where -AND $where['or']) {
        # handle this wierd loopback thing where 'or' filters screw things up
        # wrap everything in an explicit 'and'
        Write-Warning "There is a known issue with Loopback where filters that cause problems with first level 'or' filters."
        Write-Warning "You should wrap everything in an And filter to make sure this works. Doing this now."
        $where = @{
            and = @(
                @{ or = $where['or'] },
                @{ boxId = $BoxId }
            )
        }
        $where += @{ boxId = $BoxId }
        Write-Warning "where-filter:$($where|convertto-json -depth 10)"
    }
    elseif ($where) {
        $where['boxId'] = $BoxId
    } else {
        $where += @{ boxId = $BoxId }
    }

    switch ( $Type ) {
        "Process" {
            if ($AllInstances) {
                $Endpoint = "BoxProcessInstances"
            } else {
                $Endpoint = "BoxProcesses"
            }
        }
        "Host" {
            if ($AllInstances) {
                $Endpoint = 'BoxHostScans'
            } else {
                $Endpoint = 'BoxHosts'
            }
        }
        "Account" {
            if ($AllInstances) {
                $Endpoint = 'BoxAccountInstancesByHost'
            } else {
                $Endpoint = 'BoxAccounts'
            }
        }
        "Extension" {
            if (-NOT $Id) {
                $fields = @("id", "extensionId", "extensionVersionId","ip","boxId","sha256",
                "hostScanId","success","threatStatus","compromised","startedOn","endedOn",
                "createdOn","name","hostId","scanId","scannedOn","hostname","output")
            }
            if ($AllInstances) {
                $Endpoint = 'BoxExtensionInstances'

            } else {
                $fields = @("extensionId", "extensionVersionId","boxId","sha256",
                "hostScanId","success","threatStatus","compromised","name","hostId","scanId")
                Write-Verbose "Aggregate Extensions."
                $extensioninstances = Get-ICObject -Type "Extension" -BoxId $BoxId -where $where -fields $fields -AllInstances
                $results = @()
                $extensioninstances | Select-Object $fields | Group-Object extensionId | ForEach-Object {
                    $props = @{
                        Id = $_.name # extensionId
                        name = $_.group[0].name
                        boxId = $_.group[0].boxId
                        count = $_.count
                        hosts = ($_.group | Select-Object hostId -unique).hostId.count
                        success = 0
                        compromised = $false
                        Good = 0
                        'Low Risk' = 0
                        Unknown = 0
                        Suspicious = 0
                        Bad = 0
                    }
                    $_.Group | ForEach-Object {
                        if ($_.success) { $props['success'] += 1}
                    }

                    $_.group | Group-Object threatStatus | ForEach-Object {
                        $props[$_.Name] = $_.count
                    }

                    if ($_.group.compromised -contains $true) {
                        $props['compromised'] = $true
                    }
                    $props['completion'] = ($($props.hosts)/$($_.count)).tostring("P")
                    $results += New-Object PSObject -property $props
                }
                return $results
            }
        }
        "File" {
            If ($where.count -lt 2) {
                Write-Warning "No where filter provided. You should provide a filter for this query to reduce strain on the database."
                Write-Warning "Defaulting to bad and suspicious objects only."
                $where += @{ threatName = @{ or = @("Bad", "Suspicious")} }
            }
            $cnt = 0
            $Files | ForEach-Object {
                if ($CountOnly) {
                    $c = Get-ICObject -Type $_ -BoxId $BoxId -where $where -AllInstances:$AllInstances -CountOnly
                    Write-Verbose "Found $c $_ Objects"
                    $cnt += $c
                } else {
                    Write-Verbose "Querying $_"
                    Get-ICObject -Type $_ -BoxId $BoxId -where $where -fields $fields -NoLimit:$NoLimit -AllInstances:$AllInstances
                }
            }
            if ($CountOnly) {
                return $cnt
            }
        }
        Default {
            if ($AllInstances) {
                $Endpoint = "Box$($Type)Instances"
            } else {
                $Endpoint = "Box$($Type)s"
            }
        }
    }
    if ($Type -ne 'File') {
        if ($Id) {
            $CountOnly = $false
            $Endpoint += "/$id"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICVulnerability {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('applicationId')]
        [String]$Id,

        [Switch]$AllInstances,
        [parameter(HelpMessage={"Boxes are the 7, 30, and 90 day views of target group or global data. Use Set-ICBox to set your default. CurrentDefault: $Global:ICCurrentBox"})]
        [String]$BoxId=$Global:ICCurrentBox,
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [Switch]$NoLimit
    )

    BEGIN {
        if ($where -AND $where['boxId']) {
            $where['boxId'] = $BoxId
        } else {
            $where += @{ boxId = $BoxId }
        }

        Write-Verbose "Building Application table..."
        $Apps = @()
    }

    PROCESS{
        if ($Id) {
            if ($AllInstances) {
                Write-verbose "Querying for application instances with applicationId: $Id"
                $a = Get-ICObjects -Type Application -where @{ applicationId = $id } -BoxId $BoxId -AllInstances:$AllInstances
            } else {
                Write-verbose "Querying for applications with applicationId: $Id"
                $a = Get-ICObjects -Id $id -Type Application -BoxId $BoxId
                if ($a) {
                    $a | ForEach-Object {
                        $appid = $_.id
                        $_ | Add-Member -MemberType "NoteProperty" -name "applicationId" -value $appid
                    }
                    Write-Debug $a
                }
            }
            if ($a) {
                $apps += $a
            } else {
                Write-Error "No application found with applicationId: $Id in BoxId: $BoxId"
                return
            }
        } else {
            if ($AllInstances) {
                $apps = Get-ICObjects -Type Application -BoxId $BoxId -where $where -NoLimit:$NoLimit -AllInstances:$AllInstances
            } else {
                $apps = Get-ICObjects -Type Application -BoxId $BoxId -where $where -NoLimit:$NoLimit
                $apps | ForEach-Object {
                    $appid = $_.id
                    $_ | Add-Member -MemberType "NoteProperty" -name "applicationId" -value $appid
               }
            }
        }
    }

    END {
        $where.remove('boxId') | Out-Null
        $Endpoint = "ApplicationAdvisories"
        Write-Verbose "Building Application Advisory bridge table with filter: $($where|convertto-json -compress)"
        $appvulns = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$true | sort-object applicationId, cveId -unique

        if ($apps -AND $appvulns) {
            $appids = $apps.applicationid | sort-object -unique
            $appvulns = $appvulns | Where-Object  { $appids -contains $_.applicationId }
            $apps = $apps | Where-Object  { $appvulns.applicationId -contains $_.applicationId }
        } else {
            Write-Verbose "No Results found."
            return
        }

        Write-Verbose "Found $($appids.count) applications and $($appvulns.count) associated advisories. Enriching details for export...`n"
        $appvulns | ForEach-Object {
            $vuln = $_
            Write-Verbose "==Vulnerable App: $($vuln.ApplicationName) cveId: $($vuln.cveId) App id: $($vuln.applicationId)"
            if ($vuln.cveId) {
                $cve = Get-ICAPI -Endpoint "Cves/$($vuln.cveId)" -where $where
                if ($cve) {
                    $vuln | Add-Member -MemberType "NoteProperty" -name "rules" -value $cve.rules
                    $vuln | Add-Member -MemberType "NoteProperty" -name "cwes" -value $cve.cwes
                    $vuln | Add-Member -MemberType "NoteProperty" -name "reference" -value $cve.reference.url
                    if ([bool]($cve.cveimpact.PSobject.Properties.name -match "baseMetricV3")) {
                        $vuln | Add-Member -MemberType "NoteProperty" -name "cvsstype" -value 3.0
                        $vuln | Add-Member -MemberType "NoteProperty" -name "severity" -value $cve.impact.baseMetricV3.severity
                        $vuln | Add-Member -MemberType "NoteProperty" -name "impactScore" -value $cve.impact.baseMetricV3.impactScore
                        $vuln | Add-Member -MemberType "NoteProperty" -name "exploitabilityScore" -value $cve.impact.baseMetricV3.exploitabilityScore
                        $vuln | Add-Member -MemberType "NoteProperty" -name "attackVector" -value $cve.impact.baseMetricV3.cvssv3.attackVector
                        $vuln | Add-Member -MemberType "NoteProperty" -name "attackComplexity" -value $cve.impact.baseMetricV3.cvssv3.attackComplexity
                        $vuln | Add-Member -MemberType "NoteProperty" -name "authentication" -value $cve.impact.baseMetricV3.cvssv3.authentication
                    } else {
                        $vuln | Add-Member -MemberType "NoteProperty" -name "cvsstype" -value 2.0
                        $vuln | Add-Member -MemberType "NoteProperty" -name "severity" -value $cve.impact.baseMetricV2.severity
                        $vuln | Add-Member -MemberType "NoteProperty" -name "impactScore" -value $cve.impact.baseMetricV2.impactScore
                        $vuln | Add-Member -MemberType "NoteProperty" -name "exploitabilityScore" -value $cve.impact.baseMetricV2.exploitabilityScore
                        $vuln | Add-Member -MemberType "NoteProperty" -name "attackVector" -value $cve.impact.baseMetricV2.cvssv2.accessVector
                        $vuln | Add-Member -MemberType "NoteProperty" -name "attackComplexity" -value $cve.impact.baseMetricV2.cvssv2.accessComplexity
                        $vuln | Add-Member -MemberType "NoteProperty" -name "authentication" -value $cve.impact.baseMetricV2.cvssv2.authentication
                    }
                }
            }
        }
        $applicationvulnerabilities = Join-Object -Left $apps -Right $appvulns -LeftJoinProperty 'applicationid' -RightJoinProperty 'applicationid' -Type OnlyIfInBoth
        #-RightProperties cveId, description, baseScoreV2, baseScoreV3, published, modified

        Write-Verbose "Exporting $($applicationvulnerabilities.count) Vulnerabilities"
        Write-Output $applicationvulnerabilities
    }
}

# Get Full FileReport on an object by sha1
function Get-ICFileDetail {
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateScript({ if ($_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Requires a sha1 (fileRepId) of 40 characters."} })]
        [alias('fileRepId')]
        [String]$sha1,

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields
    )
    PROCESS {
        Write-Verbose "Requesting FileReport on file with SHA1: $sha1"
        $fileReport = Get-ICAPI -Endpoint "FileReps/$sha1" -fields $fields
        $notes = Get-ICNotes -relatedId $sha1
        $fileReport | Add-Member -Type NoteProperty -name CommentCount -value ($notes.count)
        $fileReport | Add-Member -Type NoteProperty -name Comments -value ($notes)
        return $fileReport
    }
}

function Get-ICNotes {
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateScript({ if ($_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Requires a relatedId or fileRepId (sha1) of 40 characters."} })]
        [alias('fileRepId')]
        [alias('sha1')]
        [String]$relatedId,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter")]
        [HashTable]$where,

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields
    )
    
    PROCESS {
        Write-Verbose "Getting notes/comments on object with id: $relatedId"
        if (-NOT $where -AND $relatedId) {
            $where += @{ relatedId = $relatedId }
        }
        $comments = Get-ICAPI -Endpoint "userComments" -where $where
        $comments | % {
            Write-Verbose "Looking up user: $($_.userId)"
            $_.createdBy = (Get-ICAPI -endpoint users -where @{ id = $_.userId } -fields email -ea 0).email
        }
        $comments | Write-Output

    }
}

# Get Account objects
function Get-ICAlert {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$Id,

        [Switch]$IncludeArchived,
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields,
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "AlertDetails"
        if ($Id) {
            $CountOnly = $false
            $Endpoint += "/$Id"
        }
        if (-NOT ($IncludeArchived -OR $Where['archived'])) {
            $Where += @{ archived = $FALSE }
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICReport {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('reportId')]
        [String]$Id,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($Id) {
            $CountOnly = $False
            $Endpoint = "Reports/$Id"
        } else {
            $Endpoint = "Reports"
            $fields = @("id","name","createdOn","type","hostCount")
        }

        Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICActivityTrace {
    [cmdletbinding(DefaultParameterSetName="fileRepId")]
    param(
        [parameter(
            ParameterSetName="Id",
            ValueFromPipeline=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$Id,

        [parameter(
            ParameterSetName="accountId",
            ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$accountId,

        [parameter(
            ParameterSetName="fileRepId",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('fileRepId')]
        [String]$sha1,

        [parameter(
            ParameterSetName="hostId",
            ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$hostId,

        [parameter(ParameterSetName="accountId")]
        [parameter(ParameterSetName="fileRepId")]
        [parameter(ParameterSetName="hostId")]     
        [DateTime]$StartTime=(Get-Date).AddDays(-7).ToUniversalTime(),

        [parameter(ParameterSetName="accountId")]
        [parameter(ParameterSetName="fileRepId")]
        [parameter(ParameterSetName="hostId")] 
        [DateTime]$EndTime = (Get-Date).ToUniversalTime(),

        [parameter(ParameterSetName="accountId")]
        [parameter(ParameterSetName="fileRepId")]
        [parameter(ParameterSetName="hostId")] 
        [HashTable]$where=@{},

        [parameter(ParameterSetName="accountId")]
        [parameter(ParameterSetName="fileRepId")]
        [parameter(ParameterSetName="hostId")] 
        [Switch]$NoLimit,

        [parameter(ParameterSetName="accountId")]
        [parameter(ParameterSetName="fileRepId")]
        [parameter(ParameterSetName="hostId")] 
        [Switch]$CountOnly
    )

    BEGIN {
        $Where['between'] = @(
            (Get-Date $StartTime -Format "o"),
            (Get-Date $EndTime -Format "o")
        )
    }
    PROCESS {
        $Endpoint = "activity"
        if ($Id) {
            $CountOnly = $false
            $Endpoint += "/$Id"
        } else {
            if ($SHA1) {
                $where['fileRepId'] = $SHA1
            }
            if ($AccountId) {
                $where['accountId'] = $AccountId
            }
            if ($HostId) {
                $where['hostId'] = $HostId
            }
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICDwellTime {
    [cmdletbinding()]
    param(
        [parameter()]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$Id,

        [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern("\b[0-9a-f]{40}\b")]
        [alias('fileRepId')]
        [String]$Sha1,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
    
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "fileDwellTimes"
        if ($Id) {
            $CountOnly = $False
            $Endpoint += "/$Id"
        }
        elseif ($sha1) {
            $where['fileRepId'] = $Sha1
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICBox {
    [cmdletbinding(DefaultParameterSetName="Global")]
    param(
        [parameter(ParameterSetName="Id")]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('BoxId')]
        [String]$Id,

        [parameter(ParameterSetName="TargetId")]
        [alias('targetId')]
        [String]$targetGroupId,

        [parameter(ParameterSetName="Global")]
        [Switch]$Global,

        [parameter(
            Mandatory=$false,
            ParameterSetName="TargetId")]
        [parameter(
            Mandatory=$false, 
            ParameterSetName="Global")]
        [ValidateSet(7,30,90)]
        [Int]$Last, #New
   
        [parameter(
            Mandatory=$false,
            ParameterSetName="TargetId")]
        [parameter(
            Mandatory=$false, 
            ParameterSetName="Global")]
        [Switch]$Last7, # Legacy

        [parameter(
            Mandatory=$false,
            ParameterSetName="TargetId")]
        [parameter(
            Mandatory=$false, 
            ParameterSetName="Global")]
        [Switch]$Last30, # Legacy

        [parameter(
            Mandatory=$false,
            ParameterSetName="TargetId")]
        [parameter(
            Mandatory=$false, 
            ParameterSetName="Global")]
        [Switch]$Last90, # Legacy

        [Switch]$IncludeArchive,
        [Switch]$NoLimit
    )

    $Endpoint = "Boxes"
    if ($Id) {
        $Endpoint += "/$Id"
    } else {
        if ($Last -eq 90 -OR $Last90) {
            $where += @{ name = "Last 90 days" }
        }
        elseif ($Last -eq 30 -OR $Last30) {
            $where += @{ name = "Last 30 days" }
        }
        elseif ($Last -eq 7 -OR $Last7) {
            $where += @{ name = "Last 7 days" }
        }

        if ($targetGroupId) {
            $where += @{ targetId = $targetGroupId }
        } 
        elseif ($Global) {
            #Global
            $where += @{ targetId = $null }
        }
    }

    $boxes = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit
    if ($Id -AND -NOT $boxes) {
        Write-Error "No Box with id $Id was found"
        return
    }
    $TargetGroups = Get-ICTargetGroup -IncludeArchive -NoLimit:$NoLimit
    $boxes | ForEach-Object {
        if ($_.targetId) {
            $tgid = $_.targetId
            $tg = $TargetGroups | Where-Object { $_.id -eq $tgid }
            if ($tg) {
                $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value $tg.name
                $_ | Add-Member -MemberType "NoteProperty" -name "lastScannedOn" -value $tg.lastScannedOn
                $_ | Add-Member -MemberType "NoteProperty" -name "deleted" -value $tg.deleted
            } else {
                $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value "Deleted"
                $_ | Add-Member -MemberType "NoteProperty" -name "deleted" -value $true
            }
        } else {
            $_ | Add-Member -MemberType "NoteProperty" -name "targetGroup" -value "Global"
        }
    }
    if ($IncludeArchive) {
        Write-Verbose "Including deleted Target Groups..."
        $boxes
    } else {
        $boxes | Where-Object { -NOT $_.deleted -AND $_.targetGroup -ne "Deleted" }
    }
}

function Set-ICBox {
    [cmdletbinding(DefaultParameterSetName="Global")]
    param(
        [parameter(
            Mandatory=$true, 
            ValueFromPipeLine=$true,
            ValueFromPipelineByPropertyName,
            ParameterSetName="Id"
            )]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('BoxId')]
        [String]$Id,

        [parameter(
            Mandatory=$false,
            ParameterSetName="TargetId")]
        [alias('targetId')]
        [String]$targetGroupId,

        [parameter(
            Mandatory=$false,
            ParameterSetName="Global")]
        [Switch]$Global,

        [parameter(
            Mandatory=$true,
            ParameterSetName="TargetId")]
        [parameter(
            Mandatory=$true, 
            ParameterSetName="Global")]
        [ValidateSet(7,30,90)]
        [Int]$Last
    )

    PROCESS {
        if ($Id) {
            $box = Get-ICbox -id $Id
            if ($box) {
                Write-Verbose "`$Global:ICCurrentBox is now set to $($box.targetGroup)-$($box.name) [$Id]"
                $Global:ICCurrentBox = $Id
                return $true
            } else {
                Write-Error "No Box found with Id: $Id"
                return
            }
        } else {
            Write-Verbose "Setting default box to global last $GlobalLast day aggregation."
            if ($targetGroupId) {
                Get-ICBox -targetGroupId $targetGroupId -Last $Last | Set-ICBox
            } else {
                #Global
                Get-ICBox -Last $Last | Set-ICBox
            }
        }
    }
}
