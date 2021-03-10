
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from Infoyte
function Get-ICObject {
    [cmdletbinding(DefaultParameterSetName="Box")]
    [alias("Get-ICData","Get-ICObjects")]
    param(
        [parameter(ValueFromPipeline)]
        [ValidateScript( { if ($_ -match $GUID_REGEX -OR $_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
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

        [parameter(
            ParameterSetName="Box",
            HelpMessage={"Boxes are the 7, 30, and 90 day views of target group or global data. Use Set-ICBox to set your default. CurrentDefault: $Global:ICCurrentBox"})]
        [ValidateScript( { if ($_ -match $GUID_REGEX -OR $_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [String]$BoxId=$Global:ICCurrentBox,

        [parameter(
            ParameterSetName = "Scan")]
        [ValidateScript( { if ($_ -match $GUID_REGEX -OR $_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [string]$ScanId,

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

    if ($ScanId) {
        if ($where -AND $where['and']) {
            if (-NOT $where.scanId -AND -NOT $where['and'].scanId) {
                $where['and'] += @{ 'scanId' = $scanId }
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
                    @{ scanId = $scanId }
                )
            }
            #$where += @{ scanId = $scanId }
            Write-Warning "where-filter:$($where|ConvertTo-Json -depth 10)"
        }
        elseif ($where) {
            $where['scanId'] = $scanId
        }
        else {
            $where += @{ scanId = $scanId }
        }
        $Box = "Scan"
    }
    else {
        #BoxId
        if ($where -AND $where['and']) {
            if (-NOT $where['boxId'] -AND -NOT $where['and'].boxId) {
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
            #$where += @{ boxId = $BoxId }
            Write-Warning "where-filter:$($where|ConvertTo-Json -depth 10)"
        }
        elseif ($where) {
            $where['boxId'] = $BoxId
        }
        else {
            $where += @{ boxId = $BoxId }
        }
        $Box = "Box"
        $B = Get-ICBox -id $BoxId
        $BoxName = "$($B.targetGroup) - $($B.name)"
    }
    
    switch ( $Type ) {
        "Process" {
            if ($AllInstances) {
                $Endpoint = "$($Box)ProcessInstances"
            } else {
                $Endpoint = "$($Box)Processes"
            }
        }
        "Script" {
            if ($AllInstances) {
                $Endpoint = "$($Box)ScriptInstances"
            } else {
                $Endpoint = "$($Box)ScriptDetails"
            }
        }
        "Host" {
            if ($AllInstances) {
                $Endpoint = "$($Box)HostScans"
            } else {
                $Endpoint = "$($Box)Hosts"
            }
        }
        "Account" {
            if ($AllInstances) {
                $Endpoint = "$($Box)AccountInstancesByHost"
            } else {
                $Endpoint = "$($Box)Accounts"
            }
        }
        "Extension" {
            $Endpoint = "$($Box)ExtensionInstances"
            $fields = @("id", "extensionId", "extensionVersionId", "hostname", "ip", "sha256",
                "hostScanId", "success", "threatStatus", "name", "hostId", "scanId", "scannedOn", "startedOn", "endedOn", "output")
            if (-NOT $ScanId) {
                $fields += "boxId"
            }

            if ($Id) {            
                $Endpoint += "\$Id"
            }
            elseif ($AllInstances) {
                $results = Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
                $results | foreach-object {
                    $_.output = $_.output.output.entry
                    $_ | Add-Member -MemberType NoteProperty -Name runTime -Value $null
                    if ($_.endedOn) {
                        $_.runTime = [math]::round(([datetime]$_.endedOn - [DateTime]$_.startedOn).TotalSeconds)
                    }
                }
                #Enrich BoxName
                if ($Box -eq "Box") {
                    $Results | ForEach-Object {
                        $_ | Add-Member -MemberType NoteProperty -Name boxName -Value $BoxName
                    }
                }
                if ($EnrichTargetGroupName) {
                    #Enrich targetGroupName
                    if ($results) {
                        $Scans = @()
                        $TargetGroups = Get-ICTargetGroup
                        $results | ForEach-Object {
                            if ($scan_id -ne $_.scanId) {
                                $scan_id = $_.scanId
                                $scan = $Scans | Where-Object { $_.id -eq $scan_id }
                                if (-NOT $scan) {
                                    $scan = Get-ICScan -id $scan_id
                                    $scans += $scan
                                }
                                $tg = $TargetGroups | Where-Object { $_.id -eq $scan.targetId }
                                if ($tg) {
                                    $tgname = $tg.name
                                } else {
                                    $tgname = "(deleted)"
                                }
                            }
                            $_ | Add-Member -MemberType NoteProperty -Name targetGroup -Value $tgname
                        }
                    }
                }
                return $results
            } 
            elseif (-Not $Id) {
                $fields = @("id","extensionId","extensionVersionId","boxId","hostScanId","success","threatStatus","name","hostId","scanId")
                Write-Verbose "Aggregating Extensions."
                if ($ScanId) {
                    $extensioninstances = Get-ICObject -Type "Extension" -ScanId $ScanId -where $where -fields $fields -AllInstances -NoLimit:$NoLimit
                } else {
                    $extensioninstances = Get-ICObject -Type "Extension" -BoxId $BoxId -where $where -fields $fields -AllInstances -NoLimit:$NoLimit
                }
                $results = @()
                $extensioninstances | Group-Object extensionVersionId | ForEach-Object {
                    $props = @{
                        Id = $_.name # extensionVersionId
                        name = $_.group[0].name
                        boxId = $_.group[0].boxId
                        boxName = $BoxName
                        count = $_.count
                        hosts = ($_.group | Select-Object hostId -unique).hostId.count
                        success = 0
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
                    $props['completion'] = ($($props.hosts)/$($_.count)).tostring("P")
                    $results += New-Object PSCustomObject -property $props
                }
                return $results
            }
        }
        "File" {
            If ($where.count -lt 2) {
                if ($where.'and'  -AND $where.'and'.count -lt 2 -OR $where.'or'  -AND $where.'or'.count -lt 2) {
                    Write-Warning "No where filter provided. You should provide a filter for this query to reduce strain on the database."
                    Write-Warning "Defaulting to bad objects only."
                    $where += @{   
                        or = @(
                            @{ threatName = "Bad" },
                            @{ threatName = "Blacklist" },
                            @{ flagName = "Verified Bad" }
                        )
                    }
                    #$where += @{ threatName = @{ or = @("Bad", "Suspicious")} }
                }
            }
            $cnt = 0
            $Files | ForEach-Object {
                if ($CountOnly) {
                    if ($ScanId) {
                        $c = Get-ICObject -Type $_ -ScanId $ScanId -where $where -AllInstances:$AllInstances -CountOnly
                    } else {
                        $c = Get-ICObject -Type $_ -BoxId $BoxId -where $where -AllInstances:$AllInstances -CountOnly
                    }
                    Write-Verbose "Found $c $_ Objects"
                    $cnt += $c
                } else {
                    Write-Verbose "Querying $_"
                    if ($ScanId) {
                        Get-ICObject -Type $_ -ScanId $ScanId -where $where -fields $fields -NoLimit:$NoLimit -AllInstances:$AllInstances
                    } else {
                        Get-ICObject -Type $_ -BoxId $BoxId -where $where -fields $fields -NoLimit:$NoLimit -AllInstances:$AllInstances
                    }
                }    
            }
            if ($CountOnly) {
                return $cnt
            }
        }
        Default {
            if ($AllInstances) {
                $Endpoint = "$($Box)$($Type)Instances"
            } else {
                $Endpoint = "$($Box)$($Type)s"
            }
        }
    }
    if ($Type -ne 'File') {
        if ($Id) {
            $CountOnly = $false
            $Endpoint += "/$id"
        }
        if ($CountOnly) { 
            Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
        } else {
            $Results = Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit

            #Enrich BoxName
            if ($Box -eq "Box") {
                $Results | ForEach-Object {
                    $_ | Add-Member -MemberType NoteProperty -Name boxName -Value $BoxName
                }
            }

            if ($EnrichTargetGroupName) {
                #Enrich targetGroupName
                if ($Results -AND $Results[0].scanId) {
                    $Scans = @()
                    $TargetGroups = Get-ICTargetGroup
                    $Results | ForEach-Object {
                        if ($scan_id -ne $_.scanId) { 
                            $scan_id = $_.scanId
                            $scan = $Scans | Where-Object { $_.id -eq $scan_id }
                            if (-NOT $scan) {
                                $scan = Get-ICScan -id $scan_id
                                $scans += $scan
                            }
                            $tg = $TargetGroups | Where-Object { $_.id -eq $scan.targetId }
                            if ($tg) {
                                $tgname = $tg.name
                            } else {
                                $tgname = "(deleted)"
                            }
                        }
                        $_ | Add-Member -MemberType NoteProperty -Name targetGroup -Value $tgname
                    }
                }
            }            
            $Results
        }
    }
}

function Get-ICComplianceResults {
    [cmdletbinding()]
    param(
        [parameter(
            Mandatory=$false
        )]
        [ValidateScript( { if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [alias('id')]
        [String]$complianceResultId,

        [Switch]$RemediationSteps
    )

    $compliancescans = @()
    if ($complianceResultId) {
        $compliancescans += Get-ICAPI -endpoint complianceresultinstances -where @{ id = $complianceResultId }
        if (-NOT $compliancescan) {
            Write-Error "complianceResultId does not exist"
            return
        }
    } else {
        $compliancescans += Get-ICAPI -endpoint complianceresultinstances
    }

    $compliancescans | ForEach-Object {
        Write-Verbose "Getting failed items for compliance result id $($_.id)"
        $items = Get-ICAPI -endpoint complianceresultitems -where @{ complianceResultId = $_.id; passed = $false } -fields id, checklistId, result, score, maxscore, remarks, passed
        $_ | Add-Member -MemberType NoteProperty -Name items -Value $items
    }

    $compliancescans
}

function Get-ICHostScanResult {
    [cmdletbinding()]
    param(
        [parameter(
            Mandatory
        )]
        [ValidateScript( { if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [alias('id')]
        [String]$scanId,

        [parameter()]
        [String]$Hostname
    )

    $Scan = Get-ICScan -id $scanId
    if (-NOT $Scan) {
        Write-Error "ScanId does not exist"
        return
    }
    
    if ($hostname) {
        $where = @{ hostname = @{ ilike = $hostname }} 
    }
    $HostResult = Get-ICObject -Type Host -scanId $scanId -where $where | Select-Object -Last 1
    if (-NOT $HostResult) {
        Write-Error "No data found for $hostname"
        return
    }
    if (-NOT $where) {
        $where = @{ scanId = $scanId }
    } else {
        $where['scanId'] = $scanId
    }
    $Alerts = @()
    $Alerts += Get-ICAlert -where $where

    return [PSCustomObject]@{
        scanId              = $scanId
        hostId              = $HostResult.hostId
        os                  = $HostResult.osVersion
        success             = $(-NOT $HostResult.failed)
        compromised         = $HostResult.compromised
        completedOn         = $HostResult.completedOn
        alerts              = $Alerts
        hostname            = $HostResult.hostname
        ip                  = $HostResult.ip
    }
}

function Get-ICResponseResult {
    [cmdletbinding()]
    param(
        [parameter(
            Mandatory)]
        [ValidateScript( { if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [alias('id')]
        [String]$scanId,

        [parameter()]
        [String]$hostname
    )

    $Scan = Get-ICScan -id $scanId
    if (-NOT $Scan) {
        throw "ScanId does not exist"
    }
    if ($hostname) {
        $where = @{ hostname = @{ ilike = $hostname }} 
    }
    $HostResult = Get-ICObject -Type Host -scanId $scanId -where $where | Select-Object -Last 1
    if (-NOT $HostResult) {
        throw "No data found for $hostname"
    }
    if (-NOT $HostResult.failed) {
        $ExtensionResult = Get-ICObject -Type Extension -scanId $scanId -where $where -allinstances | Select-Object -Last 1
        $success = $ExtensionResult.success
    } else {
        $success = $false
    }
    
    return [PSCustomObject]@{
        scanId             = $scanId
        hostId             = $HostResult.hostId
        extensionId        = $ExtensionResult.ExtensionId
        os                 = $HostResult.osVersion
        success            = $success
        threatStatus       = $ExtensionResult.threatStatus
        compromised        = $HostResult.compromised
        completedOn        = $HostResult.completedOn
        runTime            = $ExtensionResult.runTime
        extensionName      = $ExtensionResult.name
        messages           = $ExtensionResult.output
        hostname           = $HostResult.hostname
        ip                 = $HostResult.ip
    }
}

function Get-ICVulnerability {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
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
                Write-Warning "No application found with applicationId: $Id in BoxId: $BoxId"
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
            Write-Warning "No Results found."
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
        [String]$sha1
    )
    PROCESS {
        Write-Verbose "Requesting FileReport on file with SHA1: $sha1"
        $fileReport = Get-ICAPI -Endpoint "FileReps/$sha1" -fields $fields
        $notes = Get-ICNote -relatedId $sha1
        if ($notes.count -eq $null) {
            $cnt = 1
        } else {
            $cnt = $notes.count
        }
        $fileReport | Add-Member -Type NoteProperty -name CommentCount -value $cnt
        $fileReport | Add-Member -Type NoteProperty -name Comments -value $notes
        return $fileReport
    }
}

function Get-ICNote {
    [cmdletbinding()]
    [alias("Get-ICComment")]
    Param(
        [parameter(
            Mandatory=$false, 
            ValueFromPipeline, 
            ValueFromPipelineByPropertyName)]
        [ValidateScript({ if ($_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Requires a relatedId or fileRepId (sha1) of 40 characters."} })]
        [alias('fileRepId')]
        [alias('sha1')]
        [String]$relatedId,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter")]
        [HashTable]$where
    )
    
    PROCESS {
        
        if (-NOT $where -AND $relatedId) {
            Write-Verbose "Getting notes/comments on object with id: $relatedId"
            $where += @{ relatedId = $relatedId }
        }
        else {
            Write-Verbose "Getting notes/comments on all objects."
        }
        $comments = Get-ICAPI -Endpoint "userComments" -where $where
        $users = Get-ICAPI -endpoint "users" -fields id, username
        $comments | ForEach-Object {
            $userId = $_.userId
            $user = $users | Where-Object { $_.id -eq $userId }
            $_ | Add-Member -Type Noteproperty -Name createdBy -Value $user.username
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
            $where = @{ id = $Id }
            #$Endpoint += "/$Id" (currently broken)
        }
        elseif (-NOT ($IncludeArchived -OR $Where['archived'])) {
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
        [String]$Id,

        [parameter(
            ParameterSetName="accountId",
            ValueFromPipelineByPropertyName=$true)]
        [String]$accountId,

        [parameter(
            ParameterSetName="fileRepId",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$true)]
        [alias('fileRepId')]
        [String]$sha1,

        [parameter(
            ParameterSetName="hostId",
            ValueFromPipelineByPropertyName=$true)]
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
        $Where['eventTime'] = @{ 
            between = @(
                (Get-Date $StartTime -Format "o"),
                (Get-Date $EndTime -Format "o")
            )
        }
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
                Get-ICBox -Global:$Global -Last $Last | Set-ICBox
            }
        }
    }
}
