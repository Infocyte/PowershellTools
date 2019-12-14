
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from Infoyte
function Get-ICObject {
    [cmdletbinding()]
    [alias("Get-ICData","Get-ICObjects")]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [String]$Id,

        [parameter(HelpMessage="Data is currently seperated into object-type tables. 'File' will perform a recursive call of all files.")]
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
        [String]$Type="File",

        [parameter(HelpMessage={"Boxes are the 7, 30, and 90 day views of target group or global data. Use Set-ICBox to set your default. CurrentDefault: $Global:ICCurrentBox"})]
        [String]$BoxId=$Global:ICCurrentBox,
        [parameter(HelpMessage="Defaults to aggregated variants of files (normalized by hash+path). Use this switch to get all instances of the object found.")]
        [Switch]$AllInstances,

        [Switch]$CountOnly,
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order,

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


    if ($where -AND $where['boxId']) {
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
        "File" {
            If ($where.count -lt 2) {
                Write-Warning "Not Accepted: You should provide a filter for this query to reduce strain on the database."
                return
            }
            $cnt = 0
            $Files | % {
                if ($CountOnly) {
                    $c = Get-ICObject -Type $_ -BoxId $BoxId -where $where -AllInstances:$AllInstances -CountOnly
                    Write-Verbose "Found $c $_ Objects"
                    $cnt += $c
                } else {
                    Write-Verbose "Querying $_"
                    Get-ICObject -Type $_ -BoxId $BoxId -where $where -NoLimit:$NoLimit -AllInstances:$AllInstances
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
            $order = $Null
            $Endpoint += "/$id"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICVulnerability {
    [cmdletbinding()]
    param(
        [parameter(HelpMessage={"Boxes are the 7, 30, and 90 day views of target group or global data. Use Set-ICBox to set your default. CurrentDefault: $Global:ICCurrentBox"})]
        [String]$BoxId=$Global:ICCurrentBox,
        [Switch]$CountOnly,
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order,
        [Switch]$NoLimit
    )

    if ($where -AND $where['boxId']) {
        $where['boxId'] = $BoxId
    } else {
        $where += @{ boxId = $BoxId }
    }

    $Endpoint = "ApplicationAdvisories"
    Write-Verbose "Building Application Advisory table with $where filter..."
    $appvulns = Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit | sort-object applicationId, cveId -unique

    Write-Verbose "Building Application table..."
    $apps = Get-ICObjects -Type Application -BoxId $BoxId -where $where -NoLimit:$NoLimit

    if ($apps -AND $appvulns) {
        $appids = $apps.applicationid | sort-object -unique
        $appvulns = $appvulns | where { $appids -contains $_.applicationId }
        $apps = $apps | where { $appvulns.applicationId -contains $_.applicationId }
    } else {
        Write-Verbose "No Results found."
        return
    }

    Write-Verbose "Found $($appids.count) applications and $($appvulns.count) associated advisories. Enriching details for export..."
    $appvulns | % {
        $vuln = $_
        Write-Verbose "Vulnerable App: $($vuln.ApplicationName) cveId: $($vuln.cveId) App id: $($vuln.applicationId)"
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
        $applicationvulnerabilities = Join-Object -Left $apps -Right $appvulns -LeftJoinProperty 'applicationid' -RightJoinProperty 'applicationid' -Type OnlyIfInBoth
        #-RightProperties cveId, description, baseScoreV2, baseScoreV3, published, modified

        Write-Host "DONE: Exporting $($applicationvulnerabilities.count) Vulnerabilities"
        Write-Output $applicationvulnerabilities
    }
}

# Get Full FileReport on an object by sha1
function Get-ICFileDetail {
    Param(
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [alias('fileRepId')]
        [String]$sha1
    )
    PROCESS {
        Write-Verbose "Requesting FileReport on file with SHA1: $sha1"
        Get-ICAPI -Endpoint "FileReps/$sha1"
    }
}

# Get Account objects
function Get-ICAlert {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [String]$Id,
        [Switch]$IncludeArchived,
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order='createdOn desc',
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        $Endpoint = "AlertDetails"
        if ($Id) {
            $Endpoint += "/$Id"
        }
        if (-NOT ($IncludeArchived -OR $Where['archived'])) {
            $Where += @{ archived = $FALSE }
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICReport {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('ReportId')]
        [String]$Id,
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order="createdOn DESC",
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($Id) {
            $Endpoint = "Reports/$Id"
        } else {
            $Endpoint = "Reports"
            $fields = @("id","name","createdOn","type","hostCount")
        }

        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Get-ICActivityTrace {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [String]$accountId,

        [parameter(ValueFromPipelineByPropertyName)]
        [alias('fileRepId')]
        [String]$sha1,

        [parameter(ValueFromPipelineByPropertyName)]
        [String]$hostId,

        [DateTime]$StartTime=(Get-Date).AddDays(-7).ToUniversalTime(),
        [DateTime]$EndTime = (Get-Date).ToUniversalTime(),
        [HashTable]$where=@{},
        [String[]]$order= @("eventTime desc"),
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    BEGIN {
        #if (-NOT $StartTime) { $StartTime = (Get-Date).AddDays(-7) }
        #if (-NOT $EndTime) { $EndTime = Get-Date }
        $Where['between'] = @(
            (Get-Date $StartTime -Format "yyyy-MM-dd HH:mm:ss"),
            (Get-Date $EndTime -Format "yyyy-MM-dd HH:mm:ss")
        )
    }
    PROCESS {
        $Endpoint = "activity"

        if ($SHA1) {
            $where['fileRepId'] = $SHA1
        }
        if ($AccountId) {
            $where['accountId'] = $AccountId
        }
        if ($HostId) {
            $where['hostId'] = $HostId
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

function Set-ICBox {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('BoxId')]
        [String]$Id
    )
    $box = Get-ICbox -id $Id
    Write-Host "`$Global:ICCurrentBox is now set to $($box.targetGroup)-$($box.name) [$Id]"
    $Global:ICCurrentBox = $Id
    return
}
