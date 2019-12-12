
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from HUNT
function Get-ICObject {
    [cmdletbinding()]
    [alias("Get-ICData","Get-ICObjects")]
    param(
        [parameter()]
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

        [String]$BoxId=$Global:ICCurrentBox,

        [HashTable]$where=@{},

        [String[]]$order,

        [Switch]$NoLimit,
        [Switch]$CountOnly
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
    if (-NOT $BoxId) {
        # Default to 7 day view if not provided
        Write-Verbose "No BoxId provided. Defaulting to 'Last 7' Days."
        $BoxId = (Get-ICBox -Last7 -Global).id
    }
    $where['boxId'] = $BoxId

    switch ( $Type ) {
        "Connection" {
            $Endpoint = 'BoxConnectionInstances'
            if (-NOT $where) {
                $where += @{ state = "ESTABLISHED"}
            }
        }
        "Host" {
            $Endpoint = 'BoxHosts'
            if (-NOT $order) { $order = 'completedOn desc' }
        }
        "Account" {
            $Endpoint = 'BoxAccountInstancesByHost'
        }
        "Application" {
            $Endpoint = 'BoxApplicationInstances'
        }
        "File" {
            If ($where.count -lt 2) {
                Write-Warning "Not Accepted: You should provide a filter for this query to reduce strain on the database."
                return
            }
            $cnt = 0
            $Files | % {
                if ($CountOnly) {
                    $c = Get-ICObject -Type $_ -BoxId $BoxId -where $where -CountOnly
                    Write-Verbose "Found $c $_ Objects"
                    $cnt += $c
                } else {
                    Write-Verbose "Querying $_"
                    Get-ICObject -Type $_ -BoxId $BoxId -where $where -NoLimit:$NoLimit
                }
            }
            if ($CountOnly) {
                return $cnt
            }
        }
        Default {
            $Endpoint = "Box$($Type)Instances"
            if (-NOT $order) { $order = "scannedOn desc" } # "hostCompletedOn desc"
        }
    }
    if ($Type -ne 'File') {
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}


function Set-ICBox {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('BoxId')]
        [String]$Id
    )

    Write-Host "`$Global:ICCurrentBox is now set to $Id"
    $Global:ICCurrentBox = $Id
    return
}

function Get-ICApplication {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipelineByPropertyName)]
        [alias('applicationId')]
        [String]$Id,

        [String]$BoxId=$Global:ICCurrentBox,
        [HashTable]$where=@{},
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    BEGIN {
        $Endpoint = "BoxApplicationInstances"
        if (-NOT $BoxId) {
            # Default to 7 day view if not provided
            Write-Verbose "No BoxId provided. Defaulting to 'Last 7' Days."
            $BoxId = (Get-ICBox -Last7 -Global).id
        }
        $where['boxId'] = $BoxId
    }
    PROCESS {
        if ($Id) {
            $where['applicationId'] = $Id
        }
        $apps += Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit

    }

    END {
        $apps | Sort-Object hostname, applicationId -unique
    }
}


function Get-ICVulnerability {
    [cmdletbinding()]
    param(
        [String]$BoxId=$Global:ICCurrentBox,
        [HashTable]$where=@{},
        [Switch]$NoLimit
    )

    if (-NOT $BoxId) {
        # Default to 7 day view if not provided
        Write-Verbose "No BoxId provided. Defaulting to 'Last 7' Days."
        $BoxId = (Get-ICBox -Last7 -Global).id
    }
    $where['boxId'] = $BoxId

    Write-Verbose "Building Application table..."
    $apps = Get-ICApplications -BoxId $BoxId -where $where -NoLimit:$NoLimit

    $Endpoint = "ApplicationAdvisories"
    Write-Verbose "Building Application Advisory table..."
    $appvulns = Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit | sort-object applicationId, cveId -unique

    if ($apps -AND $appvulns) {
        $appids = $apps.applicationid | sort-object -unique
        $appvulns = $appvulns | where { $appids -contains $_.applicationId }
        $apps = $apps | where { $appvulns.applicationId -contains $_.applicationId }

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
        [HashTable]$where=@{},
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
        [HashTable]$where=@{},
        [String[]]$order=@("createdOn DESC"),
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
