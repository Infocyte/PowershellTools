
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from Infoyte
function New-ICFilter {
    [cmdletbinding()]
    param(
        [HashTable]$Where=@{},
        $Trailing,
        $StartTime,
        $EndTime,
        $ScanId,
        $Timefield="scannedOn"
    )

    Write-Debug "ScanId: $ScanId, Trailing: $Trailing, StartTime: $StartTime, EndTime: $EndTime, Timefield: $Timefield, Where:`n$($where|ConvertTo-Json -depth 10)"
    if ($where.ContainsKey('or')) {
        # handle this wierd loopback thing where 'or' filters screw things up
        # wrap everything in an explicit 'and'
        Write-Warning "There is a known issue with Loopback where filters that cause problems with first level 'or' filters."
        Write-Warning "You should wrap everything in an 'And' filter to make sure this works."
        throw "Unnested OR filter in base."
    }

    if (-NOT ($Trailing -OR $StartTime -OR $EndTime -OR $ScanId)) {
        Write-Debug "No additional filters selected:`n$($where|ConvertTo-Json -depth 10)"
        return $where
    }
    elseif ($where.keys -notcontains 'and') {
        $where['and'] = @()
    }

    if ($ScanId -AND (-NOT $where.scanId) -AND ($where['and'].keys -notcontains 'scanId')) {
        Write-Debug "Adding scanId to filter"
        if ($where.Count -eq 0) {
            $where = @{ scanId = $scanId }
        }
        else {
            $where['and'] += @{ scanId = $scanId }
        }
    }
    elseif (($Trailing -OR $StartTime -OR $EndTime) -AND $where.keys -notContains $Timefield -AND $where['and'].Keys -notcontains $Timefield) {
        Write-Debug "Adding time bounds to filter"
        #Time Window
        if ($Trailing) {
            Write-Debug "Converting StartTime to trailing filter"
            $StartTime = (Get-Date).AddDays(-$Trailing)
            $EndTime = $null
        }

        if ($StartTime) { 
            Write-Debug "Adding StartTime to filter"
            $where['and'] += @{ "$Timefield" = @{ gte = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }}
        }
        if ($EndTime) {
            Write-Debug "Adding StartTime to filter"
            $where['and'] += @{ "$Timefield" = @{ lte = $EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }}
        }
    }
    Write-Debug "where-filter:`n$($where|ConvertTo-Json -depth 10)"
    return $where
}

function Get-ICEvent {
    [cmdletbinding(DefaultParameterSetName="Trailing")]
    [alias("Get-ICData", "Get-ICObject")]
    param(
        [parameter(ValueFromPipeline)]
        [ValidateScript( { if ($_ -match $GUID_REGEX -OR $_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [String]$Id,

        [parameter(
            Mandatory=$true,
            HelpMessage="Data is currently seperated into object-type tables. 'File' will perform a recursive call of all file types (process, module, driver, artifact, and autostart.")]
        [ValidateSet(
          "Process",
          "Module",
          "Driver",
          "MemScan",
          "Artifact",
          "Autostart",
          "Connection",
          "Application",
          "Account",
          "Script",
          "File",
          "Extension",
          "Host"
        )]
        [String]$Type,

        [parameter(
            ParameterSetName="Trailing",
            HelpMessage={"Trailing Days"})]
        [Int]$Trailing,

        [parameter(
            ParameterSetName="Time",
            HelpMessage={"Starting timestamp of items."})]
        [DateTime]$StartTime,

        [parameter(
            ParameterSetName="Time",
            HelpMessage={"Last timestamp of items. Default = Now"})]
        [DateTime]$EndTime,

        [parameter(
            ParameterSetName = "Scan")]
        [ValidateScript( { if ($_ -match $GUID_REGEX -OR $_ -match "\b[0-9a-f]{40}\b") { $true } else { throw "Incorrect input: $_.  Should be a guid." } })]
        [string]$ScanId,

        [Switch]$CountOnly,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter")]
        [HashTable]$where=@{},

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields,

        [Switch]$AllInstances,
        [Switch]$Simple,

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

    if ($Type -eq "Host") {
        $Timefield = "completedOn"
    } else {
        $Timefield = "scannedOn"
    }

    Write-Debug "ParameterSetName: $($PSCmdlet.ParameterSetName)"
    switch ( $PSCmdlet.ParameterSetName )
    {
        "Trailing" { 
            if (-NOT $Trailing) {
                Write-Warning "No filters set: Setting default time window to trailing last 7 days" 
                $Trailing = 7 
            }
            elseif ($Trailing -ge 90) {
                $Trailing = $null
            }
            $where = New-ICFilter -Where $where -Trailing $Trailing -timefield $Timefield
        }
        "Time" { 
            $where = New-ICFilter -Where $where -StartTime $StartTime -EndTime $EndTime -timefield $Timefield
        }
        "Scan" { 
            $where = New-ICFilter -Where $where -ScanId $scanId -timefield $Timefield
        }
    }

    switch ( $Type ) {
        "Host" {
            $Endpoint = "ScanHosts"
            if ($Simple) {
                $fields = $(
                    "id", 
                    "completedOn",
                    "hostname",
                    "ip",
                    "name",
                    "domain",
                    "osVersion",
                    "architecture"
                )
            }
        }
        "Extension" {
            $Endpoint = "ScanExtensionDetails"
            if (-NOT $fields) {
                $fields = $(
                    "id", 
                    "extensionId",
                    "extensionVersionId",
                    "output",
                    "hostScanId",
                    "success",
                    "threatStatus",
                    "startedOn",
                    "endedOn",
                    "name",
                    "hostId",
                    "scanId",
                    "scannedOn",
                    "hostname",
                    "ip"
                )
            } else {
                $fields | Where-Object { $_ -notmatch "(outputString|body|createdOn)"}
            }
            if ($Simple) {
                $fields | Where-Object { $_ -notmatch ".+Id$"}
            }
            
        }
        "Extension" {
            $Endpoint = "ScanExtensionDetail"
            if (-NOT $fields) {
                $fields = @("id", "extensionId", "extensionVersionId", "hostname", "ip", "sha256",
                "hostScanId", "success", "threatStatus", "name", "hostId", "scanId", "scannedOn", "startedOn", "endedOn", "outputString")
            }           
        }
        "Extension" {
            $Endpoint = "ScanExtensionDetail"
            if (-NOT $fields) {
                $fields = @("id", "extensionId", "extensionVersionId", "hostname", "ip", "sha256",
                "hostScanId", "success", "threatStatus", "name", "hostId", "scanId", "scannedOn", "startedOn", "endedOn", "outputString")
            }           
        }
        "File" {
            $cnt = 0
            $Files | ForEach-Object {
                if ($CountOnly) {
                    $c = Get-ICObject -Type $_ -where $where -CountOnly
                    Write-Verbose "Found $c $_ Objects"
                    $cnt += $c
                } else {
                    $fields = $(
                        "id", 
                        "scannedOn",
                        "hostname",
                        "filerepId",
                        "name",
                        "path",
                        "commandLine",
                        "artifactType",
                        "modifiedOn",
                        "autostartType"
                        "regPath",
                        "value",
                        "signed",
                        "avPositives",
                        "avTotal",
                        "threatName",
                        "flagName"
                    )
                    $filetype = $_
                    Write-Verbose "Querying $filetype"
                    Get-ICObject -Type $_ -where $where -fields $fields -NoLimit:$NoLimit | ForEach-Object {
                        $_ | Add-Member -MemberType NoteProperty -Name fileType -Value $filetype
                    }
                }    
            }
            if ($CountOnly) {
                return $cnt
            }
            return
        }
        Default {
            $Endpoint = "Scan$($Type)Instances"
        }
    }

    if ($Id) {
        $CountOnly = $false
        $Endpoint += "/$id"
    }
    if ($CountOnly) { 
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    } else {
        Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit     
    }
}


function Get-ICObject_old {
    [cmdletbinding(DefaultParameterSetName="Box")]
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

    Write-Verbose "Got $where"
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
                $Endpoint = "ScanProcessInstances"
        }
        "Script" {
                $Endpoint = "ScanScriptInstances"
        }
        "Account" {
            $Endpoint = "ScanAccountInstancesByHost"
        }
        "Extension" {
            $Endpoint = "ScanExtensionInstances"
            $fields = @("id", "extensionId", "extensionVersionId", "hostname", "ip", "sha256",
                "hostScanId", "success", "threatStatus", "name", "hostId", "scanId", "scannedOn", "startedOn", "endedOn", "output")
        }
        "File" {
            $cnt = 0
            $Files | ForEach-Object {
                if ($CountOnly) {
                    if ($ScanId) {
                        $c = Get-ICObject -Type $_ -ScanId $ScanId -where $where  -CountOnly
                    } else {
                        $c = Get-ICObject -Type $_ -BoxId $BoxId -where $where  -CountOnly
                    }
                    Write-Verbose "Found $c $_ Objects"
                    $cnt += $c
                } else {
                    Write-Verbose "Querying $_"
                    if ($ScanId) {
                        Get-ICObject -Type $_ -ScanId $ScanId -where $where -fields $fields -NoLimit:$NoLimit 
                    } else {
                        Get-ICObject -Type $_ -BoxId $BoxId -where $where -fields $fields -NoLimit:$NoLimit 
                    }
                }    
            }
            if ($CountOnly) {
                return $cnt
            }
        }
        Default {
            $Endpoint = "Scan$($Type)Instances"
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
        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter")]
        [HashTable]$where=@{},

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields,

        [Switch]$NoLimit,

        [Switch]$CountOnly
    )

    if ($Id) {
        $CountOnly = $false
        $Endpoint += "/$id"
    }
    if ($CountOnly) { 
        Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
    } else {
        Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit     
    }
}

# Fix for time window
function Get-ICVulnerability {
    [cmdletbinding()]
    param(
        [parameter(
            ValueFromPipeline, 
            Mandatory,
            HelpMessage="Pipe in applications from Get-ICEvent or Get-ICObject")]
        [PSCustomObject[]]$Applications,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{}
    )

    BEGIN {
        
    }

    PROCESS {
        if (-NOT $applications.applicationId) {
            Write-Error "Input is not an application instance or list of application instances"
            continue
        } else {
            $apps += $applications
        }
    }

    END {
        #$where.remove('boxId') | Out-Null
        Write-Verbose "Building Application Advisory bridge table"
        $appvulns = Get-ICAPI -Endpoint "ApplicationAdvisories" -where $where -NoLimit:$true | sort-object applicationId, cveId -unique

        if ($apps -AND $appvulns) {
            $appids = $apps.applicationid | sort-object -unique
            $appvulns = $appvulns | Where-Object { $appids -contains $_.applicationId }
            $apps = $apps | Where-Object { $appvulns.applicationId -contains $_.applicationId }
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

# Add time window
function Get-ICAlert {
    [cmdletbinding(DefaultParameterSetName="Trailing")]
    param(
        [parameter(ValueFromPipeline)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$Id,

        [parameter(
            Mandatory=$true,
            HelpMessage="Alert sources can be from reputation, rules, compliance, or extension")]
        [ValidateSet(
          "rule",
          "reputation",
          "compliance",
          "extension",
          "all"
        )]
        [String]$sourceType = "all",

        [parameter(
            ParameterSetName="Trailing",
            HelpMessage={"Trailing Days"})]
        [Int]$Trailing,

        [parameter(
            ParameterSetName="Time",
            HelpMessage={"Starting timestamp of items."})]
        [DateTime]$StartTime,

        [parameter(
            ParameterSetName="Time",
            HelpMessage={"Last timestamp of items. Default = Now"})]
        [DateTime]$EndTime,

        [Switch]$IncludeArchived,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields,
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        
        $Timefield = "createdOn"

        Write-Debug "ParameterSetName: $($PSCmdlet.ParameterSetName)"
        Write-Debug "Trailing: $Trailing, StartTime: $StartTime, EndTime: $EndTime, Timefield: $Timefield, Where:`n$($where|ConvertTo-Json -depth 10)"
    
        switch ( $PSCmdlet.ParameterSetName )
        {
            "Trailing" {
                if ($Trailing) {
                    $where = New-ICFilter -Where $where -Trailing $Trailing -timefield $Timefield
                }
            }
            "Time" { 
                $where = New-ICFilter -Where $where -StartTime $StartTime -EndTime $EndTime -timefield $Timefield
                Write-Verbose "$($where|ConvertTo-Json -depth 10)"
            }
        }
        
        if ($sourceType -ne "all") {
            if ($where.Keys -contains 'and') {
                $where['and'] += @{ sourceType = $sourceType }
            } else {
                $where['sourceType'] = $sourceType
            }
        }
        $Endpoint = "Alerts"
        if ($Id) {
            $CountOnly = $false
            $Endpoint += "/$Id"
        } else {
            if ($Trailing -gt 30 -OR ($StartTime -AND $StartTime -lt (Get-Date).AddDays(-30))) {
                Write-Verbose "Querying Alert Archive Table for alerts older than 30 days..."
                Get-ICAPI -Endpoint "$($Endpoint)archive" -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
            }
            elseif (-NOT ($IncludeArchived -OR $Where['archived'] -OR $where['and'].Keys -contains 'archived')) {
                if ($where.Keys -contains 'and') {
                    $where['and'] += @{ archived = $FALSE }
                } else {
                    $Where['archived'] = $FALSE
                }
            }
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
