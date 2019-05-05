
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from HUNT
function Get-ICObjects {
  [cmdletbinding()]
  param(
    [parameter(Mandatory=$true)]
    [ValidateSet(
      "Processes",
      "Modules",
      "Drivers",
      "Memory",
      "Artifacts",
      "Autostarts",
      "Hosts",
      "Connections",
      "Applications",
      "Vulnerabilities",
      "Accounts",
      "Scripts"
    )]
    [String]$Type,

    [String]$TargetGroupId,
    [String]$BoxId,
    [String]$ScanId,
    [HashTable]$where=@{},
    [Switch]$NoLimit
  )

  switch ( $Type ) {
    "Processes" { $Endpoint = 'IntegrationProcesses'    }
    "Modules" { $Endpoint = 'IntegrationModules'    }
    "Drivers" { $Endpoint = 'IntegrationDrivers'   }
    "Memory" { $Endpoint = 'IntegrationMemScans' }
    "Artifacts" { $Endpoint = 'IntegrationArtifacts'  }
    "Autostarts" { $Endpoint = 'IntegrationAutostarts' }
    "Hosts" { $Endpoint = 'IntegrationHosts'  }
    "Accounts" { # Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICAccounts"
                  if ($where -AND $BoxId) { Get-ICAccounts -BoxId $BoxId -where $where -NoLimit:$NoLimit }
                  elseif ($where) { Get-ICAccounts -where $where -NoLimit:$NoLimit }
                  elseif ($BoxId) { Get-ICAccounts -BoxId $BoxId -NoLimit:$NoLimit}
                  elseif ($ScanId) { Write-Warning "This type does not yet support ScanId. Use BoxId." }
                }
    "Scripts" { # Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICScripts"
                  if ($where -AND $BoxId) { Get-ICScripts -BoxId $BoxId -where $where -NoLimit:$NoLimit }
                  elseif ($where) { Get-ICScripts -where $where -NoLimit:$NoLimit }
                  elseif ($BoxId) { Get-ICScripts -BoxId $BoxId -NoLimit:$NoLimit}
                  elseif ($ScanId) { Write-Warning "This type does not yet support ScanId. Use BoxId." }
              }
    "Connections" { # Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICConnections"
                    if ($where -AND $BoxId) { Get-ICConnections -BoxId $BoxId -where $where -NoLimit:$NoLimit }
                    elseif ($where) { Get-ICConnections -where $where -NoLimit:$NoLimit }
                    elseif ($BoxId) { Get-ICConnections -BoxId $BoxId -NoLimit:$NoLimit}
                    elseif ($ScanId) { Write-Warning "This type does not yet support ScanId. Use BoxId." }
                  }
    "Applications" { # Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICApplications"
                      if ($where -AND $BoxId) { Get-ICApplications -BoxId $BoxId -where $where -NoLimit:$NoLimit }
                      elseif ($where) { Get-ICApplications -where $where -NoLimit:$NoLimit }
                      elseif ($BoxId) { Get-ICApplications -BoxId $BoxId -NoLimit:$NoLimit}
                      elseif ($ScanId) { Write-Warning "This type does not yet support ScanId. Use BoxId." }
                  }
    "Vulnerabilities" { # Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICVulnerabilities"
                        if ($where -AND $BoxId) { Get-ICVulnerabilities -BoxId $BoxId -where $where -NoLimit:$NoLimit }
                        elseif ($where) { Get-ICVulnerabilities -where $where -NoLimit:$NoLimit }
                        elseif ($BoxId) { Get-ICVulnerabilities -BoxId $BoxId -NoLimit:$NoLimit}
                        elseif ($ScanId) { Write-Warning "This type does not yet support ScanId. Use BoxId." }
                      }
    Default { }
  }
  if ($Endpoint) {
    $filter =  @{
      order = "hostCompletedOn desc"
      limit = $resultlimit
      skip = 0
      where = @{ and = @() }
    }
    if ($where.count -gt 0) {
      if ($where.keys -contains "and") {
        $filter['where'] = $where
      } else {
        $where | % {
          $filter['where']['and'] += $_
        }
      }
      if ($BoxId -AND ($filter['where']['and'].keys -notcontains 'boxId')) {
        $filter['where']['and'] += @{ boxId = $BoxId }
      }
    } else {
      if ($BoxId) { $filter['where']['and'] += @{ boxId = $BoxId } }
    }

    if ($scanId) { $filter.where['and'] += @{ scanId = $scanId } }
    elseif ($BoxId) { $filter.where['and'] += @{ boxId = $BoxId } }
    elseif ($TargetGroupId) { $filter.where['and'] += @{ targetId = $TargetGroupId } }

    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
  }
}

# Get Connection objects
function Get-ICConnections ([String]$BoxId, [HashTable]$where, [Switch]$All, [Switch]$NoLimit) {
  $Endpoint = "BoxConnectionInstances"
  $filter =  @{
    limit = $resultlimit
    skip = 0
    where = @{ and = @() }
  }

  if ($where.count -gt 0) {
    if ($where.keys -contains "and") {
      $filter['where'] = $where
    } else {
      $where | % {
        $filter['where']['and'] += $_
      }
    }
    if ($BoxId -AND ($filter['where']['and'].keys -notcontains 'boxId')) {
      $filter['where']['and'] += @{ boxId = $BoxId }
    }

  } else {
    if ($BoxId) { $filter['where']['and'] += @{ boxId = $BoxId } }
  }

  if (-NOT $All) { $filter.where['and'] += @{ state = "ESTABLISHED"} }

  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

# Get Account objects
function Get-ICAccounts ([String]$BoxId, [HashTable]$where, [Switch]$NoLimit) {
  $Endpoint = "BoxAccountInstancesByHost"
  $filter =  @{
    limit = $resultlimit
    skip = 0
    where = @{ and = @() }
  }

  if ($where.count -gt 0) {
    if ($where.keys -contains "and") {
      $filter['where'] = $where
    } else {
      $where | % {
        $filter['where']['and'] += $_
      }
    }
    if ($BoxId -AND ($filter['where']['and'].keys -notcontains 'boxId')) {
      $filter['where']['and'] += @{ boxId = $BoxId }
    }

  } else {
    if ($BoxId) { $filter['where']['and'] += @{ boxId = $BoxId } }
  }


  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

# Get Script objects
function Get-ICScripts ([String]$BoxId, [HashTable]$where, [Switch]$NoLimit) {
  $Endpoint = "BoxScriptInstances"

  $filter =  @{
    limit = $resultlimit
    order = "scannedOn desc"
    skip = 0
    where = @{ and = @() }
  }

  if ($where.count -gt 0) {
    if ($where.keys -contains "and") {
      $filter['where'] = $where
    } else {
      $where | % {
        $filter['where']['and'] += $_
      }
    }
    if ($BoxId -AND ($filter['where']['and'].keys -notcontains 'boxId')) {
      $filter['where']['and'] += @{ boxId = $BoxId }
    }

  } else {
    if ($BoxId) { $filter['where']['and'] += @{ boxId = $BoxId } }
  }

  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Get-ICApplications ([String]$BoxId, [HashTable]$where, [Switch]$NoLimit) {

  $Endpoint = "BoxApplicationInstances"
  $filter =  @{
    limit = $resultlimit
    order = "scannedOn desc"
    skip = 0
    where = @{ and = @() }
  }

  if ($where.count -gt 0) {
    if ($where.keys -contains "and") {
      $filter['where'] = $where
    } else {
      $where | % {
        $filter['where']['and'] += $_
      }
    }
    if ($BoxId -AND ($filter['where']['and'].keys -notcontains 'boxId')) {
      $filter['where']['and'] += @{ boxId = $BoxId }
    }

  } else {
    if ($BoxId) { $filter['where']['and'] += @{ boxId = $BoxId } }
  }

  $filter['where']['and'] += @{ name = @{ nilike = "*KB/d*" }}
  $filter['where']['and'] += @{ name = @{ nilike = "*Update for*" }}

  $apps = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
  $apps | Sort-Object hostname, applicationId -unique
}

function Get-ICVulnerabilities {
  [cmdletbinding()]
  param(
    [String]$BoxId,
    [HashTable]$where,
    [Switch]$NoLimit
  )

  if ($where -AND $BoxId) { $apps = Get-ICApplications -BoxId $BoxId -where $where -NoLimit:$NoLimit }
  elseif ($where) { $apps = Get-ICApplications -where $where -NoLimit:$NoLimit }
  elseif ($BoxId) { $apps = Get-ICApplications -BoxId $BoxId -NoLimit:$NoLimit }
  else { $apps = Get-ICApplications -NoLimit:$NoLimit }

  $Endpoint = "ApplicationAdvisories"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  $appvulns = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit | sort-object applicationId, cveId -unique

  if ($apps -AND $appvulns) {
    $appids = $apps.applicationid | sort-object -unique
    $appvulns = $appvulns | where { $appids -contains $_.applicationId }

    Write-Verbose "Found $($appids.count) applications and $($appvulns.count) associated advisories. Enriching details for export..."
    $appvulns | where { $appids -contains $_.applicationId } | % {
      $vuln = $_
      Write-Verbose "Vulnerable App: $($vuln.ApplicationName) cveId: $($vuln.cveId) App id: $($vuln.applicationId)"

      if ($vuln.cveId) {
        $Endpoint = "Cves/$($vuln.cveId)"
        $filter =  @{
          limit = $resultlimit
          skip = 0
        }
			  $cve = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
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
    Write-Host "DONE: Exporting $($appvulns.count) Vulnerabilities"
    $appvulns
  }
}

# Get Full FileReport on an object by sha1
function Get-ICFileDetail {
  Param(
    [ValidateNotNullorEmpty()]
    [String]$sha1
  )

	Write-Verbose "Requesting FileReport on file with SHA1: $sha1"
	$Endpoint = "FileReps/$sha1"
  $object = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter
	$object | Add-Member -Type NoteProperty -Name 'avpositives' -Value $_.avResults.positives
	$object | Add-Member -Type NoteProperty -Name 'avtotal' -Value $_.avResults.total
	return $object
}

# Get Account objects
function Get-ICAlerts {
  [cmdletbinding()]
  param(
    [Switch]$IncludeArchived,
    [Switch]$NoLimit
  )

  $Endpoint = "Alerts"

  $filter =  @{
    limit = $resultlimit
    skip = 0
    where = @{ archived = $FALSE }
  }
  if ($IncludeArchived) { $filter.Remove('where') }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Get-ICReports {
  [cmdletbinding()]
  param(
    [String]$ReportId,
    [Switch]$NoLimit
  )

  $filter =  @{
    order = @("createdOn DESC","id")
    limit = $resultlimit
    skip = 0
  }

  if ($ReportId) {
    $Endpoint = "Reports/$ReportId"
  } else {
    $Endpoint = "Reports"
    $filter['fields'] = @("id","name","createdOn","type","hostCount")
  }

  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Get-ICActivityTrace {
  [cmdletbinding()]
  param(
    [String]$AccountId,
    [String]$SHA1,
    [String]$HostId,
    [DateTime]$StartTime,
    [DateTime]$EndTime,
    [Switch]$Enriched,
    [Switch]$NoLimit
  )

  if (-NOT $StartTime) { $StartTime = (Get-Date).AddDays(-30) }
  if (-NOT $EndTime) { $EndTime = Get-Date }

  $Endpoint = "activity"
  $filter =  @{
    limit = $resultlimit
    skip = 0
    order = @("eventTime desc")
    where = @{
      and = @(
        @{ eventTime = @{ gt = (Get-Date $StartTime -Format "yyyy-MM-dd HH:mm:ss") } },
        @{ eventTime = @{ lt = (Get-Date $EndTime -Format "yyyy-MM-dd HH:mm:ss") } }
      )
    }
  }

  if ($SHA1) {
    $filter['where']['and'] += @{ fileRepId = $SHA1 }
  }
  elseif ($AccountId) {
    $filter['where']['and'] += @{ accountId = $AccountId }
  }
  elseif ($HostId) {
    $filter['where']['and'] += @{ hostId = $HostId }
  }

  if ($enriched) {

  } else {
    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
  }

}
