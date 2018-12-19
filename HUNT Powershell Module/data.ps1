
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from HUNT
function Get-ICObjects {
  [cmdletbinding()]
  param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$Type,

    [String]$TargetGroupId,
    [String]$BoxId,
    [String]$ScanId,
    [HashTable]$where=@{},
    [Switch]$NoLimit
  )

  $ObjTypes = @(
    "Processes"
    "Modules"
    "Drivers"
    "Memory"
    "Artifacts"
    "Autostarts"
    "Hosts"
    "Connections"
    "Applications"
    "Vulnerabilities"
    "Accounts"
    "Scripts"
  )
  if (-NOT $Type) {
    Write-Warning "Choose an object type to retrieve using -Type:"
    Write-Warning "$ObjTypes"
    return
  } else {
    switch ( $Type ) {
        "Processes" { $Endpoint = 'IntegrationProcesses'    }
        "Modules" { $Endpoint = 'IntegrationModules'    }
        "Drivers" { $Endpoint = 'IntegrationDrivers'   }
        "Memory" { $Endpoint = 'IntegrationMemScans' }
        "Artifacts" { $Endpoint = 'IntegrationArtifacts'  }
        "Autostarts" { $Endpoint = 'IntegrationAutostarts' }
        "Hosts" { $Endpoint = 'IntegrationHosts'  }
        "Accounts" { Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICAccounts" }
        "Scripts" { Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICScripts" }
        "Connections" { Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICConnections" }
        "Applications" { Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICApplications" }
        "Vulnerabilities" { Write-Warning "This type is not yet supported by the Integration APIs. Use Get-ICVulnerabilities" }
        Default { Write-Warning "Choose an object type to retrieve using -Type:";
                  Write-Warning "$ObjTypes";
                  throw "$Type is not an object type in HUNT."
                }
    }
  }
  $filter =  @{
    order = "hostCompletedOn desc"
    limit = $resultlimit
    skip = 0
    where = @{ and = @() }
  }

  if ($where) {
    $filter['where'] = $where
  } else {
    if ($scanId) { $filter.where['and'] += @{ scanId = $scanId } }
    elseif ($BoxId) { $filter.where['and'] += @{ boxId = $BoxId } }
    elseif ($TargetGroupId) { $filter.where['and'] += @{ targetId = $TargetGroupId } }
  }

  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

# Get Connection objects
function Get-ICConnections ([String]$BoxId, [HashTable]$where, [Switch]$All, [Switch]$NoLimit) {
  $Endpoint = "BoxConnectionInstances"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  if (-NOT $where) {
    $filter['where'] = @{
      and = @()
    }
    if ($BoxId) { $filter.where['and'] += @{ boxId = $BoxId } }
    if (-NOT $All) { $filter.where['and'] += @{ state = "ESTABLISHED"} }
  } else {
    $filter['where'] = $where
  }

  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

# Get Account objects
function Get-ICAccounts ([String]$BoxId, [HashTable]$where, [Switch]$NoLimit) {
  $Endpoint = "BoxAccountInstances"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  if (-NOT $where) {
    $filter['where'] = @{
      and = @()
    }
    if ($BoxId) { $filter.where['and'] += @{ boxId = $BoxId } }
  } else {
    $filter['where'] = $where
  }

  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

# Get Script objects
function Get-ICScripts ([String]$BoxId, [HashTable]$where, [Switch]$NoLimit) {
  $Endpoint = "BoxScriptInstances"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  if (-NOT $where) {
    $filter['where'] = @{
      and = @()
    }
    if ($BoxId) { $filter.where['and'] += @{ boxId = $BoxId } }
  } else {
    $filter['where'] = $where
  }

  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}


function Get-ICApplications ([String]$BoxId, [HashTable]$where, [Switch]$NoLimit) {

  $Endpoint = "BoxApplicationInstances"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  if (-NOT $where) {
    $where = @{}
    if ($BoxId) { $where['boxId'] = $BoxId }
  }
  if ($where.count -gt 0) { $filter['where'] = $where }
  $apps = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
  $apps | where { $_.name -notmatch "KB|Update for" } | Sort-Object hostname, applicationId -unique
}

function Get-ICVulnerabilities {
  [cmdletbinding()]
  param(
    [Switch]$NoLimit
  )

  $Endpoint = "ApplicationAdvisories"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  $appvulns = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit | sort-object applicationId, cveId -unique

  if ($appvulns) {
    Write-Verbose "Found $($appvulns.count) App Vulns. Enriching details for export..."
    $appvulns | % {
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
    [String]$BoxId,
    [String[]]$flagNames,
    [Switch]$NoLimit
  )

  $where = @{
    and = @(
      @{ or = @(
        @{ threatName = "Bad" },
        @{ threatName = "Blacklist" },
        @{ flagName = "Verified Bad" })
      }
    )
  }
  if ($flagNames) {
    $flagNames | where { $_ -ne $Null -OR $_ -ne "" } | % {
      $where['and']['or'] += @{ flagName = $_ }
    }
  }
  if ($BoxId) { $where['and'] += @{ boxId = $BoxId } }

  Get-ICObjects -Type Processes -where $where | where { $_.flagName -ne "Verified Good" }
  Get-ICObjects -Type Modules -where $where | where { $_.flagName -ne "Verified Good" }
  Get-ICObjects -Type Drivers -where $where | where { $_.flagName -ne "Verified Good" }
  Get-ICObjects -Type Memory -where $where | where { $_.flagName -ne "Verified Good" }
  Get-ICObjects -Type Artifacts -where $where | where { $_.flagName -ne "Verified Good" }
  Get-ICObjects -Type Autostarts -where $where | where { $_.flagName -ne "Verified Good" }
  # Get-ICObjects -Type Scripts -where $where
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
