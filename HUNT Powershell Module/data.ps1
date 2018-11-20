
# General function for getting various objects (files, processes, memory injects, autostarts, etc.) from HUNT
function Get-ICObjects ([String]$Type, [String]$TargetGroupId=$null, [String]$BoxId=$null, [String]$ScanId=$null, [HashTable]$where=@{}, [Switch]$NoLimit) {
  $ObjTypes = @(
    "Processes"
    "Modules"
    "Drivers"
    "Memory"
    "Artifacts"
    "Autostarts"
    "Hosts"
    # "Accounts" TO DO
    # "Scripts" TO DO
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
        "Autostarts" { $Endpoint = 'IntegrationAutostarts'    }
        "Hosts" { $Endpoint = 'IntegrationHosts'  }
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
  }
  if ($TargetGroupId) { $where['targetId'] = $TargetGroupId }
  if ($scanId) { $where['scanId'] = $scanId }
  if ($BoxId) { $where['boxId'] = $BoxId }

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
    $where = @{
      and = @()
    }
    if ($BoxId) { $where['and'] += @{ boxId = $BoxId } }
    if (-NOT $All) { $where['and'] += @{ state = "ESTABLISHED"} }
  }
  if ($where.count -gt 0) { $filter['where'] = $where }
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}


function Get-ICApplications ($BoxId, [HashTable]$where, [Switch]$NoLimit) {
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
  _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$NoLimit
}

function Get-ICVulnerabilities ($BoxId, [HashTable]$where, [Switch]$NoLimit) {
  $Vulnerabilities = @()
  # Get Applications
  $apps = Get-ICApplications -BoxId $BoxId -NoLimit:$NoLimit | where { $_.name -notmatch "KB|Update" }
  Write-Verbose "Found $($apps.count) Installed Apps."
  $Endpoint = "ApplicationAdvisories"
  $filter =  @{
    limit = $resultlimit
    skip = 0
  }
  $apps | % {
    $app = $_
    $Endpoint = "ApplicationAdvisories"
    $filter =  @{
      where = @{ applicationId = $_.applicationId }
    	limit = $resultlimit
    	skip = 0
    }
    $appvulns = @()
    $appvulns += _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
    if ($appvulns) {
      Write-Verbose "Recieved $($appvulns.count) App Vulns for $($app.name)."
      $filter =  @{
        limit = $resultlimit
        skip = 0
      }
      $appvulns | Sort-Object id -unique | % {
        $va = $_
        Write-Verbose "Vulnerable App: $($va.ApplicationName) cveId: $($va.cveId) App id: $($app.id) VulnApp id: $($va.id)"
        $vuln = $app.PSObject.Copy()
        $vuln.id = [guid]::newguid().guid
        $vuln | Add-Member -MemberType "NoteProperty" -name "cveId" -value $va.cveId
  			$vuln | Add-Member -MemberType "NoteProperty" -name "baseScoreV2" -value $va.baseScoreV2
  			$vuln | Add-Member -MemberType "NoteProperty" -name "baseScoreV3" -value $va.baseScoreV3
  			$vuln | Add-Member -MemberType "NoteProperty" -name "published" -value $va.published
  			$vuln | Add-Member -MemberType "NoteProperty" -name "modified" -value $va.modified

        if ($va.cveId) {
          $Endpoint = "Cves/$($va.cveId)"
				  $cve = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
          if ($cve) {
            $vuln | Add-Member -MemberType "NoteProperty" -name "rules" -value $cve.rules
  					$vuln | Add-Member -MemberType "NoteProperty" -name "cwes" -value $cve.cwes
  					$vuln | Add-Member -MemberType "NoteProperty" -name "reference" -value $cve.reference.url
  					$vuln | Add-Member -MemberType "NoteProperty" -name "description" -value $cve.description
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
        $Vulnerabilities += $vuln
        $vuln = $null
      }
    }
  }
  Write-Host "DONE: Exporting $($Vulnerabilities.count) Vulnerabilities"
  $Vulnerabilities
}

# Get Full FileReport on an object by sha1
function Get-ICFileDetail {
  Param(
    [ValidateNotNullorEmpty]
    [String]$sha1
  )

	Write-Verbose "Requesting FileReport on file with SHA1: $sha1"
	$Endpoint = "FileReps/$sha1"
  $object = _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter
	$object | Add-Member -Type NoteProperty -Name 'avpositives' -Value $_.avResults.positives
	$object | Add-Member -Type NoteProperty -Name 'avtotal' -Value $_.avResults.total
	return $object
}
