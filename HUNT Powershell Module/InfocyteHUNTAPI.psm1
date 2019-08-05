

Write-Host "Importing Infocyte HUNT API Powershell Module"
$PS = $PSVersionTable.PSVersion.tostring()
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Warning "Powershell Version not supported. Install version 5.x or higher"
} else {
  Write-Host "Checking PSVersion [Minimum Supported: 5.0]: PASSED [$PS]!`n"
  Write-Host "Pass your Hunt Server credentials into Set-ICToken to connect to an instance of HUNT. This will store your login token and server into a global variable for use by the other commands"
  Write-Host "`n"
  Write-Host "Authentication Functions:"
  Write-Host -ForegroundColor Cyan "`tNew-ICToken (depreciated / On-Prem only), Set-ICToken`n"
  Write-Host "Target Group Management Functions:"
  Write-Host -ForegroundColor Cyan "`tNew-ICTargetGroup, Get-ICTargetGroups, Remove-ICTargetGroup, New-ICCredential, Get-ICCredentials, Remove-ICCredential, New-ICQuery, Get-ICQueries, Remove-ICQuery, Get-ICAddresses, Remove-ICAddresses`n"
  Write-Host "HUNT Server Status Functions:"
  Write-Host -ForegroundColor Cyan "`tGet-ICUserAuditLogs, Get-ICUserTasks, Get-ICUserTaskItems`n"
  Write-Host "Data Export Functions:"
  Write-Host -ForegroundColor Cyan "`tGet-ICBoxes, Get-ICScans, Get-ICObjects, Get-ICConnections, Get-ICScripts, Get-ICAccounts, Get-ICApplications, Get-ICVulnerabilities, Get-ICAlerts, Get-ICActivityTrace, Get-ICFileDetail`n"
  Write-Host "Scanning Functions:"
  Write-Host -ForegroundColor Cyan "`tInvoke-ICScan, Invoke-ICScanTarget, Invoke-ICFindHosts, New-ICScanOptions, Add-ICScanSchedule, Get-ICScanSchedule, Remove-ICScanSchedule`n"
  Write-Host "Offline Scan Import Functions:"
  Write-Host -ForegroundColor Cyan "`tImport-ICSurvey`n"
  Write-Host "Admin Functions:"
  Write-Host -ForegroundColor Cyan "`tGet-ICFlagColourCodes, New-ICFlag, Update-ICFlag, Remove-ICFlag`n"
  Write-Host "`n"
  Write-Host "FAQ:"
  Write-Host "- Most data within HUNT are tagged and filterable by Scan (" -NoNewLine
  Write-Host -ForegroundColor Cyan "scanId" -NoNewLine
  Write-Host "), Time Boxes (" -NoNewLine
  Write-Host -ForegroundColor Cyan "boxId" -NoNewLine
  Write-Host "), and Target Groups (" -NoNewLine
  Write-Host -ForegroundColor Cyan "targetGroupId" -NoNewLine
  Write-Host ")"
  Write-Host "- Time Boxes are Last 7, 30, and 90 Day filters for all data within range"
  Write-Host "- Results are capped at $resultlimit results unless you use -NoLimit on functions that support it`n"
  Write-Host "Example:"
  Write-Host -ForegroundColor Cyan 'PS> Set-ICToken -HuntServer "https://myserver.infocyte.com" -Token ASDFASDASFASDASF'
  Write-Host -ForegroundColor Cyan 'PS> $Box = Get-ICBoxes -Last30 | where { $_.TargetGroup -eq "Brooklyn Office"}'
  Write-Host -ForegroundColor Cyan 'PS> Get-ICObjects -Type Processes -BoxId $Box.Id'

  Write-Host 'Using custom loopback filters: $where = [Hashtable]@{ term1 = "asdf1"; term2 = "asdf2" }'
  Write-Host 'Note: Best time format is ISO 8601 or Get-Dates type code "o". i.e. 2019-05-03T00:37:40.0056344-05:00'
  Write-Host 'For more information on filtering, see loopbacks website here: https://loopback.io/doc/en/lb2/Where-filter.html'
  Write-Host -ForegroundColor Cyan 'PS> $customfilter = @{ threatName = "Unknown"; modifiedOn = @{ gt = $((Get-Date).AddDays(-10).GetDateTimeFormats('o')) }; size = @{ lt = 1000000 } }'
  Write-Host -ForegroundColor Cyan 'PS> Get-ICObjects -Type Artifacts -BoxId $Box.Id -where $customfilter'

  Write-Host "Offline Scan Processing Example (Default Target Group = OfflineScans):"
  Write-Host -ForegroundColor Cyan 'PS> Import-ICSurvey -Path .\surveyresult.json.gz'

  Write-Host "Offline Scan Processing Example (Default Target Group = OfflineScans):"
  Write-Host -ForegroundColor Cyan 'PS> Get-ICTargetGroup'
  Write-Host -ForegroundColor Cyan 'PS> Get-ChildItem C:\FolderOfSurveyResults\ -filter *.json.gz | Import-ICSurvey -Path .\surveyresult.json.gz -TargetGroupId b3fe4271-356e-42c0-8d7d-01041665a59b'
  Write-Host -ForegroundColor Cyan 'PS> Get-ICObjects -Type Processes -BoxId $Box.Id'
}

# Read in all ps1 files

. "$PSScriptRoot\requestHelpers.ps1"
. "$PSScriptRoot\auth.ps1"
. "$PSScriptRoot\data.ps1"
. "$PSScriptRoot\targetgroupmgmt.ps1"
. "$PSScriptRoot\status.ps1"
. "$PSScriptRoot\scan.ps1"
. "$PSScriptRoot\admin.ps1"
