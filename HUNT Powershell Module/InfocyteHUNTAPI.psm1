Write-Host "Importing Infocyte HUNT API Powershell Module"
$PS = $PSVersionTable.PSVersion.tostring()
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Warning "Powershell Version not supported. Install version 5.x or higher"
} else {
  Write-Host "Checking PSVersion [Minimum Supported: 5.0]: PASSED [$PS]!`n"
  Write-Host "Pass your Hunt Server credentials into New-ICToken to connect to an instance of HUNT. This will store your login token and server into a global variable for use by the other commands"
  Write-Host "`n"
  Write-Host "Authentication Functions:"
  Write-Host -ForegroundColor Cyan "`tNew-ICToken, Set-ICToken`n"
  Write-Host "Target Group Management Functions:"
  Write-Host -ForegroundColor Cyan "`tNew-ICTargetGroup, Get-ICTargetGroups, Remove-ICTargetGroup, New-ICCredential, Get-ICCredentials, New-ICQuery, Get-ICQueries, Get-ICAddresses, Remove-ICAddresses`n"
  Write-Host "HUNT Server Status Functions:"
  Write-Host -ForegroundColor Cyan "`tGet-ICJobs, Get-ICUserTasks, Get-ICLastScanId`n"
  Write-Host "Data Export Functions:"
  Write-Host -ForegroundColor Cyan "`tGet-ICBoxes, Get-ICScans, Get-ICObjects, Get-ICConnections, Get-ICApplications, Get-ICVulnerabilities, Get-ICFileDetail`n"
  Write-Host "Scanning Functions:"
  Write-Host -ForegroundColor Cyan "`tImport-ICSurvey, Invoke-ICScan, Invoke-ICEnumeration`n"
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
  Write-Host "- Results are capped at 5000 results unless you use -NoLimit on function that support it`n"
  Write-Host "Example:"
  Write-Host -ForegroundColor Cyan 'PS> New-ICToken -HuntServer "https://myserver.infocyte.com"'
  Write-Host -ForegroundColor Cyan 'PS> $Box = Get-ICBoxes -Last30 | where { $_.TargetGroup -eq "Brooklyn Office"}'
  Write-Host -ForegroundColor Cyan 'PS> Get-ICObjects -Type Processes -BoxId $Box.Id'
}


# Variables
$resultlimit = 5000 # limits the number of results that come back.

# Read in all ps1 files

. "$PSScriptRoot\requestHelpers.ps1"
. "$PSScriptRoot\auth.ps1"
. "$PSScriptRoot\data.ps1"
. "$PSScriptRoot\targetgroupmgmt.ps1"
. "$PSScriptRoot\status.ps1"
. "$PSScriptRoot\scan.ps1"
. "$PSScriptRoot\admin.ps1"
