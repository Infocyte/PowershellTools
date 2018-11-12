Write-Host "Importing Infocyte HUNT API Powershell Module"
$PS = $PSVersionTable.PSVersion.tostring()
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Throw "Powershell Version not supported. Install version 5.x or higher"
} else {
  Write-Host "Checking PSVersion [Minimum Supported: 5.0]: PASSED [$PS]!"
  Write-Host "Pass your Hunt Server credentials into New-ICToken to connect to a hunt server. This will store your login token and server into a global variable for use by the other commands"
  Write-Host "`n"
  Write-Host "Authentication Functions: `nNew-ICToken, Set-ICToken`n"
  Write-Host "Target Group Management Functions: `nNew-ICTargetGroup, Get-ICTargetGroups, New-ICCredential, Get-ICCredentials, New-ICQuery, Get-ICQueries, Get-ICAddresses, Remove-ICAddresses`n"
  Write-Host "HUNT Server Status Functions: `nGet-ICJobs, Get-ICUserTasks, Get-ICLastScanId`n"
  Write-Host "Data Export Functions: `nGet-ICBoxes, Get-ICScans, Get-ICObjects, Get-ICConnections, Get-ICApplications, Get-ICVulnerabilities, Get-ICFileDetail`n"
  Write-Host "Scanning Functions: `nImport-ICSurvey, Invoke-ICScan, Invoke-ICEnumeration`n"
  Write-Host "Admin Functions: `nGet-ICFlagColourCodes, New-ICFlag, Update-ICFlag, Remove-ICFlag`n"
  Write-Host ""
  Write-Host "Example:"
  Write-Host -ForegroundColor Green 'PS> New-ICToken -HuntServer "https://myserver.infocyte.com" -Credential (Get-Credential)'
  Write-Host -ForegroundColor Green 'PS> $Box = Get-ICBoxes -Last30 | where { $_.TargetGroup -eq "Brooklyn Office"}'
  Write-Host -ForegroundColor Green 'PS> Get-ICObjects -Type Processes -BoxId $Box.Id'
}

# Read in all ps1 files

. "$PSScriptRoot\requestHelpers.ps1"
. "$PSScriptRoot\auth.ps1"
. "$PSScriptRoot\data.ps1"
. "$PSScriptRoot\targetgroupmgmt.ps1"
. "$PSScriptRoot\status.ps1"
. "$PSScriptRoot\scan.ps1"
. "$PSScriptRoot\admin.ps1"


$Functions = @(
  "Invoke-ICEnumeration",
  "Invoke-ICScan",
  "Import-ICSurvey",
  "Get-ICObjects",
  "Get-ICConnections",
  "Get-ICApplications",
  "Get-ICVulnerabilities",
  "Get-ICFileDetail",
  "New-ICToken",
  "Set-ICToken",
  "New-ICTargetGroup",
  "Get-ICTargetGroups",
  "New-ICCredential",
  "Get-ICCredentials",
  "New-ICQuery",
  "Get-ICQueries",
  "Get-ICAddresses",
  "Remove-ICAddresses",
  "Get-ICScans",
  "Get-ICJobs",
  "Get-ICUserTasks",
  "Get-ICLastScanId",
  "Get-ICBoxes",
  "Get-ICFlagColourCodes",
  "New-ICFlag",
  "Get-ICFlags",
  "Update-ICFlag",
  "Remove-ICFlag"
)
# Export-ModuleMember -Function $Functions
