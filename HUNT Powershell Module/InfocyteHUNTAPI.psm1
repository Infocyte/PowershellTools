#Variables
$GUID_REGEX = "^[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}$"

Write-Verbose "Importing Infocyte HUNT API Powershell Module"
$PS = $PSVersionTable.PSVersion.tostring()
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Warning "Powershell Version not supported. Install version 5.x or higher"
  return
} else {
    Write-Verbose "Checking PSVersion [Minimum Supported: 5.0]: PASSED [$PS]!`n"
}

function Get-ICHelp {
  $Version = (Get-Module -Name InfocyteHUNTAPI).Version.ToString()
    Write-Host "Infocyte Powershell Module version $Version"
    Write-Host "Pass your Infocyte API Token into Set-ICToken to connect to an instance of Infocyte."
    Write-Host "`tThis will store your login token and server into a global variable for use by the other commands"
    Write-Host "`n"
    Write-Host "Help:"
    Write-Host -ForegroundColor Cyan "`tGet-ICHelp`n"

    Write-Host "Authentication Functions:"
    Write-Host -ForegroundColor Cyan "`tNew-ICToken (On-Prem ONLY), Set-ICToken (alias: Set-ICInstance)`n"

    Write-Host "Generic API Functions"
    Write-Host -ForegroundColor Cyan "`tGet-ICAPI, Invoke-ICAPI`n"

    Write-Host "Extension Development Functions:"
    Write-Host -ForegroundColor Cyan "`tNew-ICExtension, Test-ICExtension,"
    Write-Host -ForegroundColor Cyan "`tGet-ICExtension, Update-ICExtension, Remove-ICExtension,"
    Write-Host -ForegroundColor Cyan "`tImport-ICExtension, Import-ICOfficialExtensions`n"

    Write-Host "Admin/Misc Functions:"
    Write-Host -ForegroundColor Cyan "`tNew-ICFlag, Update-ICFlag, Remove-ICFlag, Get-ICFlagColors"
    Write-Host -ForegroundColor Cyan "`tGet-ICUsers, Get-ICUserAuditLog,"
    Write-Host -ForegroundColor Cyan "`tAdd-ICComment", "Get-ICDwellTime`n"

    Write-Host "Target Group Management Functions:"
    Write-Host -ForegroundColor Cyan "`tNew-ICTargetGroup, Get-ICTargetGroup, Remove-ICTargetGroup,"
    Write-Host -ForegroundColor Cyan "`tNew-ICCredential, Get-ICCredential, Remove-ICCredential,"
    Write-Host -ForegroundColor Cyan "`tNew-ICQuery, Get-ICQuery, Remove-ICQuery,"
    Write-Host -ForegroundColor Cyan "`tGet-ICAddress, Remove-ICAddress,"
    Write-Host -ForegroundColor Cyan "`tGet-ICAgent, Remove-ICAgent`n"

    Write-Host "Analysis Data Retrieval Functions:"
    Write-Host -ForegroundColor Cyan "`tGet-ICBox, Set-ICBox,"
    Write-Host -ForegroundColor Cyan "`tGet-ICObject (alias: Get-ICData), Get-ICVulnerability, Get-ICNotes,"
    Write-Host -ForegroundColor Cyan "`tGet-ICAlert, Get-ICFileDetail, Get-ICActivityTrace`n"

    Write-Host "Scanning Functions:"
    Write-Host -ForegroundColor Cyan "`tInvoke-ICFindHosts, New-ICScanOptions,"
    Write-Host -ForegroundColor Cyan "`tGet-ICScan, Invoke-ICScan, Invoke-ICScanTarget, Invoke-ICResponse,"
    Write-Host -ForegroundColor Cyan "`tAdd-ICScanSchedule, Get-ICScanSchedule, Remove-ICScanSchedule`n"

    Write-Host "Task Status Functions:"
    Write-Host -ForegroundColor Cyan "`tGet-ICTask, Get-ICTaskItems, Get-ICLastScanTask`n"

    Write-Host "Offline Scan Import Functions:"
    Write-Host -ForegroundColor Cyan "`tImport-ICSurvey`n"

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
    Write-Host "- GET Results are capped at $resultlimit results unless you use -NoLimit`n"
    Write-Host "Example:"
    Write-Host -ForegroundColor Cyan 'PS> Set-ICInstance -Instance "clouddemo" -Token ASDFASDASFASDASF -Save'
    Write-Host -ForegroundColor Cyan 'PS> $Box = Get-ICBox -Last30 | where { $_.TargetGroup -eq "Brooklyn Office"}'
    Write-Host -ForegroundColor Cyan 'PS> Get-ICObject -Type Process -BoxId $Box.Id -NoLimit'


    Write-Host 'Using custom loopback filters: [HashTable]$where = @{ term1 = "asdf1"; term2 = "asdf2" }'
    Write-Host 'Note: Best time format is ISO 8601 or Get-Dates type code "o". i.e. 2019-05-03T00:37:40.0056344-05:00'
    Write-Host 'For more information on filtering, see loopbacks website here: https://loopback.io/doc/en/lb2/Where-filter.html'
    Write-Host -ForegroundColor Cyan 'PS> Get-ICObject -Type File -BoxId $Box.Id -where @{ path = @{ regexp = "/roaming/i" } }'
    Write-Host -ForegroundColor Cyan 'PS> $customfilter = @{ threatName = "Unknown"; modifiedOn = @{ gt = $((Get-Date).AddDays(-10).GetDateTimeFormats('o')) }; size = @{ lt = 1000000 } }'
    Write-Host -ForegroundColor Cyan 'PS> Get-ICObject -Type Artifact -BoxId $Box.Id -where $customfilter'

    Write-Host "Offline Scan Processing Example (Default Target Group = OfflineScans):"
    Write-Host -ForegroundColor Cyan 'PS> Import-ICSurvey -Path .\surveyresult.json.gz'

    Write-Host "Offline Scan Processing Example (Default Target Group = OfflineScans):"
    Write-Host -ForegroundColor Cyan 'PS> Get-ICTargetGroup'
    Write-Host -ForegroundColor Cyan 'PS> Get-ChildItem C:\FolderOfSurveyResults\ -filter *.json.gz | Import-ICSurvey -Path .\surveyresult.json.gz -TargetGroupId b3fe4271-356e-42c0-8d7d-01041665a59b'
}

# Read in all ps1 files
. "$PSScriptRoot\requestHelpers.ps1"
. "$PSScriptRoot\auth.ps1"
. "$PSScriptRoot\data.ps1"
. "$PSScriptRoot\targetgroupmgmt.ps1"
. "$PSScriptRoot\status.ps1"
. "$PSScriptRoot\scan.ps1"
. "$PSScriptRoot\admin.ps1"
. "$PSScriptRoot\extensions.ps1"
