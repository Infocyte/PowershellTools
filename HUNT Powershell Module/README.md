# Infocyte HUNT API Module
Tested on Powershell Version: 5.0

## Getting Started
Import the module:
> PS> Import-Module .\InfocyteHUNTAPI.psd1

Create an API token in the Web Console within your profile or admin panel.
Use Set-ICToken to connect to your HUNT server and set your API token.
Example:
> PS> Set-ICToken -HuntServer "https://myserver.infocyte.com" -Token ASASDFASDFSASDF12123

This will store your login token and server into a global variable for use by the other commands

Authentication Functions:

    New-ICToken (Input: HuntServer, Credential) <-- Depreciated in SaaS version, still used with on-prem
    Set-ICToken (Input: HuntServer, Token)

Target Group Management Functions:

	New-ICTargetGroup (Input: Name)
	Get-ICTargetGroups (Input: TargetGroupId)
	Remove-ICTargetGRoup (Input: TargetGroupId)
	New-ICCredential (Input: )
	Get-ICCredentials (Input: )
	New-ICQuery (Input: TargetGroupId, Query)
	Get-ICQueries (Input: TargetGroupId)
	Get-ICAddresses (Input: TargetGroupId)
	Remove-ICAddresses (Input: TargetGroupId)

HUNT Server Status Functions:

    Get-ICScans
    Get-ICUserTasks
    Get-ICLastScanId

Data Export Functions:

	Get-ICObjects (Input: Type, ScanId, BoxId )
	Get-ICConnections (Input: BoxId )
	Get-ICApplications (Input: BoxId )
	Get-ICVulnerabilities (Input: BoxId )
	Get-ICFileDetail (Input: Hash)
	Get-ICBoxes (Input: (AllScans, Last7 or Last30), targetGroupId)  # This gives you the boxid (a box is grouped scan data over a time period)

Scanning Functions:

	Invoke-ICScan (Input: TargetGroupId)
	Invoke-ICFindHosts (Input: TargetGroupId, QueryId)
  New-ICScanSchedule (Input: TargetGroupId, CronExpression)
  Get-ICScanSchedule (Input: TargetGroupId)
  Remove-ICScanSchedule (Input: TargetGroupId or ScheduleId)

Offline Scans:

	Import-ICSurvey (Input: FilePath, (ScanId, TargetGroupId, or TargetGroupName))
