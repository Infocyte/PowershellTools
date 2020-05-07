
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$GUID_REGEX = "^[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}$"

Import-Module -Name Pester -Force -ErrorAction Stop
Remove-Module -Name InfocyteHUNTAPI -Force -ErrorAction Ignore
if (-Not $PSScriptRoot) {
    Import-Module $pwd\..\infocyteHUNTAPI.psd1 -Force -ErrorAction Stop
} else {
    Import-Module $PSScriptRoot\..\infocyteHUNTAPI.psd1 -Force -ErrorAction Stop
}


# get default from static property$PesterPreference = [PesterConfiguration]::Default
$config = [PesterConfiguration]::Default
$config.CodeCoverage.Enabled = $true
$config.Output.Verbosity = "Normal"
$config.Should.ErrorAction = "Stop"

# Test configs
$Testname = "PSTest"
$Testhost = "dc1.pegasus.test"
$TestInstance = "TestChris2644"

if (-NOT (Set-ICToken -Instance $testInstance)) {
    Throw "Could not connect to Test Instance: $testInstance"
}

get-childitem -filter *.test.ps1 | ForEach-Object { 
    Invoke-Pester -Output Normal -Path $_.FullName 
} 


<#


# Test Data Export Functions:
Set-ICBox -Last 7 -Global
Get-ICObject -Type Process -CountOnly
Get-ICObject -Type File -CountOnly

Get-ICScan -Id "95d51783-06d4-4264-b4d6-9e3e8dd4ccd3"
Get-ICVulnerability
Get-ICAlert
Get-ICActivityTrace
Get-ICFileDetail

# Test Scanning Functions:
Invoke-ICScan
Invoke-ICScanTarget
Invoke-ICFindHosts
New-ICScanOptions

$a = Add-ICScanSchedule -
Get-ICScanSchedule -id $a.id
Remove-ICScanSchedule -id $a.id

# Test Offline Scan Import Functions:
Import-ICSurvey

# Test Admin Functions:
Get-ICFlagColors
New-ICFlag
Update-ICFlag
Remove-ICFlag
Add-ICComment
New-ICExtension
Get-ICExtension

#>