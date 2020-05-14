
$ErrorActionPreference = 'Continue'
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
$TestInstance = "TestPanXSOAR"

Write-Host "Running tests against Instance=$TestInstance, TestName=$Testname, Testhost=$Testhost"
if (-NOT (Set-ICToken -Instance $testInstance)) {
    Throw "Could not connect to Test Instance: $testInstance"
}
<#
get-childitem -filter *.test.ps1 | ForEach-Object { 
    Invoke-Pester -Output Normal -Path $_.FullName 
} 
#>
Invoke-Pester -Output Normal -Path "C:\Users\cgerr\Documents\GitHub\PowershellTools\HUNT Powershell Module\tests\scan.test.ps1"