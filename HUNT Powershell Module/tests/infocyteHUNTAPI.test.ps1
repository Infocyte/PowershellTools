
# Test Target Group Management Functions:
$a = New-ICTargetGroup -Name "PSTest"
if (-NOT $a) {
    $cg = Get-ICControllerGroup -where @{ name = "ChrisTest" }
    $a = New-ICTargetGroup -Name "PSTest" -ControllerGroupId $cg.id
}
$b = Get-ICTargetGroup -where @{ name = "PSTest" }
if ($a.id -ne $b.id) { throw "Error" }

$pw = ConvertTo-SecureString "testpass" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ("test\testsvcacct", $pw)
$c = New-ICCredential -Name "PSTest" -Cred $Cred
Get-ICCredential -where @{ byok = $true }
$d = Get-ICCredential -where @{ name = "PSTest" }
if ($c.id -ne $d.id) { throw "Error" }

$e = New-ICQuery -TargetGroupId $b.id -credentialId $d.id -Query "localhost" -Name "PSTest"
$f = Get-ICQuery -where @{ name = "PSTest" }


$g = Get-ICAddress -where @{ osWindows = $true; port445 = $True; latency = @{ lt = 5 } }
$g = Get-ICAddress -where @{ accessible = $false }
# Remove-ICAddress -id $g[0].id

$e = Get-ICAgent
$e = Get-ICAgent -where @{ hostname = "PEGASUSACTUAL"}
# Remove-ICAgent -id $e.id

$f | ForEach-Object { Remove-ICQuery -id $_.id -confirm }
$d | ForEach-Object { Remove-ICCredential -id $_.id -confirm }
$b | ForEach-Object { Remove-ICTargetGroup -Id $_.id -IncludeArchive -confirm }
if (Get-ICTargetGroup -where @{ name = "PSTest"}) { throw "Error on Remove-ICTargetGroup"}

# Test HUNT Server Status Functions:
Get-ICUserAuditLog
$a = Get-ICUserTask
$a[0].id | Get-ICUserTaskItem

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
