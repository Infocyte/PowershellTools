Get-ICAddress

$Hostname = "win2k12r2x64.pegasus.test"
$Extensions = Get-ICExtension -where @{ active = $true}
$ExtensionName = "Yara Scanner"
$ExtId = $Extensions | Where-Object { $_.name -eq $ExtensionName } | Select-Object Id -ExpandProperty Id
if ($extId) {
    $Opts = New-ICScanOptions -ExtensionsOnly -ExtensionId $ExtId
    $task = Invoke-ICScanTarget -target $Hostname -ScanOptions $opts 
} else {
    Write-Error "No Extension by that name"
    return
}

