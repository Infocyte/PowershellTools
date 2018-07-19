# example script to upload a survey file to HUNT (3.0+)

$url = "https://localhost"
$survey = "HostSurvey.json.gz"
$targetId = $null
$scanId = $null
$scanName = $null
$targetName = "offline"
$user = "infocyte"
$password = "hunt"

#ignore certificate root errors from self signed certs
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$api = "$url/api"
$surveyPath = "$PSScriptRoot\$survey"

Write-Host "Acquiring token..."
$login = @{ username=$user; password=$password } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "$api/users/login" -Method Post -Body $login -ContentType "application/json"
$token = $response.id

if ($targetId -eq $null) {
	Write-Host "Creating target..."
	$target = @{ name=$targetName } | ConvertTo-Json
	$response = Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/targets" -Method Post -Body $target -ContentType "application/json"
	$targetId = $response.id
}

if($scanName -eq $null) {
	$scanName = (get-date).toString("yyyy-MM-dd HH:mm")
}

if ($scanId -eq $null) {
	Write-Host "Creating scan..."
	$scan = @{ name=$scanName; targetId=$targetId; startedOn=(get-date).toString()  } | ConvertTo-Json
	$response = Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/scans" -Method Post -Body $scan -ContentType "application/json"
	$scanId = $response.id
}

Write-Host "Uploading survey to scan $scanId..."
Write-host $surveyPath

Invoke-RestMethod -Headers @{ Authorization = $token; scanid = $scanId; filename = $survey } -Uri "$api/survey" -Method Post -InFile $surveyPath -ContentType "application/octet-stream"
