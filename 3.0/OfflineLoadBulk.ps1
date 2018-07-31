###
# OfflineLoadBulk.ps1
#
# This script can bulk import surveys that are collected during an offline analysis/scan that are stored
# in a designated directory. It can be safely run from any endpoint with access to the Infocyte HUNT 
# server controlled by the enterprise. 
#
# Notes:
# - If the readonly property on the survey file (gz) is chcecked, the script will fail due to an access
#   path is denied error. If ths happens, uncheck the property and re-import. 
# - This script will not create individual endpoints under a target group, but you can look at the
#   history of the target group to see the results of the import. 
# - This script only handles the import and analysis, It does not track the timeboxing workflow that 
#   follows analysis. As survey results are added to the timeboxing they will appear in the analysis
#   section of the product. This may take additional time.
# - This script is tested wth 3.0 and it requires PowerShell 3.0. It will not work 
#   with 2.9 and older.
#
###
# VARIABLES
#
#URL to the HUNT Server we'll be importing into and a holder variable for the API URL - note the port incase of change
$url = "https://localhost"      
$api = "$url/api"                    # should not be altered

#Name of the Target Group that we'll be importing survey files into
$targetName = "OfflineScans"       

#The username and password of an account that will be used to do the importing
$user = "infocyte"                   
$password = "hunt"

#The path of where the survey are located - can be relative or full
$surveys = ".\surveys"

#Variables used in the script
$targetId = $null                   # should not be altered outside of special use-cases
$scanId = $null                     # should not be altered outside of special use-cases
$scanName = $null                   # should not be altered outside of special use-cases

#This ensures that self-signed certificates are ignored.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Acquire a Login Token from the Infocyte HUNT erver
Write-Host "Acquiring token..."

$login = @{ username=$user; password=$password } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "$api/users/login" -Method Post -Body $login -ContentType "application/json"
$token = $response.id

Write-Host "Token Acquired:" $token "`n"

#Create the target group if it doesn't already exist
#Note: if the target ID is known, it can be replaced in the $targetId variable and we'll skip this
if ($targetId -eq $null) {

	Write-Host "Creating target..."
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    #Make a query to see if the taget name configured exsits
    $response = Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/targets?filter={""where"":{""name"":""$targetName""}}" -Method Get -ContentType "application/json"
    $targetId = $response.id
    
    #If doesn't exist it will be null so we'll create it
    if($targetId -eq $null){
    
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    	$target = @{ name=$targetName } | ConvertTo-Json
	    $response = Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/targets" -Method Post -Body $target -ContentType "application/json"
	    $targetId = $response.id

        Write-Host "Target Group $targetName created `n"        

    }else{
        write-host "Target Group $targetName already exsits `n"
    }
}else{
    write-host "Using supplied Target Group Id: $targetId `n"
}

#Create the Scan Name if it doesn't already exist
#Note: if the scanName is known or provided, it can be replaced in the $scanName variable and we'll skip creation
if($scanName -eq $null) {
	$scanName = (get-date).toString("yyyy-MM-dd HH:mm")
    write-Host "Scan Name $scanName created"
}else{
    write-host "Using supplied Scan Name: $scanName `n"
}

#Create the Scan ID if it doesn't already exist
#Note: if the endpoint is being added to an existing scan ID that is known, it can be replaced in the #scanId variable and we'll skip creation
if ($scanId -eq $null) {

	Write-Host "Creating scan..."
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
	$scan = @{ name=$scanName; targetId=$targetId; startedOn=(get-date).toString()  } | ConvertTo-Json
	$response = Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/scans" -Method Post -Body $scan -ContentType "application/json"
	$scanId = $response.id
    
    Write-Host "Created Scan Id:" $scanId 
}else{
    write-host "Using supplied Scan Id: $scanId"
}

#Upload All Scans in the Survey Folder

Write-Host "`nUploading survey..."

$hostsSubmitted = 0    #counter variable holding total # of surveys that are found and uploaded

#for each gz (survey) file in the surveys folder
Get-ChildItem $surveys -Filter *.gz |
ForEach-Object{
    
    $filename = $_.Name
    try {

    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    #Upload the survey
    Invoke-RestMethod -Headers @{ Authorization = $token; scanid = $scanId; filename = $filename } -Uri "$api/survey" -Method Post -InFile $_.FullName -ContentType "application/octet-stream"
    #increment the counter
    }	catch {
        $hostsSubmitted -= 1
		Write-Warning -Message "Unable to upload: $filename. Please remove successful surveys and try again."
        
	}

    $hostsSubmitted += 1 
    Write-Host "Uploading" $_.Name

} 

Write-host "`n"$hostsSubmitted "suveys uploaded, waiting for analysis..."



DO{
    Start-Sleep -s 3

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    #check the status of the analysis by looking at the hostCount (will be populated as survey analysis completes)
    $response = Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/scans/$scanId" -Method Get -ContentType "application/json"
    $hostsCompleted = $response.hostCount    

    Write-Host "`n"$hostsCompleted " of " $hostsSubmitted "Completed"

  
  #Keep waiting and checking so long as $hostsCompleted is not null and != total number of submitted hosts 
} while (($hostsCompleted -ne $null) -and ($hostsCompleted -ne $hostsSubmitted))

Write-Host "Done."