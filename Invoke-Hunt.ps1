<#
	Infocyte API Functions
#>
Param(
	[Parameter()]
	[ValidateNotNull()]
	[String]$Target = "127.0.0.1",

	[String]$Log = "C:\log", # Output Path for logs

	[String]$HuntServer = "https://localhost:4443",
	
	[PSCredential]$HuntCredential,

	[PSCredential]$ScanCredential
)

<#
	NOTES:
	
	[Parameter()]
	[ValidateNotNull()]
	[System.Management.Automation.PSCredential]
	[System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
#>

# Hardcoded Credentials (unsafe in production, should switch these to command line parameters using PSCredential Objects)

#Infocyte Credentials
if (-NOT $HuntCredential) {
	$username = 'infocyte'
	$password = 'pulse' | ConvertTo-SecureString -asPlainText -Force
	$Script:Credential = New-Object System.Management.Automation.PSCredential($username,$password)
}

#Query Credentials (Scanning Admin/Service Account)
if (-NOT $ScanCredential) {
	$username = 'domain.net\administrator'
	$password = 'pulse' | ConvertTo-SecureString -asPlainText -Force
	$Script:ScanCredential = New-Object System.Management.Automation.PSCredential($username,$password)
}

# SCRIPT SETUP ROUTINES

if (-NOT (Test-Path $Log)) {
	New-Item $Log -ItemType "directory"
}


# MAIN

# Create new login Token and add it to Script variable
New-ICToken $Credential $HuntServer
# Error if token no longer valid is:
# WARNING: Error: The underlying connection was closed: An unexpected error occurred on a send.


# Get Target Lists.  If our specified list isn't there, create it.
$TargetLists = Get-ICTargetList
if ($TargetLists.name -contains $TargetListName) {
	$TargetListId = ($TargetLists | where { $_.name -eq $TargetListName -AND $_.deleted -eq $False}).id
	if (-NOT $TargetListId) {
		Write-Host "Creating TargetList named $TargetListName"
		$TargetListId = (New-ICTargetList $TargetListName).id
	}
} else {
	Write-Host "Creating TargetList named $TargetListName"
	$TargetListId = (New-ICTargetList $TargetListName).id
}

# If we don't clear the target list, we would enumerate and scan all the other addresses already in there again
Write-Host "Clearing Target List targets from $TargetListId"
Remove-ICAddresses $TargetListId

#Create new Query for target
Write-Host "Creating new Query for: $Target"
$QueryId = (New-ICQuery $TargetListId $Target $ScanCredential).id

# Initiate Enumeration
Write-Host "Enumerating $Target"
Invoke-ICEnumeration $TargetListId $QueryId

# Track Status of Enumeration
$active = $true
Write-Host "Waiting for enumeration to complete"
Write-Progress -Activity "Enumerating Target" -status "Waiting for enumeration to complete"
while ($active) { 
	$status = Get-ICActiveTasks | where { $_.type -eq "Enumerate" }
	Write-Progress -Activity "Enumerating Target" -status "[$elapsed/1000] $($status.message)" -percentComplete $status.progress
	if ($status.status -eq "Active") {
		
	} else {
		$active = $false
		if ($status.message -like "error") {
			Write-Host "ERROR: Could not enumerate Target"
		} else {
			Write-Host "Enumeration Complete!"
		}
	}
}

# Initiate Scan
Write-Host "Initiating Scan of $Target"
Invoke-ICScan $TargetListId

# Track Status of Scan
$active = $true
Write-Progress -Activity "Scanning Target" -status "Initiating Scan"
while ($active) { 
	$status = Get-ICActiveTasks | where { $_.type -eq "Scan" -AND $_.status -eq "Active"}
	if ($status.status -eq "Active") {
		Write-Progress -Activity "Scanning Target" -status "[Elapsed (seconds): $($($status.elapsed)/1000)] $($status.message)" -percentComplete ($status.progress)		
	} else {
		$active = $false
		if ($status.message -like "error") {
			Write-Host "ERROR: Could not scan Target"
		} else {
			Write-Host "Scan Completed in $($($status.elapsed)/1000) seconds"
		}
	}
}