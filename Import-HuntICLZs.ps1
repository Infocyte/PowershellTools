# Script to upload manual .iclz file to hunt server.
Param(
	[Parameter(	Position = 0, 
				Mandatory = $true)]
	[String]
	$Path, # <folder containing the .iclz files to upload>
	
	[String]
	$TargetListName = "OfflineScans",
	
	[String]$HuntServer = "https://localhost:4443",
	
	[PSCredential]
	[System.Management.Automation.Credential()]
	$HuntCredential = [System.Management.Automation.PSCredential]::Empty,
	
	[PSCredential]
	[System.Management.Automation.Credential()]
	$ScanCredential = [System.Management.Automation.PSCredential]::Empty
)

$Target = "localhost"
$UploadDir = "C:\Program Files\Infocyte\Hunt\uploads"

# Hardcoded Credentials (unsafe in production but convenient for testing)

#Infocyte Credentials
if ($HuntCredential -eq [System.Management.Automation.PSCredential]::Empty) {
	$username = 'infocyte'
	$password = 'pulse' | ConvertTo-SecureString -asPlainText -Force
	$Script:HuntCredential = New-Object System.Management.Automation.PSCredential($username,$password)
}

#Query Credentials (Scanning Admin/Service Account)
if ($ScanCredential -eq [System.Management.Automation.PSCredential]::Empty) {
	$username = 'galactica.int\administrator'
	$password = 'pulse' | ConvertTo-SecureString -asPlainText -Force
	$Script:ScanCredential = New-Object System.Management.Automation.PSCredential($username,$password)
}

if (-NOT (Test-Path $Path)) {
	Write-Warning "Path does not exist, place your ICLZ files in $Path"
	return
} 
elseif (-NOT (Get-ChildItem -Recurse -Path $Path -Filter *.iclz)) {
	Write-Warning "Path does not contain any .ICLZ files"
	return
}

# Create new login Token and add it to Script variable
Write-Host "Connecting $HuntServer using account $($HuntCredential.username)"
$NewToken = New-ICToken $HuntCredential $HuntServer
if ($NewToken.id) {
	Write-Host "Login successful to $HuntServer"
	Write-Host "Login Token id: $($NewToken.id)"
} else {
	Write-Warning "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
	return
}
# Error if token no longer valid is:
# WARNING: Error: The underlying connection was closed: An unexpected error occurred on a send.

#Copy .iclz files into upload folder (temp dir)
$TempFolderName = "temp$([guid]::NewGuid())"
Write-Host "Copying folder of .iclz files to staging temp directory: $UploadDir\$TempFolderName"
Copy-Item -Path $Path -Destination $UploadDir\$TempFolderName -recurse -Container
<# 
# TODO: Change this to grab the iclz files only and rename them using their md5 hash so we're not uploading the same iclz file twice (which would break everything)
Get-ChildItem $Path -filter *.iclz | Foreach-Object { 
	$newhash = (Get-Hashes -Path $_ -Type MD5).md5
	Copy-Item -Path $_ -Destination $UploadDir\$TempFolderName\Survey-$newhash.json.iclz -recurse -Container
}	
#>

# Get Target Lists.  
$TargetList = Get-ICTargetList
if ($TargetList -match "Error") {
	Write-Warning "$TargetList"
	return
} else {
	$TargetList = $TargetList | where { $_.name -eq $TargetListName -AND $_.deleted -eq $False}
}
 
if ($TargetList) {
	$TargetListId = $TargetList.id
} else {
	# If our specified list isn't there, create it.
	Write-Host "Creating TargetList named $TargetListName"
	$TargetListId = (New-ICTargetList $TargetListName).id
	
	#Create new Query for target
	Write-Host "Creating new Query for: $Target"
	$QueryId = (New-ICQuery $TargetListId $Target $ScanCredential).id

	# Initiate Enumeration
	Write-Host "Enumerating $Target"
	Invoke-ICEnumeration $TargetListId $QueryId
	Start-Sleep 1
	
	# Track Status of Enumeration
	$active = $true
	Write-Host "Waiting for enumeration to complete"
	Write-Progress -Activity "Enumerating Target" -status "Initiating Enumeration"
	while ($active) { 
		Start-Sleep 1
		$status = Get-ICActiveTasks
		if ($status -match "Error") {
			Write-Host "$Status"
			Write-Host "Attempting to re-connecting to $HuntServer"
			$NewToken = New-ICToken $HuntCredential $HuntServer
			if ($NewToken.id) {
				Write-Host "Login successful to $HuntServer"
				Write-Host "Login Token id: $($NewToken.id)"
				continue
			} else {
				Write-Warning "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
				return
			}
		} else {
			$status = $status | where { $_.type -eq "Enumerate" -AND $_.status -eq "Active"}
		}
		
		if ($status) {
			$lastStatus = $status
			$elapsedtime = "$($($status.elapsed)/1000)"
			Write-Progress -Activity "Enumerating Target" -status "[Elapsed (seconds): $elapsedtime] $($status.message)" -percentComplete ($status.progress)	
		} elseif ($Status.message -match "error") {
			$active = $false
			Write-Warning "ERROR: Could not enumerate Target: $($Status.message)"
			return "ERROR: Could not enumerate Target: $($Status.message)"
		} else {
			$active = $false
			Write-Warning "Enumeration Complete: $($lastStatus.message)"
		}
	}
}
Start-Sleep 1


Write-Host "Retrieving Last Job and ScanId"
$LastFolder = (gci 'C:\Program Files\Infocyte\Hunt\uploads\' | Sort-Object LastWriteTime -Descending)[0].Name
$ScanJobs = Get-ICActiveJobs
if ($ScanJobs -match "Error") {
	Write-Warning "$ScanJobs"
	Write-Host "Attempting to re-connecting to $HuntServer"
	$NewToken = New-ICToken $HuntCredential $HuntServer
	if ($NewToken.id) {
		Write-Host "Login successful to $HuntServer"
		Write-Host "Login Token id: $($NewToken.id)"
		$ScanJobs = Get-ICActiveJobs
	} else {
		Write-Warning "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
		return
	}
} 

$ScanJobs = $ScanJobs | Sort-Object timestamp -Descending | where { $_.status -eq "Scanning" }
if ($ScanJobs) {
	$baseScanId = $ScanJobs[0].scanId
} else {
	$baseScanId = "NO_SCAN"
}
Write-Host "Last Folder name: $LastFolder"
Write-Host "Last Active ScanId: $baseScanId"
	

# Initiate Scan
Write-Host "Initiating Scan of $Target"
$ScanTask = Invoke-ICScan $TargetListId
Start-Sleep 1
if ($ScanTask -match "Error") {
	Write-Warning "$ScanTask"
	Write-Host "Attempting to re-connecting to $HuntServer"
	$NewToken = New-ICToken $HuntCredential $HuntServer
	if ($NewToken.id) {
		Write-Host "Login successful to $HuntServer"
		Write-Host "Login Token id: $($NewToken.id)"
        $ScanTask = Invoke-ICScan $TargetListId
		Start-Sleep 1
	} else {
		Write-Warning "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
		return
	}
}


# Wait for new scan to be created
$scanId = $baseScanId
while ($scanId -eq $baseScanId) {
	Start-Sleep 2
	$ScanJobs = Get-ICActiveJobs
	if (!$ScanJobs -OR ($ScanJobs -match "Error")) {
		Write-Warning "$ScanJobs"
		Write-Host "Attempting to re-connecting to $HuntServer"
		$NewToken = New-ICToken $HuntCredential $HuntServer
		if ($NewToken.id) {
			Write-Host "Login successful to $HuntServer"
			Write-Host "Login Token id: $($NewToken.id)"
		} else {
			Write-Warning "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
			return
		}
	} elseif ($ScanJobs) {
        $ScanJobs = $ScanJobs | Sort-Object timestamp -Descending | where { $_.status -eq "Scanning" }
		if ($ScanJobs) {
            $scanId = $ScanJobs[0].ScanId
        }
		Write-Host "Waiting for new ScanId to be created... ScanID is currently $scanID as of $(Get-Date)"
	} else {
		Write-Warning "No Active Scan! Waiting for scan to be initiated..."
		$ScanId = "NO_SCAN"
	}
}
Write-Host "New ScanID created! Now: $scanId"

Write-Host "Renaming $UploadDir\$TempFolderName Directory to $UploadDir\$ScanId"
if (Test-Path $UploadDir\$ScanId) {
	Write-Warning "Folder $UploadDir\$ScanId already exists!"
} else {
	Rename-Item $UploadDir\$TempFolderName $UploadDir\$ScanId -Force
}
Write-Host "Your HostSurvey results will be processed as the current scan of TargetList $TargetListName moves to the processing phase."

# Track Status of Scan processing
$active = $true
while ($active) { 
	Start-Sleep 0.5
	$status = Get-ICActiveTasks
	if ($status -match "Error") {
		Write-Host "$Status"
		Write-Host "Attempting to re-connecting to $HuntServer"
		$NewToken = New-ICToken $HuntCredential $HuntServer
		if ($NewToken.id) {
			Write-Host "Login successful to $HuntServer"
			Write-Host "Login Token id: $($NewToken.id)"
			continue
		} else {
			Write-Warning "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
			return
		}
	} else {
		$status = $status | where { $_.type -eq "Scan" -AND $_.status -eq "Active"}
	}
	
	if ($status.status -eq "Active") {
		$elapsedtime = "$($($status.elapsed)/1000)"
		Write-Progress -Activity "Waiting for scan to process" -status "[Elapsed (seconds): $elapsedtime] $($status.message)" -percentComplete ($status.progress)	
	} else {
		$active = $false
		if ($status.message -match "error") {
			Write-Host "ERROR: Could not scan Target"
		} else {
			Write-Host "Scan Completed in $elapsedtime seconds"
		}
	}
}