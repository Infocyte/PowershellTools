# Script to upload manual .iclz file to hunt server.
Param(
	[Parameter(	Position = 0, 
				Mandatory = $true)]
	[String]
	$Path, # <folder containing the .iclz files to upload>
	
	[String]
	$TargetListName = "OfflineScans",
	
	[String]
	$Target = "localhost",
	
	[String]
	$HuntServer = "https://localhost:4443",
	
	[PSCredential]
	[System.Management.Automation.Credential()]
	$HuntCredential = [System.Management.Automation.PSCredential]::Empty,
	
	[PSCredential]
	[System.Management.Automation.Credential()]
	$ScanCredential = [System.Management.Automation.PSCredential]::Empty
)

Write-Host "PSVersion Check: $($PSVersionTable.PSVersion.tostring())"
$UploadDir = "C:\Program Files\Infocyte\Hunt\uploads"

# Automatically import the Infocyte API calls
# Makes it easier for users, so they don't have to do this separately
if (Get-Command New-ICToken -errorAction SilentlyContinue) {
	# InfocyteAPIFunctions.ps1 already imported
} else {
	if (Test-Path -Path "$PSScriptRoot\InfocyteAPIFunctions.ps1") {
		Write-Host "Importing Infocyte API Functions ($PSScriptRoot\InfocyteAPIFunctions.ps1)"
		. "$PSScriptRoot\InfocyteAPIFunctions.ps1" 
	} else {
		Write-Host -ForegroundColor Red "You must import the InfocyteAPIFunctions.ps1 script."
		Write-Host -ForegroundColor Red  "Include it in the same folder as this script, and rerun this script with the same parameters."
		return
	}
}

if (-NOT (Test-Path -Path $UploadDir)) {
	Write-Host -ForegroundColor Red "You are not on the Hunt Server. You must run this script on the Hunt server."
	return
}

if (Test-Path $Path -PathType Container) { 
	if (-NOT (Get-ChildItem $Path -filter *.iclz)) {
		Write-Host -ForegroundColor Red "ERROR: $Path does not contain .iclz files"
		return	
	}
} else {
	Write-Host -ForegroundColor Red "ERROR: $Path is not a directory"
	return
}

# Hardcoded Credentials (unsafe in production but convenient for testing)

# Infocyte Credentials
# If a user did not add their credentials, use the default ones.
if ($HuntCredential -eq [System.Management.Automation.PSCredential]::Empty) {
	$username = 'infocyte'
	$password = 'hunt' | ConvertTo-SecureString -asPlainText -Force
	$Script:HuntCredential = New-Object System.Management.Automation.PSCredential($username,$password)
}

# Query Credentials (Scanning Admin/Service Account)
# If a user did not add their credentials, use the default ones.
# This will not work unless it is on that specific machine, so make sure you add your credentials at the beginning. 
if ($ScanCredential -eq [System.Management.Automation.PSCredential]::Empty) {
	$username = 'galactica.int\administrator'
	$password = 'hunt' | ConvertTo-SecureString -asPlainText -Force
	$Script:ScanCredential = New-Object System.Management.Automation.PSCredential($username,$password)
}

if (-NOT (Test-Path $Path)) {
	Write-Host -ForegroundColor Red "Path does not exist, place your ICLZ files in $Path"
	return
} 
elseif (-NOT (Get-ChildItem -Recurse -Path $Path -Filter *.iclz)) {
	Write-Host -ForegroundColor Red "Path does not contain any .ICLZ files"
	return
}

# Create new login Token and add it to Script variable
Write-Host "Connecting $HuntServer using account $($HuntCredential.username)"
$NewToken = New-ICToken $HuntCredential $HuntServer
if ($NewToken.id) {
	Write-Host "Login successful to $HuntServer"
	Write-Host "Login Token id: $($NewToken.id)"
} else {
	Write-Host -ForegroundColor Red "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
	return
}
# Error if token no longer valid is:
# WARNING: Error: The underlying connection was closed: An unexpected error occurred on a send.


# Get Target List.  
$TargetList = Get-ICTargetList
if ($TargetList -like "Error:*") {
	Write-Host -ForegroundColor Red "$TargetList"
	return
} else {
	$TargetList = $TargetList | Where-Object { $_.name -eq $TargetListName -AND $_.deleted -eq $False}
	if ($TargetList) {
		Write-Host "TargetList $TargetListName is already created"
		$TargetListId = $TargetList[0].id
	} else {
		# If our specified list isn't there, create it.
		Write-Host "Creating TargetList named $TargetListName"
		$TargetListId = (New-ICTargetList $TargetListName).id
	}
}

# Get Credentials
$CredObjects = Get-ICCredentials
if ($CredObjects -like "Error:*") {
	Write-Host -ForegroundColor Red "$CredObjects"
	return
} else {
	$CredObjects = $CredObjects | where { $_.name -eq "HuntLocal"}
	if ($CredObjects) {
		Write-Host "HuntLocal Credential is already loaded. Check the HUNT interface if you need to change the password or account."
		$CredentialId = $CredObjects[0].id
	} else {
		#Create new Credential for target
		Write-Host "Creating new Credential for the local Hunt Server: $($ScanCredential.username)"
		$CredentialId = (New-ICCredential -Name "HuntLocal" -Cred $ScanCredential).id	
	}
}

# Get Queries
$Queries = Get-ICQuery $TargetListId
if ($Queries -like "Error:*") {
	Write-Host -ForegroundColor Red "$Queries"
	return
} else {	
	$Queries = $Queries | where { $_.value -eq $Target -AND $_.credentialId -eq $CredentialId}
	if ($Queries) {
		Write-Host "Query already created for $Target within TargetList $TargetListId"
		$QueryId = $Queries[0].id
	} else {
		#Create new Query for target
		Write-Host "Creating new Query for: $Target within TargetList $TargetListId"
		$QueryId = (New-ICQuery -targetListId $TargetListId -credentialId $CredentialId -query $Target).id
	}
}

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
	if ($status -like "Error:*") {
		Write-Host -ForegroundColor Red "Error on Get-ICActiveTasks: $status"
		Write-Warning "Attempting to re-connecting to $HuntServer"
		$NewToken = New-ICToken $HuntCredential $HuntServer
		if ($NewToken.id) {
			Write-Host "Login successful to $HuntServer"
			Write-Host "Login Token id: $($NewToken.id)"
			continue
		} else {
			Write-Host -ForegroundColor Red "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
			return
		}
	} else {
		$status = $status | Where-Object { $_.type -eq "Enumerate" -AND $_.status -eq "Active"}
	}
	
	if ($status) {
		$lastStatus = $status[0]
		$Status = $status[0]
		$elapsedtime = "$($($status.elapsed)/1000)"
		if ($status.progress) {
			Write-Progress -Activity "Enumerating Target" -status "[Elapsed (seconds): $elapsedtime] $($status.message)" -percentComplete ($status.progress)	
		}
	} elseif ($Status.message -match "error") {
		$active = $false
		Write-Host -ForegroundColor Red "ERROR: Could not enumerate Target: $($Status.message)"
		return "ERROR: Could not enumerate Target: $($Status.message)"
	} else {
		$active = $false
		Write-Host "Enumeration Complete: $($lastStatus.message)"
	}
}
Start-Sleep 1

$TargetListResults = Get-ICAddresses $TargetListId
if ($TargetListResults) {
    if ($TargetListResults.accessibleAddressCount -eq 0) {
        $failreason = (Get-ICAddresses $TargetListId).failureReason

        Write-Host -ForegroundColor Red "ERROR: Enumeration was not successful ($failreason). Please check your ScanCredentials for the hunt server (HuntLocal) localhost within the Infocyte HUNT UI Credential Manager and try again"
        return
    } else {
        Write-Host "Enumeration Successful!"
    }
} else {
    Write-Host -ForegroundColor Red "ERROR: Could not get target list"
    return
}


#Copy .iclz files into upload folder (temp dir)
# $LastFolder = (Get-ChildItem $UploadDir | Sort-Object LastWriteTime -Descending)[0].Name
$TempFolderName = "temp$([guid]::NewGuid())"
$iclznum = get-childitem $Path -filter *.iclz -recurse
Write-Host "Copying folder of $($iclznum.count) .iclz files from $Path to staging temp directory: $UploadDir\$TempFolderName"
try {
	Copy-Item -Path $Path -Destination "$UploadDir\$TempFolderName" -recurse -ErrorAction Stop
} catch {
	Write-Host -ForegroundColor Red "ERROR: Could not copy files from $Path to the infocyte upload directory: $UploadDir"
	Write-Host -ForegroundColor Red "ERROR: $_"
	return
}
<# 
# TODO: Change this to grab the iclz files only and rename them using their md5 hash so we're not uploading the same iclz file twice (which would break everything)
Get-ChildItem $Path -filter *.iclz | Foreach-Object { 
	$newhash = (Get-Hashes -Path $_ -Type MD5).md5
	Copy-Item -Path $_ -Destination $UploadDir\$TempFolderName\Survey-$newhash.json.iclz -recurse -Container
}	
#>

Write-Host "Retrieving Last Job and ScanId"
#$LastFolder = (Get-ChildItem $UploadDir | Sort-Object LastWriteTime -Descending)[0].Name
$ScanJobs = Get-ICActiveJobs
if ($ScanJobs -like "Error:*") {
	Write-Host -ForegroundColor Red "$ScanJobs"
	Write-Warning "Attempting to re-connecting to $HuntServer"
	$NewToken = New-ICToken $HuntCredential $HuntServer
	if ($NewToken.id) {
		Write-Host "Login successful to $HuntServer"
		Write-Host "Login Token id: $($NewToken.id)"
		$ScanJobs = Get-ICActiveJobs
	} else {
		Write-Host -ForegroundColor Red "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
		return
	}
} 

$ScanJobs = $ScanJobs | Sort-Object timestamp -Descending | Where-Object { $_.status -eq "Scanning" }
if ($ScanJobs) {
	$baseScanId = $ScanJobs[0].scanId
} else {
	$baseScanId = "NO_SCAN"
}
Write-Host "Last Active ScanId: $baseScanId (Should say NO_SCAN if no scan is currently running)"
	

# Initiate Scan
Write-Host "Initiating Scan of $Target"
$ScanTask = Invoke-ICScan $TargetListId
$ScanTask
Start-Sleep 1
if ($ScanTask -like "Error:*") {
	Write-Host -ForegroundColor Red "$ScanTask"
	Write-Warning "Attempting to re-connecting to $HuntServer"
	$NewToken = New-ICToken $HuntCredential $HuntServer
	if ($NewToken.id) {
		Write-Host "Login successful to $HuntServer"
		Write-Host "Login Token id: $($NewToken.id)"
        $ScanTask = Invoke-ICScan $TargetListId
		Start-Sleep 1
	} else {
		Write-Host -ForegroundColor Red "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
		return
	}
}


# Wait for new scan to be created
$scanId = $baseScanId
while ($scanId -eq $baseScanId) {
	Start-Sleep 1
	$ScanJobs = Get-ICActiveJobs
	if ($ScanJobs -match "Error") {
		Write-Host -ForegroundColor Red "$ScanJobs"
		Write-Warning "Attempting to re-connecting to $HuntServer"
		$NewToken = New-ICToken $HuntCredential $HuntServer
		if ($NewToken.id) {
			Write-Host "Login successful to $HuntServer"
			Write-Host "Login Token id: $($NewToken.id)"
		} else {
			Write-Host -ForegroundColor Red "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
			return
		}
	} elseif ($ScanJobs) {
        $ScanJobs = $ScanJobs | Sort-Object timestamp -Descending | Where-Object { $_.status -eq "Scanning" }
		if ($ScanJobs) {
            $scanId = $ScanJobs[0].ScanId
        } else {
			Write-Host "Waiting for new ScanId to be created... ScanID is currently $scanID as of $(Get-Date)"
			Get-ICUserTasks | Where-Object { $_.type -eq "Scan" -AND $_.status -eq "Active"}
		}
	} else {
		Write-Host -ForegroundColor Red "No Active Scan! Waiting for scan to be initiated..."
		Get-ICUserTasks | Where-Object { $_.type -eq "Scan" -AND $_.status -eq "Active"}
		$ScanId = "NO_SCAN"
	}
}
Write-Host "New ScanID created! Now: $scanId"

Write-Host "Renaming $UploadDir\$TempFolderName Directory to $UploadDir\$ScanId"
if (Test-Path $UploadDir\$ScanId) {
	Write-Host -ForegroundColor Red "Folder $UploadDir\$ScanId already exists!"
} else {
	try {
		Rename-Item -path $UploadDir\$TempFolderName -newname $ScanId -ErrorAction Stop
	} catch {
		Write-Host -ForegroundColor Red "ERROR: Could not rename temp folder ($UploadDir\$TempFolderName --> $UploadDir\$ScanId), survey results will not be processed"
		Write-Host -ForegroundColor Red "ERROR: $_"
		return
	}
}
Write-Host "Your HostSurvey results will be processed as the current scan of TargetList $TargetListName moves to the processing phase."
Start-Sleep 1

# Track Status of Scan processing
$active = $true
while ($active) { 
	Start-Sleep 0.5
	$status = Get-ICUserTasks
	if ($status -like "Error:*") {
		Write-Host -ForegroundColor Red "$Status"
		Write-Warning "Attempting to re-connecting to $HuntServer"
		$NewToken = New-ICToken $HuntCredential $HuntServer
		if ($NewToken.id) {
			Write-Host "Login successful to $HuntServer"
			Write-Host "Login Token id: $($NewToken.id)"
			continue
		} else {
			Write-Host -ForegroundColor Red "ERROR: Could not get a token from $HuntServer using credentials $($HuntCredential.username)"
			return
		}
	}
	$status = $status | Where-Object { $_.type -eq "Scan" -AND $_.options.ScanId -eq $scanId}
	
	if ($status.status -eq "Active") {
		$elapsedtime = ((Get-Date) - [datetime]$status.createdOn).TotalSeconds
		$statusmessage = "[Elapsed (seconds): {0:N2} ] {1}" -f $elapsedtime, $status.message
		if ($status.progress) {
			Write-Progress -Activity "Waiting for scan to process" -status $statusmessage -percentComplete ($status.progress)	
		} else {
			Write-Progress -Activity "Waiting for scan to process" -status $statusmessage
		}
	} else {
		$active = $false
		if ($status.status -eq "Error") {
			Write-Host -ForegroundColor Red "ERROR: Could not complete scan and analysis."
			Write-Host -ForegroundColor Red "$status.message"
		} elseif ($status.status -eq "Completed") {
			Write-Host "Scan Completed in $elapsedtime seconds"
		} else {
			Write-Host -ForegroundColor Red "Something went wrong..."
			Write-Host -ForegroundColor Red "$status.message"
		}
	}
}