New-Module -name survey -scriptblock {
	# Infocyte HUNT scripted survey option (manual scan). If unfamiliar with this script, contact your IT or Security team.
	# www.infocyte.com

	# WARNING: Single line scripts like this use similiar techniques to modern staged malware.
	# As a result, this script will likely trigger behavioral detection products and may need to be whitelisted.

	# To execute this script as a one liner on a windows host with powershell 3.0+ (.NET 4.5+), run this command replacing instancename and key with your hunt instance <mandatory> and registration key [optional]. NOTE: Instancename is the cname from the URL, not the FULL url https://instancename.infocyte.com). This script will append the url for you during install.
	# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -win 1 -executionpolicy bypass -nop -command { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-objectNet.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/manualscan/survey.ps1") | iex; survey <instancename> <regkey> }

	# HElPER FUNCTIONS
	$Depth = 10

	# Used with most Infocyte Get methods. Takes a filter object (hashtable) and adds authentication and passes it as the body for URI encoded parameters. NoLimit will iterate 1000 results at a time to the end of the data set.
	function _ICGetMethod ([String]$url, [HashTable]$filter, [Switch]$NoLimit) {
	  $skip = 0
	  if ($Interactive) { Write-Progress -Activity "Getting Data from Hunt Server API" -status "Requesting data from $url [$skip]" }
	  $count = 0
	  $body = @{
			access_token = $Global:ICToken
		}
	  if ($filter) {
	    $body['filter'] = $filter | ConvertTo-JSON -Depth $Depth -Compress
	  }
	  Write-Verbose "Requesting data from $url (Limited to $resultlimit unless using -NoLimit)"
	  Write-Verbose "$($body | ConvertTo-JSON -Depth $Depth -Compress)"
		try {
			$Objects = Invoke-RestMethod $url -body $body -Method GET -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
		} catch {
			if ($Interactive) { Write-Warning "Error: $_" }
			"$(Get-Date) [Error] REST Error: $($_.Exception.Message)" >> $LogPath
			return "ERROR: $($_.Exception.Message)"
		}
		if ($Objects) {
	    $count += $Objects.count
			Write-Output $Objects
		} else {
			return $null
		}
		$GlobalLimit = 10000
	  if ($NoLimit -AND $Objects.count -eq $resultlimit) { $more = $true } else { $more = $false }
	  if ($Objects.count -gt $Globallimit) {
	    $more = $FALSE
	    if ($Interactive) { Write-Warning "Reached Global Limit ($GlobalLimit) -- Try refining your query with a where filter. Performance on the database seriously degrades when trying to pull more than 100k objects" }
	  }
		While ($more) {
			$skip += $resultlimit
			$filter['skip'] = $skip
			$body.remove('filter') | Out-Null
			$body.Add('filter', ($filter | ConvertTo-JSON -Depth $Depth -Compress))
	    Write-Progress -Activity "Getting Data from Hunt Server API" -status "Requesting data from $url [$skip]"
			try {
				$moreobjects = Invoke-RestMethod $url -body $body -Method GET -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
			} catch {
				If ($Interactive) { Write-Warning "Error: $_" }
				"$(Get-Date) [Error] REST Error: $($_.Exception.Message)" >> $LogPath
				return "ERROR: $($_.Exception.Message)"
			}
			if ($moreobjects.count -gt 0) {
	      $count += $moreobjects.count
				Write-Output $moreobjects
			} else {
				$more = $false
			}
		}
	  Write-Verbose "Recieved $count objects from $url"
	}

	# Used with all other rest methods. Pass a body (hashtable) and it will add authentication.
	function _ICRestMethod ([String]$url, $body=$null, [String]$method) {
	  $headers = @{
	    Authorization = $Global:ICToken
	  }
	  Write-verbose "Sending $method command to $url"
	  Write-verbose "Body = $($body | ConvertTo-JSON -Compress -Depth 10)"
		try {
			$Result = Invoke-RestMethod $url -headers $headers -body ($body|ConvertTo-JSON -Compress -Depth $Depth) -Method $method -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
		} catch {
			if ($Interactive) { Write-Warning "Error: $_" }
			"$(Get-Date) [Error] REST Error: $($_.Exception.Message)" >> $LogPath
			throw "ERROR: $($_.Exception.Message)"
		}
		if ($Result) {
			Write-Output $Result
		} else {
			return $null
		}
	}

	# Generate an API token in the web console's profile or admin section.
	function Set-ICToken {
		[cmdletbinding()]
		param(
			[parameter(Mandatory=$true)]
			[ValidateNotNullOrEmpty()]
			[String]$HuntServer = "https://localhost:443",

			[parameter(Mandatory=$true)]
			[ValidateNotNullorEmpty()]
			[String]$Token,

			[String]$Proxy,
			[String]$ProxyUser,
			[String]$ProxyPass,

			[Switch]$DisableSSLVerification
		)

		if ($DisableSSLVerification) {
			_DisableSSLVerification
		}
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

		if ($HuntServer -notlike "https://*") {
			$Global:HuntServerAddress = "https://" + $HuntServer
		} else {
			$Global:HuntServerAddress = $HuntServer
		}

		# Set Token to global variable
		if ($Token.length -eq 64) {
				$Global:ICToken = $Token
		} else {
			if ($Interactive) { Write-Warning "That token won't work. Must be a 64 character string generated within your profile or admin panel within Infocyte HUNT's web console" }
			return
		}
		if ($Interactive) { Write-Host "Setting Auth Token for $HuntServer to $Token" }
		if ($Proxy) {
				$Global:Proxy = $Proxy
				if ($ProxyUser -AND $ProxyPass) {
					$pw = ConvertTo-SecureString $ProxyPass -AsPlainText -Force
					$Global:ProxyCredential = New-Object System.Management.Automation.PSCredential ($ProxyUser, $pw)
				}
		}
		Write-Verbose "Token, Hunt Server Address, and Proxy settings are stored in global variables for use in all IC cmdlets"
	}

	function New-ICTargetGroup {
	  param(
	    [parameter(Mandatory=$true, Position=0)]
	    [ValidateNotNullOrEmpty()]
	    [String]$Name
	  )

	  $Endpoint = "targets"
	  $body = @{
	    name = $Name
	  }
	  if ($Interactive) { Write-Host "Creating new target group: $Name [$HuntServerAddress/api/$Endpoint]" }
	  _ICRestMethod -url $HuntServerAddress/api/$Endpoint -body $body -method 'POST'
	}

	function Get-ICTargetGroups ([String]$TargetGroupId) {
	  $Endpoint = "targets"
	  $filter =  @{
	    order = @("name", "id")
	    limit = $resultlimit
	    skip = 0
	  }
	  if ($TargetGroupId) {
	    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true | where { $_.id -eq $TargetGroupId}
	  } else {
	    _ICGetMethod -url $HuntServerAddress/api/$Endpoint -filter $filter -NoLimit:$true
	  }
	}

	function Import-ICSurvey {
		[cmdletbinding(DefaultParameterSetName = 'Path')]
		param(
			[parameter(
					Mandatory,
					ParameterSetName  = 'Path',
					Position = 0,
					ValueFromPipeline,
					ValueFromPipelineByPropertyName
			)]
			[ValidateNotNullOrEmpty()]
			[SupportsWildcards()]
			[string[]]$Path, # <paths of the survey results (.bz2) files to upload>

			[parameter(
					Mandatory,
					ParameterSetName = 'LiteralPath',
					Position = 0,
					ValueFromPipelineByPropertyName
			)]
			[ValidateNotNullOrEmpty()]
			[Alias('PSPath')]
			[string[]]$LiteralPath,

	  	[String]$TargetGroupName = "OfflineScans"
	  )

	  BEGIN {
	  	# INITIALIZE
	  	$survey = "HostSurvey.json.gz"
	  	$surveyext = "*.json.gz"

	  	function Upload-ICSurveys ([String]$FilePath, [String]$ScanId){
	  		Write-Verbose "Uploading Surveys"
				$headers = @{
			    Authorization = $Global:ICToken
					scanid = $ScanId
			  }
	  		try {
					$objects = Invoke-RestMethod $HuntServerAddress/api/survey -Headers $headers -Method POST -InFile $FilePath -ContentType "application/octet-stream" -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
	  		} catch {
	  			if ($Interactive) { Write-Warning "Error: $_" }
					"$(Get-Date) [Error] Upload Error: $($_.Exception.Message)" >> $LogPath
	  			throw "ERROR: $($_.Exception.Message)"
	  		}
	  		#$objects
	  	}

			if ($ScanId) {
				# Check for existing ScanId and use it
				$scans = Get-ICScans -NoLimit
				if ($scans.id -contains $ScanId) {
					$TargetGroupName = ($Scans | where { $_.scanId -eq $ScanId}).targetList
				} else {
					Throw "No scan exists with ScanId $ScanId. Specify an existing ScanId to add this survey result to or use other parameters to generate one."
				}
			}
			elseif ($TargetGroupId) {
				# Check TargetGroupId and create new ScanId for that group
				if ($Interactive) { Write-Host "Checking for existance of target group with TargetGroupId: '$TargetGroupId' and generating new ScanId" }
				$TargetGroups = Get-ICTargetGroups
				if ($TargetGroups.id -contains $TargetGroupId) {
					$TargetGroupName = ($TargetGroups | where { $_.id -eq $TargetGroupId }).name
				} else {
					Throw "No Target Group exists with TargetGroupId $TargetGroupId. Specify an existing TargetGroupId to add this survey to or use other parameters to generate one."
				}
			}
			else {
				if ($Interactive) { Write-Host "No ScanId or TargetGroupId specified. Checking for existance of target group: '$TargetGroupName'" }
		  	$TargetGroups = Get-ICTargetGroups
		  	if ($TargetGroups.name -contains $TargetGroupName) {
		  		if ($Interactive) { Write-Host "$TargetGroupName Exists." }
					$TargetGroupId = ($targetGroups | where { $_.name -eq $TargetGroupName}).id
		  	} else {
		  			if ($Interactive) { Write-Host "$TargetGroupName does not exist. Creating new Target Group '$TargetGroupName'" }
						"$(Get-Date) [Status] $TargetGroupName does not exist. Creating new Target Group '$TargetGroupName'" >> $LogPath
		  			New-ICTargetGroup -Name $TargetGroupName
						Start-Sleep 1
						$TargetGroups = Get-ICTargetGroups
						$TargetGroupId = ($targetGroups | where { $_.name -eq $TargetGroupName}).id
		  	}
			}

			# Creating ScanId
			if (-NOT $ScanId) {
				$ScanName = "Offline-" + (get-date).toString("yyyyMMdd-HHmm")
				if ($Interactive) { Write-Host "Creating scan named $ScanName [$TargetGroupName-$ScanName]..." }
				$StartTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
				$body = @{
					name = $scanName;
					targetId = $TargetGroupId;
					startedOn = $StartTime
				}
				try {
					$newscan = _ICRestMethod -url $HuntServerAddress/api/scans -body $body -Method 'POST' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
				} catch {
					if ($Interactive) { Write-Warning "Error: $_" }
					"$(Get-Date) [Error] ScanId Creation Error: $($_.Exception.Message)" >> $LogPath
					throw "ERROR: $($_.Exception.Message)"
				}
				Start-Sleep 1
				$ScanId = $newscan.id
			}


			if ($Interactive) { Write-Host "Importing Survey Results into $TargetGroupName-$ScanName [ScanId: $ScanId] [TargetGroupId: $TargetGroupId]" }
			"Importing Survey Results into $TargetGroupName-$ScanName [ScanId: $ScanId] [TargetGroupId: $TargetGroupId]" >> $LogPath
	  }

	  PROCESS {
			# Resolve path(s)
	        if ($PSCmdlet.ParameterSetName -eq 'Path') {
	            $resolvedPaths = Resolve-Path -Path $Path | Select-Object -ExpandProperty Path
	        } elseif ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
	            $resolvedPaths = Resolve-Path -LiteralPath $LiteralPath | Select-Object -ExpandProperty Path
	        }

					# Process each item in resolved paths
					foreach ($file in $resolvedPaths) {
			 			if ($Interactive) { Write-Host "Uploading survey [$file]..." }
			 			if ((Test-Path $file -type Leaf) -AND ($file -like $surveyext)) {
			 				Upload-ICSurveys -FilePath $file -ScanId $ScanId
			   		} else {
			   			if ($Interactive) { Write-Warning "$file does not exist or is not a $surveyext file" }
			   		}
			   	}
		}

	  END {
	  	# TODO: detect when scan is no longer processing submissions, then mark as completed
	  	#Write-Host "Closing scan..."
	  	#Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$HuntServerAddress/api/scans/$scanId/complete" -Method Post
	  }

	}

	Function Invoke-HuntSurvey() {
		param(
			[Parameter(Mandatory = $True, Position = 0)]
			[String]$InstanceName,

			[Parameter(Mandatory = $True, Position = 1)]
			[String]$APIKey,

			[String]$Proxy, # "http://proxyserver:port"

			[String]$ProxyUser,

			[String]$ProxyPass,

			[Switch]$Interactive
		)

		$Global:Interactive = $Interactive
		$SurveyDestination = "$($env:TEMP)\survey.exe"
		$SurveyResults = "$($env:TEMP)\hostsurvey.json.gz"
		$LogPath = "$($env:TEMP)\s1_deploy.log"
		$hunturl = "https://$InstanceName.infocyte.com"
		$HuntAPI = "https://$InstanceName.infocyte.com/api"
		$DownloadEndpoint = "/survey/download-client"

		Set-ICToken -HuntServer $hunturl -Token $APIKey -Proxy $Proxy -ProxyUser $ProxyUser -ProxyPass $ProxyPass

		# Make script silent unless run interactive
		if (-NOT $Interactive) {
			$ErrorActionPreference = "SilentlyContinue"
			$ProgressPreference = "SilentlyContinue"
		}

		If (-NOT $InstanceName) {
			if ($Interactive) { Write-Error "Please provide Infocyte HUNT instance name (i.e. mycompany in mycompany.infocyte.com)" }
			"$(Get-Date) [Error] Install started but no InstanceName provided in arguments." >> $LogPath
			return
		}

		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			if ($Interactive) { Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" }
			"$(Get-Date) [Error] Survey Error: Survey started but script not run as administrator" >> $LogPath
			return
		}

		# Downloading Survey
		$URL = $HuntAPI+$DownloadEndpoint+"?platform=windows&access_token=$APIKey"
		if ($Interactive) { Write-Host "Pulling Survey Binary down from $hunturl" }
		try {
			$a = Invoke-RestMethod -Method GET -Uri $URL -OutFile $SurveyDestination -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
		} catch {
			if ($Interactive) { Write-Error "Could not download HUNT Survey from $binaryURL" }
			"$(Get-Date) [Error] Survey Error: Install started but could not download survey.exe from $binaryURL." >> $LogPath
			return
		}


		# Verify Sha1 of file [to do: Finish]
		try {
			$SHA1CryptoProvider = new-object -TypeName system.security.cryptography.SHA1CryptoServiceProvider
			$inputBytes = [System.IO.File]::ReadAllBytes($SurveyDestination);
			$Hash = [System.BitConverter]::ToString($SHA1CryptoProvider.ComputeHash($inputBytes))
			$sha1 = $Hash.Replace('-','').ToUpper()
		} catch {
			if ($Interactive) { Write-Warning "Hash Error. $_" }
			$sha1 = "Hashing Error"
			#"$(Get-Date) [Warning] Installation Warning: Could not hash survey.exe." >> $LogPath
		}

		$msg = "$(Get-Date) [Information] Running Survey: Downloading survey.exe from $binaryURL [sha1: $sha1] and executing: $SurveyDestination"
		$msg >> $LogPath
		if ($Interactive) { Write-Host $msg }
		# Execute!

 		try {
			if ($Interactive) {
				Start-Process -NoNewWindow -FilePath $SurveyDestination -ErrorAction Stop -Wait
			} else {
				Start-Process -WindowStyle Hidden -FilePath $SurveyDestination -ErrorAction Stop -Wait
			}
		} catch {
			"$(Get-Date) [Error] Survey Error: Could not start survey.exe. [$_]" >> $LogPath
			Return
		}

		# Upload results-
		if ($Interactive) { Write-Host Sending Survey Results to $hunturl }
		Import-ICSurvey -Path $SurveyResults -TargetGroupName "ManualScans" #| Out-Null

	}

Set-Alias survey -Value Invoke-HuntSurvey | Out-Null
Export-ModuleMember -Alias 'survey' -Function 'Invoke-HuntSurvey' | Out-Null
}
