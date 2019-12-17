# Helpers

$sslverificationcode = @"
		using System.Net.Security;
		using System.Security.Cryptography.X509Certificates;
		public static class TrustEverything
		{
				private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
						SslPolicyErrors sslPolicyErrors) { return true; }
				public static void SetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback; }
				public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; }
		}
"@

function _DisableSSLVerification {
	Write-Verbose "Disabling SSL Verification!"
    if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
        Add-Type -TypeDefinition $sslverificationcode
    }
    [TrustEverything]::SetCallback()
}

#Get Login Token (required) -- NOTE: Depreciated in the SaaS version
function New-ICToken {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$HuntServer = "https://localhost:443",

		[parameter(Mandatory=$true)]
		[System.Management.Automation.PSCredential]
		$Credential
	)

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	_DisableSSLVerification

	if ($HuntServer -notlike "https://*") {
		$Global:HuntServerAddress = "https://" + $HuntServer
	} else {
		$Global:HuntServerAddress = $HuntServer
	}
  	$url = "$Global:HuntServerAddress/api/users/login"

	if (-NOT $Credential) {
		# Default Credentials
		Write-Verbose "No Credentials provided"
		$Credential = Get-Credential
	}



	$data = @{
		username = $Credential.GetNetworkCredential().username
		password = $Credential.GetNetworkCredential().password
	}
	$i = $data | ConvertTo-JSON
	Write-Host "Requesting new Token from $Global:HuntServerAddress using account $($Credential.username)"
	Write-Verbose "Credentials and Hunt Server Address are stored in global variables for use in all IC cmdlets"

	try {
		$response = Invoke-RestMethod $url -Method POST -Body $i -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($response -match "Error") {
		Write-Warning "Error: Unauthorized"
		return "ERROR: $($_.Exception.Message)"
	} else {
		# Set Token to global variable
		$Global:ICToken = $response.id
		Write-Verbose 'New token saved to global variable: $Global:ICToken'
		$response
	}
}


# Generate an API token in the web console's profile or admin section.
# You can save tokens and proxy info to disk as well with the -Save switch.
function Set-ICToken {
	[cmdletbinding()]
	[alias("Set-ICInstance")]
	param(
		[parameter(Mandatory=$true, HelpMessage="Infocyte Cloud Instance Name (e.g. 'clouddemo') or Full URL of Server/API (e.g. https://CloudDemo.infocyte.com)'")]
		[ValidateNotNullOrEmpty()]
		[alias("HuntServer")]
		[String]$Instance,

		[parameter(HelpMessage="API Token from Infocyte App. Omit if using saved credentials.")]
		[String]$Token,

		[parameter(HelpMessage="Proxy Address and port: e.g. '192.168.1.5:8080'")]
		[String]$Proxy,
		[String]$ProxyUser,
		[String]$ProxyPass,

		[Switch]$DisableSSLVerification,

		[parameter(HelpMessage="Will save provided token and proxy settings to disk for future use with this Infocyte Instance.")]
		[Switch]$Save
	)

	if ($DisableSSLVerification) {
		_DisableSSLVerification
	}
	Write-Verbose "Setting Security Protocol to TLS1.2"
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	if ($Instance -match "[:\.]+") {
		if ($Instance -notlike "https://*") {
			$Global:HuntServerAddress = "https://$Instance"
		} else {
			$Global:HuntServerAddress = $Instance
		}
	} else {
		$Global:HuntServerAddress = "https://$Instance.infocyte.com"
	}
	Write-Host "Setting Global API URL to $Global:HuntServerAddress/api"

	$credentialfile = "$env:appdata\infocyte\credentials.json"
	$Global:ICCredentials = @{}
	if (Test-Path $credentialfile) {
		(Get-Content $credentialfile | ConvertFrom-JSON).psobject.properties | Foreach {
			$Global:ICCredentials[$_.Name] = $_.Value
		}
	} else {
		if (-NOT (Test-Path "$env:appdata\infocyte")) {
			New-Item -ItemType "directory" -Path "$env:appdata\infocyte"
		}
	}

	if ($Token) {
		# Set Token to global variable
		if ($Token.length -eq 64) {
				$Global:ICToken = $Token
				Write-Host "Setting Auth Token for $Global:HuntServerAddress to $Token"
		} else {
			Write-Warning "That token won't work. Must be a 64 character string generated within your profile or admin panel within Infocyte HUNT's web console"
			return
		}
	} else {
		# Load from file
		if ($Global:ICCredentials[$Global:HuntServerAddress]) {
			Write-Host "Setting auth token from credential file: $credentialfile"
			$Global:ICToken = $Global:ICCredentials[$Global:HuntServerAddress]
		} else {
			Write-Warning "No Token found for $($Global:HuntServerAddress) in credential file!"
			Write-Warning "Please provide credentials with -Save switch to save them to credential file first."
			return
		}
	}

	if ($Proxy) {
			Write-Host "Infocyte API functions will use Proxy: $Proxy"
			$Global:Proxy = $Proxy
			if ($ProxyUser -AND $ProxyPass) {
				Write-Host "Infocyte API functions will now use Proxy User: $ProxyUser"
				$pw = ConvertTo-SecureString $ProxyPass -AsPlainText -Force
				$Global:ProxyCredential = New-Object System.Management.Automation.PSCredential ($ProxyUser, $pw)
			}
	} else {
		# Load from file
		$Global:Proxy = $Global:ICCredentials["Proxy"]
		if ($Global:Proxy) {
			Write-Host "Infocyte API functions will use Proxy config loaded from credential file: $($Global:Proxy)"
		}
		if ($Global:ICCredentials["ProxyUser"]) {
			$pw = ConvertTo-SecureString $Global:ICCredentials["ProxyPass"] -AsPlainText -Force
			$Global:ProxyCredential = New-Object System.Management.Automation.PSCredential ($Global:ICCredentials["ProxyPass"], $pw)
		}
	}

	# Set initial default boxId (change with Set-ICBox) and test connection
	$box = Get-ICBox -Last7 -Global
	if ($box) {
		$Global:ICCurrentBox = $box.id
		Write-Host "`$Global:ICCurrentBox is set to $($box.targetGroup)-$($box.name) [$($box.id)]"
		Write-Host "All analysis data & object retrieval will default to this box."
		Write-Host "Use Set-ICBox to change the default in this session."
	} else {
		Write-Error "Your connection to $Global:HuntServerAddress failed!"
		Write-Warning "`nInfocyte API URI: $Global:HuntServerAddress`nToken: $Global:ICToken`nProxy: $Global:Proxy`nProxyUser: $($Global:ICCredentials["ProxyUser"])"
	}


	if ($Save) {
		Write-Host "Saving Token and Proxy settings to credential file: $credentialfile"
		$Global:ICCredentials[$Global:HuntServerAddress] = $Global:ICToken
		if ($Proxy) {
			$Global:ICCredentials["Proxy"] = $Proxy
			if ($ProxyUser -AND $ProxyPass) {
				$Global:ICCredentials["ProxyUser"] = $ProxyUser
				$Global:ICCredentials["ProxyPass"] = $ProxyPass
			}
		}
		if (Test-Path $credentialfile) {
			# Archive current credential
			Write-Host "Previous credential file has been backed up."
			Copy-Item -Path $credentialfile -Destination "$($credentialfile)-OLD"
		}
		$Global:ICCredentials | ConvertTo-JSON | Out-File $credentialfile -Force
		Write-Host "Token, Hunt Server Address, and Proxy settings are stored on disk. Omit token and proxy arguments to use saved versions."
	} else {
		Write-Host "Token, Hunt Server Address, and Proxy settings are stored in global session variables for use in all IC cmdlets."
	}
}
