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
	[System.Net.ServicePointManager]::MaxServicePointIdleTime = 60000

	if ($Instance -match "https://*") {
		$Global:HuntServerAddress = $Instance
	} elseif ($Instance -match ".*infocyte.com") {
		$Global:HuntServerAddress = "https://$Instance"
	} else {
		$Global:HuntServerAddress = "https://$Instance.infocyte.com"
	}
	Write-Verbose "Setting Global API URL to $Global:HuntServerAddress/api"

	if ($IsWindows -OR $env:OS -match "windows") {
		$credentialfile = "$env:appdata/infocyte/credentials.json"
	} 
	else {
		$credentialfile = "$env:HOME/infocyte/credentials.json"
	}

	$Global:ICCredentials = @{}
	if (Test-Path $credentialfile) {
		(Get-Content $credentialfile | ConvertFrom-JSON).psobject.properties | ForEach-Object {
			$Global:ICCredentials[$_.Name] = $_.Value
		}
	} else {
		if (-NOT (Test-Path (Split-Path $credentialfile))) {
			New-Item -ItemType "directory" -Path (Split-Path $credentialfile) | Out-Null
		}
	}

	if ($Token) {
		# Set Token to global variable
		if ($Token.length -eq 64) {
				$Global:ICToken = $Token
				Write-Verbose "Setting Auth Token for $Global:HuntServerAddress to $Token"
		} else {
			Throw "Invalide token. Must be a 64 character string generated within your profile or admin panel within Infocyte HUNT's web console"
			return
		}
	} else {
		# Load from file
		if ($Global:ICCredentials[$Global:HuntServerAddress]) {
			Write-Verbose "Setting auth token from credential file: $credentialfile"
			$Global:ICToken = $Global:ICCredentials[$Global:HuntServerAddress]
		} else {
			Throw "No Token found for $($Global:HuntServerAddress) in credential file! Please provide credentials with -Save switch to save them to credential file first."
		}
	}

	if ($Proxy) {
			Write-Verbose "Infocyte API functions will use Proxy: $Proxy"
			$Global:Proxy = $Proxy
			if ($ProxyUser -AND $ProxyPass) {
				Write-Verbose "Infocyte API functions will now use Proxy User: $ProxyUser"
				$pw = ConvertTo-SecureString $ProxyPass -AsPlainText -Force
				$Global:ProxyCredential = New-Object System.Management.Automation.PSCredential ($ProxyUser, $pw)
			}
	} else {
		# Load from file
		$Global:Proxy = $Global:ICCredentials["Proxy"]
		if ($Global:Proxy) {
			Write-Verbose "Infocyte API functions will use Proxy config loaded from credential file: $($Global:Proxy)"
		}
		if ($Global:ICCredentials["ProxyUser"]) {
			$pw = ConvertTo-SecureString $Global:ICCredentials["ProxyPass"] -AsPlainText -Force
			$Global:ProxyCredential = New-Object System.Management.Automation.PSCredential ($Global:ICCredentials["ProxyPass"], $pw)
		}
	}

	#Test connection
	$ver = Get-ICAPI -Endpoint "Version"

	# Set initial default boxId (change with Set-ICBox) and test connection
	$box = Get-ICBox -Last 7 -Global

	if ($box) {
		Write-Verbose "Successfully connected to $Global:HuntServerAddress"
		$Global:ICCurrentBox = $box.id
		Write-Verbose "`$Global:ICCurrentBox is set to $($box.targetGroup)-$($box.name) [$($box.id)]"
		Write-Verbose "All analysis data & object retrieval will default to this box."
		Write-Verbose "Use Set-ICBox to change the default in this session."
	} else {
		Throw "Your connection to $Global:HuntServerAddress failed using Infocyte API URI: $Global:HuntServerAddress`nToken: $Global:ICToken`nProxy: $Global:Proxy`nProxyUser: $($Global:ICCredentials['ProxyUser'])"
	}


	if ($Save) {
		Write-Verbose "Saving Token and Proxy settings to credential file: $credentialfile"
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
			Write-Verbose "Previous credential file has been backed up."
			Copy-Item -Path $credentialfile -Destination "$($credentialfile)-OLD"
		}
		$Global:ICCredentials | ConvertTo-JSON | Out-File $credentialfile -Force
		Write-Verbose "Token, Hunt Server Address, and Proxy settings are stored on disk. Omit token and proxy arguments to use saved versions."
	} else {
		Write-Verbose "Token, Hunt Server Address, and Proxy settings are stored in global session variables for use in all IC cmdlets."
	}

	Return $true
	
}
