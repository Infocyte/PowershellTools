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
		[String]
		$HuntServer = "https://localhost:443",

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
function Set-ICToken {
	[cmdletbinding()]
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$HuntServer = "https://localhost:443",

		[parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[String]$Token
	)

	Write-Host "Setting Auth Token for $HuntServer to $Token"
	Write-Verbose "Token and Hunt Server Address are stored in global variables for use in all IC cmdlets"

	# Set Token to global variable
	$Global:ICToken = $Token
	$Global:HuntServerAddress = $HuntServer
}
