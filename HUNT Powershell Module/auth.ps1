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
	Write-Warning "Disabling SSL Verification!"
    if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
        Add-Type -TypeDefinition $sslverificationcode
    }
    [TrustEverything]::SetCallback()
}

#Get Login Token (required)
function New-ICToken ([PSCredential]$Credential, [String]$HuntServer = "https://localhost:443" ) {
	Write-Verbose "Requesting new Token from $HuntServer using account $($Credential.username)"
	Write-Verbose "Credentials and Hunt Server Address are stored in global variables for use in all IC cmdlets"

	_DisableSSLVerification

  $url = "$HuntServer/api/users/login"

	if (-NOT $Credential) {
		# Default Credentials
		$username = 'infocyte'
		$password = 'hunt' | ConvertTo-SecureString -asPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential($username,$password)
	}

	$Global:HuntServerAddress = $HuntServer

	$data = @{
		username = $Credential.GetNetworkCredential().username
		password = $Credential.GetNetworkCredential().password
	}
	$i = $data | ConvertTo-JSON
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

function Set-ICToken ([String]$HuntServer = "https://localhost:443", [String]$Token) {
		Write-Verbose "Setting Auth Token for $HuntServer to $Token"
		Write-Verbose "Token and Hunt Server Address are stored in global variables for use in all IC cmdlets"

		# Set Token to global variable
		$Global:ICToken = $Token
		$Global:HuntServerAddress = $HuntServer
}
