New-Module -name install_huntagent -scriptblock {
	# Definately Not Malware
	# Infocyte HUNT scripted installation option. If unfamiliar with this script, contact your IT or Security team.
	# www.infocyte.com

	# To execute this script as a one liner on a windows host with powershell 2.0+, run this command replacing instancename and key with your hunt instance <mandatory> and registration key [optional]
	# [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent <instancename> [regkey]

	# Example:
	# [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent alpo1 asdfhrendsa

	Function Install-HuntAgent() {
		param(
			[Parameter(Position = 0, Mandatory = $True)]
			[String]$InstanceName,

			[Parameter(Position = 1, Mandatory = $False)]
			[String]$RegKey,

			[Parameter(Mandatory = $False)]
			[Switch]$Interactive
		)

		$LogPath = "$($env:TEMP)\huntagentinstall.log"

		# Make script silent unless run interactive
		if (-NOT $Interactive) { $ErrorActionPreference = "silentlycontinue" }

		If (-NOT $InstanceName) {
			if ($Interactive) { Write-Error "Please provide Infocyte HUNT instance name (i.e. mycompany in mycompany.infocyte.com)" }
			"$(Get-Date) [Error] Installation Error: No InstanceName provided in arguments." >> $LogPath
			return
		}

		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			if ($Interactive) { Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" }
			"$(Get-Date) [Error] Installation Error: Script not run as administrator" >> $LogPath
			return
		}

		$InstallPath = 'C:\Program Files\Infocyte\Agent\agent.windows.exe'
		If (Get-Service -name huntAgent -ErrorAction SilentlyContinue) {
			if ($Interactive) { Write-Error "huntAgent service already installed" }
			"$(Get-Date) [Information] HUNTAgent service already running. Skipping." >> $LogPath
			return
		}

		# Downloading Agent
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		$agentURL = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows.exe"
		$agentDestination = "$($env:TEMP)\agent.windows.exe"
		$url = "$InstanceName.infocyte.com"

		$wc = New-Object Net.WebClient
		$wc.UseDefaultCredentials = $true
		$wc.Encoding = [System.Text.Encoding]::UTF8
		# $wc.CachePolicy = New-Object System.Net.Cache.HttpRequestCachePolicy([System.Net.Cache.HttpRequestCacheLevel]::NoCacheNoStore) # For Testing:
		try {
			$wc.DownloadFile($agentURL, $agentDestination)
		} catch {
			if ($Interactive) { Write-Error "Could not download HUNT agent from $agentURL" }
			"$(Get-Date) [Error] Installation Error: Could not download agent.windows.exe from $agentURL." >> $LogPath
		}

		# Verify Sha1 of file
		try {
			$SHA1CryptoProvider = new-object -TypeName system.security.cryptography.SHA1CryptoServiceProvider
			$inputBytes = [System.IO.File]::ReadAllBytes($agentDestination);
			$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA1CryptoProvider.ComputeHash($inputBytes))
			$sha1 = $Hash.Replace('-','').ToUpper()
			"$(Get-Date) [Information] Installation: agent.windows.exe downloaded from $agentURL with sha1: $sha1" >> $LogPath
		} catch {
			if ($Interactive) { Write-Warning "Hash Error. $_" }
			"$(Get-Date) [Warning] Installation Warning: Could not hash agent.survey.exe." >> $LogPath
		}

		# Setup exe arguments
		$arguments = "--url $url --install"
		if (-NOT $interactive) { $arguments += " --quiet" }
		if ($RegKey) { $arguments += " --key $APIKey" }

		# Execute!
		& $agentDestination $arguments
		"$(Get-Date) [Information] Installation: agent.windows.exe installed with the following commandline: $($agentDestination.Substring($agentDestination.LastIndexOf('\')+1)) $arguments" >> $LogPath
	}
Set-Alias installagent -Value Install-HuntAgent | Out-Null
Export-ModuleMember -Alias 'installagent' -Function 'Install-HuntAgent' | Out-Null
}
