New-Module -name install_huntagent -scriptblock {
	# Infocyte HUNT scripted installation option. If unfamiliar with this script, contact your IT or Security team.
	# www.infocyte.com

	# WARNING: Single line scripted installers like this use similiar techniques to modern staged malware.
	# As a result, this script will likely trigger behavioral detection products and may need to be whitelisted.

	# To execute this script as a one liner on a windows host with powershell 3.0+ (.NET 4.5+), run this command replacing instancename and key with your hunt instance <mandatory> and registration key [optional]. NOTE: Instancename is the cname from the URL, not the FULL url https://instancename.infocyte.com). This script will append the url for you during install.
	# [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent <instancename> [regkey]

	# Example:
	# [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent alpo1 asdfhrendsa

	# Logs are stored here: "$($env:TEMP)\huntagentinstall.log"

	Function Install-HuntAgent() {
		param(
			[Parameter(Mandatory=$true, Position = 0, HelpMessage="The cname from the URL: https://<instancename>.infocyte.com)")]
			[String]$InstanceName,

			[Parameter(Position = 1, HelpMessage="This will automatically approve the agent registration and add it to its' default Target Group.")]
			[String]$RegKey,

			[Parameter(HelpMessage="Will register a name for the system. Otherwise will use the hostname.")]
			[String]$FriendlyName,

			[Parameter(HelpMessage='Authenticated: "user:password@192.168.1.1:8080" or Unauthenticated: "192.168.1.1:8080"')]
			[String]$Proxy, # "user:password@192.168.1.1:8080" or "192.168.1.1:8080"

			[Parameter(HelpMessage="Silent install is default. Use this switch to display output.")]
			[Switch]$Interactive,

			[Parameter(HelpMessage="Will force a reinstall if agent already installed.")]
			[Switch]$Force
		)

		$agentDestination = "$($env:TEMP)\agent.windows.exe"
		$LogPath = "($env:SystemDrive)\windows\Temp\infocyteagentinstaller.log"
		$agentURL = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows.exe"
		$hunturl = "https://$InstanceName.infocyte.com"

		If (-NOT $InstanceName) {
			Write-Warning "[Error] Please provide Infocyte HUNT instance name (i.e. mycompany in mycompany.infocyte.com)"
			"$(Get-Date) [Error] Installation Error: No InstanceName provided in arguments!" >> $LogPath
			return
		}

		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			Write-Warning "[Error] You do not have Administrator rights to run this script!`nPlease re-run as an Administrator!"
			"$(Get-Date) [Error] Installation Error: Script not run as administrator!" >> $LogPath
			return
		}

		# Make script silent unless run interactive
		if (-NOT $Interactive) { $ErrorActionPreference = "silentlycontinue" }

		$InstallPath = 'C:\Program Files\Infocyte\Agent\agent.windows.exe'
		If (Get-Service -name huntAgent -ErrorAction SilentlyContinue) {
			if ($Force) {
				$Uninstall = $True
			else {
				if ($Interactive) { Write-Error "huntAgent service already installed" }
				"$(Get-Date) [Information] Install started but HUNTAgent service already running. Skipping." >> $LogPath
				return
			}
		}

		# Downloading Agent
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		$wc = New-Object Net.WebClient
		$wc.UseDefaultCredentials = $true
		$wc.Encoding = [System.Text.Encoding]::UTF8
		# $wc.CachePolicy = New-Object System.Net.Cache.HttpRequestCachePolicy([System.Net.Cache.HttpRequestCacheLevel]::NoCacheNoStore) # For Testing:
		try {
			$wc.DownloadFile($agentURL, $agentDestination)
		} catch {
			if (-NOT $Silent) { Write-Warning "Could not download HUNT agent from $agentURL" }
			"$(Get-Date) [Error] Installation Error: Install started but could not download agent.windows.exe from $agentURL." >> $LogPath
		}

		# Verify Sha1 of file
		try {
			$SHA1CryptoProvider = new-object -TypeName system.security.cryptography.SHA1CryptoServiceProvider
			$inputBytes = [System.IO.File]::ReadAllBytes($agentDestination);
			$Hash = [System.BitConverter]::ToString($SHA1CryptoProvider.ComputeHash($inputBytes))
			$sha1 = $Hash.Replace('-','').ToUpper()
		} catch {
			if (-NOT $Silent) { Write-Warning "Hash Error. $_" }
			$sha1 = "Hashing Error"
			#"$(Get-Date) [Warning] Installation Warning: Could not hash agent.survey.exe." >> $LogPath
		}

		# Uninstall if already installed and forcing a reinstall
		if ($Force -AND $Uninstall) {
			if ($Interactive) { Write-Warning "huntAgent service already installed. Forcing a reinstall." }
			"$(Get-Date) [Information] HUNTAgent service already running. Forcing a reinstall." >> $LogPath

			$arguments = @("--uninstall")
			if (-NOT $interactive) { $arguments += "--quiet" }
			try {
				Start-Process -NoNewWindow -FilePath $agentDestination -ArgumentList $arguments -ErrorAction Stop
				#& $agentDestination $arguments
			} catch {
				if ($Interactive) { Write-Error "$(Get-Date) [Error] Uninstall Error: Could not start agent.windows.exe. [$_]" }
				"$(Get-Date) [Error] Uninstall Error: Could not start agent.windows.exe. [$_]" >> $LogPath
				return
			}
		}

		# Setup exe arguments
		#$arguments = "--url $hunturl --install"
		#if ($Silent) { $arguments += " --quiet" }
		#if ($RegKey) { $arguments += " --key $RegKey" }
		$arguments = @("--install", "--url $hunturl")
		if ($RegKey) { $arguments += "--key $RegKey" }
		if ($Silent) { $arguments += "--quiet" }

		if ($Interactive) { Write-Host "$(Get-Date) [Information] Installing Agent: Downloading agent.windows.exe from $agentURL [sha1: $sha1] and executing with commandline: $($agentDestination.Substring($agentDestination.LastIndexOf('\')+1)) $arguments" }
		"$(Get-Date) [Information] Installing Agent: Downloading agent.windows.exe from $agentURL [sha1: $sha1] and executing with commandline: $($agentDestination.Substring($agentDestination.LastIndexOf('\')+1)) $arguments" >> $LogPath
		# Execute!
		try {
			Start-Process -NoNewWindow -FilePath $agentDestination -ArgumentList $arguments -ErrorAction Stop
			if (-NOT $Silent) { Write-Host "$(Get-Date) [Success] Installation Succeeded! Agent associated to $InstanceName." }
			"$(Get-Date) [Success] Installation Succeeded! Agent associated to $InstanceName." >> $LogPath

			#& $agentDestination $arguments
		} catch {
			if ($Interactive) { Write-Error "$(Get-Date) [Error] Installation Error: Could not start agent.windows.exe. [$_]" }
			"$(Get-Date) [Error] Installation Error: Could not start agent.windows.exe. [$_]" >> $LogPath
		}

	}
Set-Alias installagent -Value Install-HuntAgent | Out-Null
Export-ModuleMember -Alias 'installagent' -Function 'Install-HuntAgent' | Out-Null
}
