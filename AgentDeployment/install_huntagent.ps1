New-Module -name install_dattoedr -scriptblock {
	# Datto EDR scripted installation option. If unfamiliar with this script, contact your IT or Security team.
	# www.datto.com

	# WARNING: Single line scripted installers like this use similiar techniques to modern staged malware.
	# As a result, this script will likely trigger behavioral detection products and may need to be whitelisted by your current security software.

	# To execute this script as a one liner on a windows host with powershell 3.0+ (.NET 4.5+), run this command replacing instancename and key with your hunt instance <mandatory> and registration key [optional]. NOTE: Instancename is the cname from the URL, not the FULL url https://instancename.infocyte.com). This script will append the url for you during install.
	# [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; Install-EDR -InstanceName <instancename> -RegKey [regkey] -Region [ap|eu]

	# Example:
	# [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072); (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; Install-EDR -InstanceName allsafemsp -RegKey asdf1234 -Region ap

	# Logs are stored here: "C:\Windows\Temp\agentinstallscript.log"

	Function Install-EDR() {
		<#
		.SYNOPSIS
		Installs the Infocyte agent

		.DESCRIPTION
		Installs the Infocyte agent

		.ALIASES
		installagent

		.LINK
		https://github.com/Infocyte/PowershellTools/master/AgentDeployment

		#>
		param(
			[Parameter(Mandatory=$true, Position = 0, HelpMessage="The API URL or cname from the URL: https://<instancename>.infocyte.com or https://<instancename>.<region>.infocyte.com)")]
			[Alias("InstanceName")]
			[String]$URL,

			[Parameter(Position = 1, HelpMessage="This will automatically approve the agent registration and add it to its' default Target Group.")]
			[String]$RegKey,

			[Parameter(HelpMessage="Will register a name for the system. Otherwise will use the hostname.")]
			[String]$FriendlyName,

			[Parameter(HelpMessage='Authenticated: "user:password@192.168.1.1:8080" or Unauthenticated: "192.168.1.1:8080"')]
			[String]$Proxy, # "user:password@192.168.1.1:8080" or "192.168.1.1:8080"

			[Parameter(HelpMessage="The temporary location where agent setup will be downloaded to and ran from.")]
			[String]$DownloadPath = "$($env:TEMP)\agent.windows.exe",

			[Parameter(HelpMessage="Silent install is default. Use this switch to display output.")]
			[Switch]$Interactive,

			[Parameter(HelpMessage="Will force a reinstall if agent already installed.")]
			[Switch]$Force
		)

		$LogPath = "$env:Temp\agentinstallscript.log"
		if ([System.IntPtr]::Size -eq 4) {
			$agentURL = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows32.exe"
		} else {
			$agentURL = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows64.exe"
		}
		
		
		If (-NOT $URL) {
			Write-Warning "[Error] Please provide Datto EDR URL or instance name (i.e. mycompany in mycompany.infocyte.com) or a full URL to your EDR instance."
			"$(Get-Date) [Error] Installation Error: No InstanceName or URL provided in arguments!" >> $LogPath
			return
		}

		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			Write-Warning "[Error] You do not have Administrator rights to run this script!`nPlease re-run as an Administrator!"
			"$(Get-Date) [Error] Installation Error: Script not run as administrator!" >> $LogPath
			return
		}

		if ($URL -match "https://.*?\.infocyte\.com/?") {
				$hunturl = $URL.TrimEnd('/')
		} elseif ($URL -match "\.infocyte\.com/?") {
			$hunturl = "https://$($URL.TrimEnd('/'))"
		} elseif ($URL -notmatch "([:\\/-]|.com)") {
			$hunturl = "https://$URL.infocyte.com"
		} else {
			if ($Interactive) { Write-Error "Could not parse instance name or url correctly: $hunturl" }
			"$(Get-Date) [Error] Could not parse instance name or url correctly: $URL" >> $LogPath
		}

		if ([Uri]::IsWellFormedUriString($hunturl, [URIKind]::RelativeOrAbsolute)) {
			if ($Interactive) { Write-Host "Installing with URL: $hunturl" }
			"$(Get-Date) [Information] Installing with URL: $hunturl" >> $LogPath
		} else {
			if ($Interactive) { Write-error "URL is invalid: $hunturl" }
			"$(Get-Date) [Error] URL is invalid: $hunturl" >> $LogPath
		}
		

		If (Get-Service -name huntAgent -ErrorAction SilentlyContinue) {
			if (-NOT $Force) {
				if ($Interactive) { Write-Error "Datto EDR already installed" }
				"$(Get-Date) [Information] Datto EDR is already installed and HUNTAgent service running. Skipping." >> $LogPath
				return
			}
		}

		# Downloading Agent
		[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
		$wc = New-Object Net.WebClient
		$wc.Encoding = [System.Text.Encoding]::UTF8
		
		$proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
		if ($Proxy) {
			$ProxyObj = new-object System.Net.WebProxy
			if ($proxy.split("@").count -gt 1) {
				$proxyaddr = $proxy.split("@")[1]
				$user = $proxy.split("@")[0].split(':')[0]
				$pass = $proxy.split("@")[0].split(':')[1]
				$Credentials = New-Object Net.NetworkCredential($user,$pass,"")
				$ProxyObj.Address = $proxyaddr
				$ProxyObj.Credentials = $Credentials
			} else {
				$ProxyObj.Address = $proxy
			}
			$wc.Proxy = $ProxyObj
		} elseif ($proxyAddr) {
			$ProxyObj = new-object System.Net.WebProxy
			$ProxyObj.Address = $proxyAddr
			$ProxyObj.useDefaultCredentials = $true
			$wc.Proxy = $ProxyObj
		}
		else {
			$wc.UseDefaultCredentials = $true
		}
		
		# $wc.CachePolicy = New-Object System.Net.Cache.HttpRequestCachePolicy([System.Net.Cache.HttpRequestCacheLevel]::NoCacheNoStore) # For Testing:
		try {
			$wc.DownloadFile($agentURL, $DownloadPath)
		} catch {
			if ($Interactive) { Write-Warning "Could not download Datto EDR agent from $agentURL" }
			"$(Get-Date) [Error] Installation Error: Install started but could not download agent from $agentURL." >> $LogPath
		}

		# Verify Sha1 of file
		try {
			$SHA1CryptoProvider = new-object -TypeName system.security.cryptography.SHA1CryptoServiceProvider
			$inputBytes = [System.IO.File]::ReadAllBytes($DownloadPath);
			$Hash = [System.BitConverter]::ToString($SHA1CryptoProvider.ComputeHash($inputBytes))
			$sha1 = $Hash.Replace('-','').ToUpper()
		} catch {
			if ($Interactive) { Write-Warning "Hash Error. $_" }
			$sha1 = "Hashing Error"
			"$(Get-Date) [Warning] Installation Warning: Could not hash agent.survey.exe." >> $LogPath
		}

		# Setup exe arguments
		$arguments = @("--url $hunturl")
		$arguments += "--no-gui"
		$arguments += "--no-verify"
		if ($RegKey) { $arguments += "--key $RegKey" }
		if ($FriendlyName) { $arguments += "--friendly $FriendlyName" }
		if ($Proxy) { $arguments += "--proxy $Proxy" }
		if (-NOT $Interactive) { $arguments += "--quiet" }

		$version = & "$DownloadPath" --version
		if ($version -notmatch "RTS Agent") {
			if ($Interactive) { 
				Write-Warning "$(Get-Date) [Error] $DownloadPath (version: $version, sha1: $sha1) is not valid or appears to be corrupt." 
				Write-Warning "Output: `n$version"
			}
			"$(Get-Date) [Error] $DownloadPath (version: $version, sha1: $sha1) is not valid or appears to be corrupt." >> $LogPath
			"$(Get-Date) [Error] Output: `n$version" >> $LogPath
		}

		if ($Interactive) { Write-Host "$(Get-Date) [Information] Downloaded agent.windows.exe (version: $version, sha1: $sha1) from $agentURL" }
		if ($Interactive) { Write-Host "$(Get-Date) [Information] Installing Agent: $($DownloadPath.Substring($DownloadPath.LastIndexOf('\')+1)) $arguments" }
		"$(Get-Date) [Information] Installing Agent: Downloaded agent.windows.exe from $agentURL [sha1: $sha1] and executing with commandline: $($DownloadPath.Substring($DownloadPath.LastIndexOf('\')+1)) $arguments" >> $LogPath
		# Execute!
		try {
			Start-Process -NoNewWindow -FilePath $DownloadPath -ArgumentList $arguments -Wait -ErrorAction Stop
			if ($Interactive) { Write-Host "$(Get-Date) [Success] Installation Succeeded! Agent associated to $URL." }
			"$(Get-Date) [Success] Installation Succeeded! Agent associated to $URL." >> $LogPath

			#& $DownloadPath $arguments
		} catch {
			if ($Interactive) { Write-Error "$(Get-Date) [Error] Installation Error: Could not start agent.windows.exe. [$_]" }
			"$(Get-Date) [Error] Installation Error: Could not start agent.windows.exe. [$_]" >> $LogPath
		}

	}

	Function Uninstall-EDR() {
		<#
		.SYNOPSIS
		Uninstalls the Datto EDR agent

		.DESCRIPTION
		Uninstalls the Datto EDR agent

		.Aliases
		uninstallagent

		.LINK
		https://github.com/Infocyte/PowershellTools/master/AgentDeployment

		#>
		param(
			[Parameter(HelpMessage="Use this switch silence output.")]
			[Switch]$Silent
		)
		$LogPath = "$env:SystemDrive\windows\Temp\agentinstallscript.log"

		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			Write-Warning "[Error] You do not have Administrator rights to run this script!`nPlease re-run as an Administrator!"
			"$(Get-Date) [Error] Installation Error: Script not run as administrator!" >> $LogPath
			return
		}

		$service = Get-WmiObject -class win32_service -Filter "name='HUNTAgent'" -ea SilentlyContinue | Select-Object PathName -ExpandProperty PathName

		If ($Service) {
			if ($service -match '^"(.*?)" --service') {
				$AgentPath = $matches[1]
			} else {
				$AgentPath = 'C:\Program Files\Infocyte\Agent\agent.exe'
			}
			
			if (-NOT $Silent) { Write-Host "Uninstalling Datto EDR Agent." }
			"$(Get-Date) [Information] Uninstalling Datto EDR Agent." >> $LogPath

			# Uninstall
			$arguments = @("--uninstall")
			$arguments += "--no-gui"
			if ($Silent) { $arguments += "--quiet" }

			try {
				Start-Process -NoNewWindow -FilePath $AgentPath -ArgumentList $arguments -Wait -ErrorAction Stop
				#& $DownloadPath $arguments
			} catch {
				if (-NOT $Silent) { Write-Error "$(Get-Date) [Error] Uninstall Error: Could not execute agent.exe --uninstall. [$_]" }
				"$(Get-Date) [Error] Uninstall Error: Could not execute agent.windows.exe --uninstall. [$_]" >> $LogPath
			}

		} else {
			if (-NOT $Silent) { Write-Warning "Agent was not installed." }
			"$(Get-Date) [Information] Attempted to uninstall Agent but was not installed. Skipping." >> $LogPathvvv
		}
	}

	Export-ModuleMember -Alias 'installagent' -Function 'Install-EDR'
	Export-ModuleMember -Alias 'uninstallagent' -Function 'Uninstall-EDR'
} | Out-Null
Set-Alias installagent -Value Install-EDR
Set-Alias uninstallagent -Value Uninstall-EDR