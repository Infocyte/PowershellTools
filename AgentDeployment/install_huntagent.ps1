New-Module -name install_huntagent -scriptblock {
	# Infocyte HUNT scripted installation option. If unfamiliar with this script, contact your IT or Security team.
	# www.infocyte.com
	Function Install-HuntAgent() {
		param(
			[Parameter(Position = 0, Mandatory = $True)]
			[String]$InstanceName,

			[Parameter(Position = 1, Mandatory = $False)]
			[String]$RegKey,

			[Parameter(Mandatory = $False)]
			[Switch]$Interactive
		)

		# Make script silent unless run interactive
		if (-NOT $Interactive) { $ErrorActionPreference = "silentlycontinue" }

		If (-NOT $InstanceName) {
			if ($Interactive) { Write-Error "Please provide Infocyte HUNT instance name (i.e. mycompany in mycompany.infocyte.com)" }
			return
		}

		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			if ($Interactive) { Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" }
			return
		}

		$InstallPath = 'C:\Program Files\Infocyte\Agent\agent.windows.exe'
		If (Get-Service -name huntAgent -ErrorAction SilentlyContinue) {
			if ($Interactive) { Write-Error "huntAgent service already installed" }
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
		$wc.DownloadFile($agentURL, $agentDestination) > $null

		# Setup exe arguments
		$arguments = "--url $url --install"
		if (-NOT $interactive) { $arguments += " --quiet" }
		if ($RegKey) { $arguments += " --key $APIKey" }

		# Execute!
		if ($interactive) {

		} else {

		}
		& $agentDestination $arguments
	}
Set-Alias installagent -Value Install-HuntAgent | Out-Null
Export-ModuleMember -Alias 'installagent' -Function 'Install-HuntAgent' | Out-Null
}

client.CachePolicy = New System.Net.Cache.RequestCachePolicy(System.Net.Cache.RequestCacheLevel.NoCacheNoStore)
# [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Infocyte/PowershellTools/master/AgentDeployment/install_huntagent.ps1") | iex; installagent alpo1
