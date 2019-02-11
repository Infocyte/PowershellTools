New-Module -name install_huntagent -scriptblock {

	Function Install-HuntAgent() {
		param(
			[Parameter(Position = 0, Mandatory = $True)]
			[String]$InstanceName,
			
			[Parameter(Position = 1, Mandatory = $False)]
			[String]$RegKey
		)

		If (-NOT $InstanceName) {
			Write-Error "Please provide Hunt instance name"
			return
		}
			
		If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!" 
			return
		}
		
		$InstallPath = 'C:\Program Files\Infocyte\Agent\agent.windows.exe'
		If (Get-Service -name huntAgent -ErrorAction SilentlyContinue) {
			Write-Error "huntAgent service already installed"
			return
		}

		# Installing Agent
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		$agentURL = "https://s3.us-east-2.amazonaws.com/infocyte-support/executables/agent.windows.exe"
		$agentDestination = "$($env:TEMP)\agent.windows.exe"
		$url = "$InstanceName.infocyte.com"
		(new-object Net.WebClient).DownloadFile($agentURL, $agentDestination)
		if ($RegKey) {
			& $agentDestination --url $url --key $APIKey --install --quiet
		} else {
			& $agentDestination --url $url --install --quiet
		}
	}
Set-Alias installagent -Value Install-HuntAgent
Export-ModuleMember -Alias 'installagent' -Function 'Install-HuntAgent'
}