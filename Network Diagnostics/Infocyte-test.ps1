<# 
    .SYNOPSIS
        Tests Domain, System, and Credential configuration for use with Infocyte Pulse

    .DESCRIPTION
        Tests Domain, System, and Credential configuration for use with Infocyte Pulse.  Will attempt several 
		tests of the credentials, permissions, remote connectivity, networking, and DNS Resolution.

    .PARAMETER Target
        (Mandantory) IP Address or FQDN of a remote system to test against

	.PARAMETER Credential
        (Mandatory) Network credentials to test (PSCredential Object)

    .PARAMETER ProxyAddress
        (Optional) Web Address of the proxy ie. http://192.168.1.2:8080
		
	.PARAMETER ProxyCredential
        (Optional) Proxy credentials (PSCredential Object)

    .EXAMPLE
        $Netcreds = Get-Credentials
        PS C:\> .\Test-InfocyteCredentials.ps1 -Target 192.168.1.5 -Credential $Netcreds
		
    .EXAMPLE
        $Netcreds = Get-Credentials
		PS C:\> $Proxycreds = Get-Credentials
        PS C:\> .\Test-InfocyteCredentials.ps1 -Target 192.168.1.5 -Credential $Netcreds -ProxyAddress "http://192.168.1.2:8080" -ProxyCredential $Proxycreds

    .NOTES
		Tests we will run:
		1.  Test DNS Resolution
		2.  Test DNS Reverse Lookup
		3.  Test Proxy
		4.  Test Internet Access
			a.  http:\\www.google.com
			b.  https:\\incyte.infocyte.com
		5.  Test Remote Connectivity (Ping)
		6.  Test Credentials (Username and Password Combo)
		7.  Test Active Directory Permissions
		8.  Gather Resultant Set of Policy (RSoP)
		9.  Test Remote File Transfer (SMB)
			a.  C:\Windows\Temp
			b.  C:\Users\<someoneelse>\Desktop
		10.  Test Remote Execution
			a. Test WMI 
			b. Test Schedtasks
			c. Test Remote Registry
			d. Test PSRemoting
#>
[CmdletBinding()]
Param(
	[Parameter(Position = 0, Mandatory = $True, HelpMessage = "The remote system to test connectivity to")]
	[ValidateNotNullOrEmpty()]
    [String]
    $Target,

	[Parameter(Position = 1, Mandatory = $True, HelpMessage = "Elevated account that will be used with Pulse")]
	[ValidateNotNullOrEmpty()]
	[System.Management.Automation.PSCredential]
	$Credential,

    [Parameter(Mandatory = $False, HelpMessage = "Address of proxy in the form of: http://<myproxy-ip>:8080")]
    [String]
    $ProxyAddress,

	[Parameter(Mandatory = $False, HelpMessage = "Proxy credentials for authenticated proxies")]
	[ValidateNotNullOrEmpty()]
	[System.Management.Automation.PSCredential]
	$ProxyCredential
)

#requires -version 2.0
$Admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”)
If (-NOT $Admin) {
	Write-Warning "NOTE: Your shell is not running as Administrator (But you shouldn't need it for this script)."
}

# $PSScriptRoot
# [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")]
# FUNCTIONS

Function Get-DNSEntry ($target) {

	try {
		Write-Verbose "Resolving $target"
        $Temp = [System.Net.Dns]::GetHostEntry($target)
	} catch {
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-Warning "[ERROR] Failed DNS Lookup against $target - No such host/IP is known - Error Item: $FailedItem, Message: $Message"
		Write-Warning "Using DNS $(nslookup $target 2> $null)"
		return
	}
	if ($target -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
		$IPAddress = $target
	} else {
		if (($temp.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' }) -is [System.Net.IPAddress]) {
			$IPAddress = ($temp.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' }).IPAddressToString
		} else {
			$IPAddress = ($temp.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0].IPAddressToString
		}
	}
	$Result = @{
		IP = $IPAddress
		IPs = $temp.AddressList.IPAddressToString
		HostName = $Temp.HostName
	}
	New-Object PSObject -Property $Result	
}

function Test-Port ($target, $port) {

    $tcpclient = New-Object Net.Sockets.TcpClient
    try
    {
        $tcpclient.Connect($target,$port)
    } catch {}

    if($tcpclient.Connected)
    {
        $tcpclient.Close()
		Write-Verbose "[SUCCESS] Port $port on $target is open"
		$True
    } 
	else {
		Write-Warning "[FAILURE] Port $port on $target is closed"       
		$False                        
    }
}

function Test-Connectivity {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $True, ValueFromPipeline=$False)]
		[ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")]
		[String]
		$IP,

		[Parameter(Position = 1, Mandatory = $True, ValueFromPipeline=$True)]
		[ValidateRange(1,65535)]
		[Int32]
		$port,

		[Parameter(Position = 2, Mandatory = $False, ValueFromPipeline=$False)]
		[ValidateRange(1,128)]
		[Int32]
		$MaxThreads = 24
	)

	BEGIN {
		$portdict = @{
			22 = "SSH (TCP 22)"
			53 = "DNS (TCP 53)"
			80 = "HTTP (TCP 80)"
			135 = "WMI/RPC (TCP 135)"
			137 = "NetBIOS (TCP 137)"
			139 = "NetBIOS (TCP 139)"
			389 = "LDAP (TCP 389)"
			443 = "HTTPS (TCP 443)"
			445 = "SMB (TCP 445)"
			1024 = "Dynamic-Legacy (TCP 1024)"
			1025 = "Dynamic-Legacy (TCP 1025)"
			1026 = "Dynamic-Legacy (TCP 1026)"
			3389 = "Remote Desktop (TCP 3389)"
			5985 = 	"PSRemoting-HTTP (TCP 5985)"
			5986 = 	"PSRemoting-HTTPS (TCP 5986)"
			49152 = "Dynamic (TCP 49152)"
			49153 = "Dynamic (TCP 49153)"
			49154 = "Dynamic (TCP 49154)"
		}

		$TestPort_Scriptblock = {
				Param($target, $port)

				$tcpclient = New-Object Net.Sockets.TcpClient
				try
				{
					$tcpclient.Connect($target,$port)
				} catch {}

				if($tcpclient.Connected)
				{
					$tcpclient.Close()
					Write-Verbose "[SUCCESS] Port $port on $target is open"
					$True
				} 
				else {
					Write-Warning "[FAILURE] Port $port on $target is closed"       
					$False                        
				}
		}
		$ports = @()
	}

	PROCESS {
		$ports += $_
	}

	END {
	
		# Create Runspace for multi-threading
		$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
		$RunspacePool.Open()
		$Jobs = @()
		
		$ports | ForEach-Object {
			$Job = [powershell]::Create().AddScript($TestPort_Scriptblock)
			$Job.AddArgument($IP) | Out-Null
			$Job.AddArgument($_) | Out-Null
			$Job.RunspacePool = $RunspacePool
			$Jobs += New-Object PSObject -Property @{
				Port = $_
				Pipe = $Job
				Result = $Job.BeginInvoke()
			}
		}

		# Track Progress of Port Scan
		$elapsedTime = [system.diagnostics.stopwatch]::StartNew()
		Do {
			Write-Progress -activity "Port Scanning" -Status "$([string]::Format("Waiting... Elapsed Time: {0:d2}:{1:d2}.{2:d3}", $elapsedTime.Elapsed.minutes, $elapsedTime.Elapsed.seconds, $elapsedTime.Elapsed.Milliseconds))"
			#Start-Sleep -Milliseconds 50
		} While ( $Jobs.Result.IsCompleted -contains $false)
		Write-Progress -activity "Port Scanning" -Completed "Port scan completed!"
		
		$Results = @()
		ForEach ($Job in $Jobs ) {
			$Result = @{
				"Port"   = $Job.Port
				"Name"   = $portdict[$Job.Port]
				"Access" = $Job.Pipe.EndInvoke($Job.Result)[0]
			}   
			$Results += New-Object PSObject -Property $Result
		}

		# Cleanup
		$elapsedTime.stop()
		$RunspacePool.Close()

		$Results
	}
}

Function Test-ADCredentials {
	Param(
		[Parameter(Position = 0, Mandatory = $True)]
		[System.Management.Automation.PSCredential]
		$Credential
	)

	Add-Type -AssemblyName System.DirectoryServices.AccountManagement -IgnoreWarnings
	$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
	try {
		$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $Credential.GetNetworkCredential().Domain) 
	} catch {
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-Warning "ERROR: Could not contact DirectoryServices on domain $($Credential.GetNetworkCredential().Domain)  - Error Item: $FailedItem, Message: $Message"
		return
	}

	New-Object PSObject -Property @{
		Username = $Credential.UserName
		isValid  = $pc.ValidateCredentials($Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
	}
}

Function Test-RemoteWMI {
	Param($IP, $credential)	
	
	$GetWmiObjectParams = @{
		Class = "win32_OperatingSystem"
		Property = "Caption"
		ComputerName = $IP
		Credential = $credential
	}

	Try {
		$OS = (Get-WmiObject @GetWmiObjectParams).Caption
	} Catch {
	
	}
	
	$GetWmiObjectParams2 = @{
		ClassName = "Win32_Process"
		Property = "Name,CommandLine,ExecutablePath"
		ComputerName = $IP
		Credential = $credential
	}
	$proc = (Get-CimInstance @GetWmiObjectParams)
	#(Get-CimInstance -ClassName Win32_Process -Property Name, CommandLine, ExecutablePath)[6] | select Name, CommandLine, ExecutablePath | fl	
}

Function New-ProxyWebClient {
	# Test HTTP Proxy Authentication (Basic, NTLM, Digest, Negotiate/Kerberos)
	Param(	
			[Parameter(Position = 0, Mandatory = $True)]
			[String]
			$ProxyAddress, 
			
			[Parameter(Position = 1, Mandatory = $False)]
			[System.Management.Automation.PSCredential]
			$Credential,

			[Parameter(Position = 2, Mandatory = $False)]
			[String]
			$AuthType = "Negotiate"
	)
	
	$BypassLocal = $True	
	$BypassList = @()
    if ($AuthType -eq "") {
        #			[ValidateSet("", "Basic", "NTLM", "Digest", "Kerberos", "Negotiate")]
        $AuthType = "Negotiate"
    }
	#$BypassList.Insert(";*.$Domain")

	try {

		$wc = new-object net.webclient
		$proxyUri = new-object system.uri($ProxyAddress)
	} catch {
		$ErrorMessage = [String]$_.Exception.Message
		$FailedItem = [String]$_.Exception.ItemName
		Write-Warning "ERROR: Could not set up proxy - Error Item: $FailedItem, Message: $Message"
	}
	if ($Credential) {
		# Configure Authenticated proxy
		Write-Verbose "Configuring Proxy ($ProxyAddress) using $AuthType authentication"
		try {
			$cachedCredentials = new-object system.net.CredentialCache
			$cachedCredentials.Add($proxyUri, $AuthType, $Credential.GetNetworkCredential())
			
			$wc.Proxy = new-object system.net.WebProxy($proxyUri, $bypassLocal)
			$wc.Proxy.Credentials = $cachedCredentials.GetCredential($proxyUri, $AuthType, $Domain)
		} catch {
			$ErrorMessage = [String]$_.Exception.Message
			$FailedItem = [String]$_.Exception.ItemName
			Write-Warning "ERROR: Could not add credentials to proxy - Error Item: $FailedItem, Message: $Message"
		}
		return $wc

	} else {
		# Use Default System Proxy Settings (Internet Explorer Settings)
		Write-Verbose "Configuring Proxy ($ProxyAddress) using default (Internet Explorer) Proxy credentials"
		try {
			$wc.Proxy = new-object system.net.WebProxy($proxyUri, $bypassLocal)
			$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
		} catch {
			$ErrorMessage = $_.Exception.Message
			$FailedItem = $_.Exception.ItemName
			Write-Warning "ERROR: Error while setting system's default proxy credentials - Error Item: $FailedItem, Message: $Message" 
		}
		$showcurrentproxy = netsh winhttp show proxy
		Write-Verbose $showcurrentproxy
		return $wc

	}
}


# MAIN
	$Creds = [System.Management.Automation.PSCredential]$Credential
	$Username = $Creds.GetNetworkCredential().UserName
	$Domain = $Creds.GetNetworkCredential().Domain
	if (($Domain -ne $null) -AND ($Domain -ne "")) {
		$FQUsername = "$Domain\$Username"
	} else {
		$FQUsername = $Username
	}
	$TestNum = 0
	$TestWebsite = 'http://infocyte.com'
	if (-NOT $PSScriptRoot) { 
		$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
	}
	$OutputFileLocation = "$PSScriptRoot\InfocyteTest.log"
	$ports = 22,53,80,135,137,139,389,443,445,1024,1025,1026,3389,5985,5986,49152,49153,49154

	# Start transcript log of this script's output
	Start-Transcript -path $OutputFileLocation
	Write-Host "Running script with the following parameters:"
	Write-Host "Target: $Target"
	Write-Host "Credential: $($Credential.Username)"
	Write-Host "ProxyAddress: $ProxyAddress"
	Write-Host "ProxyCredential: $($ProxyCredential.Username)"
	if ($ProxyAddress) { 
		if ($ProxyAddress -match "http") {
			# "http://<myproxy-ip>:8012"
		} elseif ($ProxyAddress -like "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
			$ProxyAddress = "http://$ProxyIP"
		} else {
			Write-Warning "ProxyAddress ($ProxyAddress) may be in the wrong format.  Should be http://myproxyaddress.com or http://192.168.1.80:8080"
		}
	}

    Write-Host -ForegroundColor Cyan "`n==========================================================================="
    Write-Host -ForegroundColor Cyan "==========================================================================="
    Write-Host -ForegroundColor Cyan "==========================================================================="
    Write-Host -ForegroundColor Gray "This script will run several tests to test for remote connectivity, DNS, Internet Access, and permissions necessary to run Infocyte Pulse" 
    Write-Host -ForegroundColor Gray "Any failed test or warning may be an issue that needs to be addressed before you use Infocyte Pulse"	
	Write-Host -ForegroundColor Gray "Log File Location: $OutputFileLocation"
    Start-Sleep 3
    Write-Host -ForegroundColor Cyan "`n=== BEGINING TESTS ==="
	
    # Flush Local DNS Cache for testing
	Write-Host "`nFlushing DNS"
	ipconfig /flushdns | out-null

	#region Internet Tests
	# Test DNS Resolution and connectivity to the internet
	$Testnum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing DNS resolution and connectivity to the internet (Optional)"
	$DNSEntry = Get-DNSEntry www.google.com
	if ($DNSEntry) { 
		Write-Host "SUCCESS: $($DNSEntry.Hostname) => $($DNSEntry.IP)"
	} else {
		Write-Warning "FAIL: DNS Resolution of www.google.com failed - Your internet may be down"
	}

	try {
		$ICMP = Test-Connection -BufferSize 16 -Count 1 -ComputerName www.google.com -ea STOP
		Write-Host "SUCCESS: Ping (ICMP) to www.google.com ($($ICMP.IPV4Address)) in $($ICMP.ResponseTime) m/s"
	} catch {
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-Warning "FAIL: Ping (ICMP) to www.google.com - Error Item: $FailedItem, Message: $Message"
	}

	
	# Test DNS Resolution and connectivity to Incyte
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing DNS resolution and connectivity to Infocyte (Required)"
	$DNSEntry = Get-DNSEntry incyte.infocyte.com
	if ($DNSEntry) { 
		Write-Host "SUCCESS: $($DNSEntry.Hostname) => $($DNSEntry.IP)"
	} else {
		Write-Warning "FAIL: DNS Resolution of incyte.infocyte.com failed - Your internet may be down"
	}

	try {
		$ICMP = Test-Connection -BufferSize 16 -Count 1 -ComputerName incyte.infocyte.com -ea STOP
		Write-Host "SUCCESS: Ping (ICMP) to incyte.infocyte.com ($($ICMP.IPV4Address)) in $($ICMP.ResponseTime) m/s"
	} catch {
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-Warning "FAIL: Ping (ICMP) to incyte.infocyte.com (($($ICMP.IPV4Address)) - Error Item: $FailedItem, Message: $Message"
	}
	#endregion Internet Test

	#region Proxy Tests
	
	# $req = [system.Net.WebRequest]::Create($TestWebsite)
	# $res = $results.GetResponse()
	# $int = [int]$res.StatusCode
	# Write-Host $int
	$TestNum += 1
	Write-Host  -ForegroundColor Cyan "`n[TEST $TestNum] Testing web connectivity with direct access (No Proxy)"
	
	#Configure Proxy if required
	$showcurrentproxy = netsh winhttp show proxy
	Write-Host "Current System Proxy Settings:`n"
	Write-Host "-------------------`n" $showcurrentproxy
	
	try {
		$wc = new-object net.webclient
		$results = $wc.DownloadString($TestWebsite)
		if ($results -match "Malware Hunting") {
			Write-Host "SUCCESS: Web (http) connectivity with direct access (No Proxy) succeeded to $TestWebsite"
		} else {
			Write-Warning "FAIL: Web (http) connectivity with direct access (No Proxy) failed to $TestWebsite"
			$results
		}
	} catch {
			Write-Warning "FAIL: Web (http) connectivity with direct access (No Proxy) failed to $TestWebsite"
			$ErrorMessage = $_.Exception.Message
			$FailedItem = $_.Exception.ItemName
			Write-Warning "Error Item: $FailedItem, Message: $Message"
	}

    if ($ProxyAddress) {

		# Testing web client with unauthenticated Proxy
		Write-Host "Testing web client with unauthenticated proxy ($ProxyAddress)"
		try {
			$wc = New-ProxyWebClient $ProxyAddress
			$results = $wc.DownloadString($TestWebsite)
			if ($results -match "Malware Hunting") {
				Write-Host "SUCCESS: Web (http) connectivity with unauthenticated Proxy succeeded to $TestWebsite"
			} else {
				Write-Warning "FAIL: Web (http) connectivity with unauthenticated Proxy failed to $TestWebsite"
				$results
			}
		} catch {
			Write-Warning "FAIL: Web (http) connectivity with unauthenticated Proxy failed to $TestWebsite"
			$ErrorMessage = $_.Exception.Message
			$FailedItem = $_.Exception.ItemName
			Write-Warning "Error Item: $FailedItem, Message: $Message"
		}


        if ($ProxyCredential) {

			# Testing web client with authenticated Proxy
            $AuthType = "Negotiate"
   			Write-Host "Testing proxied web client with $AuthType Proxy Auth"
            $wc = New-ProxyWebClient $ProxyAddress $ProxyCredential $AuthType
			try {
				$results = $wc.DownloadString($TestWebsite)   
				if ($results -match "Malware Hunting") {
					Write-Host "SUCCESS: Web (http) connectivity through proxy with $AuthType authentication succeeded to $TestWebsite"
				} else {
					Write-Warning "FAIL: Web (http) connectivity through proxy with $AuthType authentication failed to $TestWebsite"
					#$results
				}
			} catch {
				Write-Warning "FAIL: Web (http) connectivitythrough proxy with $AuthType authentication failed to $TestWebsite"
				$ErrorMessage = $_.Exception.Message
				$FailedItem = $_.Exception.ItemName
				Write-Warning "Error Item: $FailedItem, Message: $Message"
			}
		}
    }
	#endregion

	#region Remote Target Connectivity Tests
	# Test DNS Resolution and connectivity to Target
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing DNS resolution and connectivity to $target"
	$DNSEntry = Get-DNSEntry $target
	if ($DNSEntry) { 
		$IP = $DNSEntry.IP
		$Hostname = $DNSEntry.Hostname	
        Write-Host "SUCCESS: DNS Resoloved $target to $Hostname ($IP)"
        if ($Hostname -notlike "*.$Domain") {
            Write-Warning "This system seems to have resolved to a domain that is different from the provided credentials for $Domain."
            Write-Warning "You may need to provide the correct credentials for the resolved domain or check your DNS provider"
            Write-Warning "If this result is unexpected, ensure this system is pointed to the correct DNS server."
            Write-Warning "Currently using DNS $(nslookup $target 2> $null)"
        }
	} else {
		Write-Warning "FAIL: DNS Resolution to target failed"
		Write-Warning "No target to test against.  Exiting Script"
		Stop-Transcript
		break
	}

	# Test Remote Connectivity (Ping)
	Write-Host "`nTesting Connectivity to $IP w/ ICMP"
	try {
		$ICMP = Test-Connection -BufferSize 16 -Count 1 -ComputerName $IP -ea STOP
		Write-Host "SUCCESS: Ping (ICMP) to $Hostname ($($ICMP.IPV4Address)) in $($ICMP.ResponseTime) m/s"
	} catch {
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-Warning "FAIL: Ping (ICMP) to $Hostname (($($ICMP.IPV4Address)) - Error Item: $FailedItem, Message: $Message" 
	}

	# Test Remote Connectivity (Ports)
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Performing TCP port scan of the following ports:"
	Write-Host $ports
	$PortResults = $ports | Test-Connectivity -IP $IP
	try { Start-Transcript -path $OutputFileLocation -Append | Out-Null } catch {}
    Write-Host "==========================================================================="
    Write-Host -NoNewline ("{0,-8}`t{1,-35}`t{2}`n" -f "Port","Name","Access")
    $PortResults | ForEach-Object {
        if ($_.Access) {
            Write-Host -ForegroundColor Green -NoNewline ("{0,-8}`t{1,-35}`t{2}`n" -f $_.Port,$_.Name,$_.Access)
        } else {
            Write-Host -ForegroundColor Red -NoNewline ("{0,-8}`t{1,-35}`t{2}`n" -f $_.Port,$_.Name,$_.Access) 
        }
    }   
	Write-Host ""
    $PortResults | ForEach-Object {
		$result = $_
		if (-NOT $result.Access) {
			Switch ($_.Port){
				22  { 
						Write-Warning "FAIL: No Access to $($result.Name) on $IP - Will affect SSH Execution and Deployment against a Unix-based Hosts" 
					}
				
				135 { 
						Write-Warning "FAIL: No Access to $($result.Name) on $IP - Will affect WMI Execution and Deployment against a Windows-based Hosts" 
					}
				139 { 
						If (-NOT ($PortResults | Where-Object { $_.Port -eq 445 }).Access) {
							Write-Warning "FAIL: No Access to $($result.Name) on $IP - May affect RPC Execution and Deployment against a Windows-based Hosts" 
						}
					}
				445 { 	
						If (-NOT ($PortResults | Where-Object { $_.Port -eq 139 }).Access) {
							Write-Warning "FAIL: No Access to $($result.Name) on $IP - May affect RPC Execution and Deployment against a Windows-based Hosts" 
						}
					}

				5985 { 
						Write-Warning "FAIL: No Access to $($result.Name) on $IP - May affect PSRemoting Execution and Deployment against a Windows-based Hosts" 
					 }
				default { }
			}
		}
	}
	#endregion Remote Target Connectivity Test
	
	#region Permissions Tests
	# Test Credentials against domain
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Validating Credentials are valid..."
	$TestCreds = Test-ADCredentials $Creds
	if ($TestCreds.isValid) {
		Write-Host "SUCCESS: Credentials for $Username are valid on $Domain"
	} else {
		Write-Warning "FAIL: Credentials for $Username are either not valid or you cannot connect to DirectoryServices on $Domain"		
	}

	# Test Permissions
	$TestNum += 1
    Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing Permissions of account: $Domain\$Username"
    Write-Host "Getting Resultant Set of Policy (RSoP) for localhost - output to file .\InfocyteTest_RSoP_localhost.html"
	$res = GPResult.exe /USER $Username /H InfocyteTest_RSoP_localhost.html /F
	if ($res -match "does not have RSOP data") {
		Write-Warning "$res"
		Write-Warning "Fallback: Attempting to gather RSoP for current user"
		GPResult.exe /H InfocyteTest_RSoP_localhost.html /F
	}
	Write-Host "Getting Resultant Set of Policy (RSoP) for $Hostname - output to file .\InfocyteTest_RSoP_$Hostname.txt"
	$res = Gpresult /S $Hostname /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /USER $Username /v > InfocyteTest_RSoP_$Hostname.txt
	if ($res -match "does not have RSOP data") {
		Write-Warning "$res"
		Write-Warning "Fallback: Attempting to gather RSoP for current user"
		Gpresult /S $Hostname /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /v > InfocyteTest_RSoP_$Hostname.txt
	}
	#endregion Permissions Test

	#region Remote Execution Protocol Tests
	# Test WMI Execution
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing WMI Execution..."
	if (($PortResults | Where-Object { $_.Port -eq 135 }).Access) {
		$GetWmiObjectParams = @{
			Class = "win32_OperatingSystem"
			Property = "Caption"
			ComputerName = $Hostname
			Credential = $Creds
			Impersonation = 'Impersonate'
			#Authority = "ntlmdomain:$Domain"
		}

		Try {
			$OS = (Get-WmiObject @GetWmiObjectParams -ea Stop).Caption
			Write-Host "SUCCESS: WMI w/ NTLM succeeded.  $IP is a $OS System"
		} Catch {
			Write-Warning "FAIL: WMI with NTLM failed to $IP"
		}

		# Test Kerberos
		$GetWmiObjectParams = @{
			Class = "win32_OperatingSystem"
			Property = "Caption"
			ComputerName = $Hostname
			Credential = $Creds
			Impersonation = 'Impersonate'
			Authority = "kerberos:"+$Domain+"\"+$Hostname.Split('.')[0]+'$'
		}
        #Write-Host "Testing WMI w/ explicit Kerberos authentication (Recommended)"
		Try {
			$OS = (Get-WmiObject @GetWmiObjectParams -ea Stop).Caption
			Write-Host "SUCCESS: WMI w/ Kerberos succeeded.  $IP is a $OS System"
		} Catch {
			Write-Warning "FAIL: WMI with Kerberos failed to $Domain\$Hostname"
		}

	} else {
		Write-Warning "No connectivity to RPC port - skipping WMI test"
	}

	# Test SMB Connectivity
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing Server Message Block (SMB) connectivity..."
	if (($PortResults | Where-Object { $_.Port -eq 139}).Access -OR ($PortResults | Where-Object { $_.Port -eq 445}).Access) {

        try {
            $mountdrive = New-PSDrive -Name test -PSProvider FileSystem -Root "\\$IP\C$" -Credential $Creds -ea STOP
            Write-Host "SUCCESS: Connected to $IP via SMB"
            Remove-PSDrive test
        } catch {
			$ErrorMessage = $_.Exception.Message
			$FailedItem = $_.Exception.ItemName
            Write-Warning "FAIL: Could not connect to $IP via SMB - C$ administrative share may not be accessible - Error Item: $FailedItem, Message: $Message"
        }
        
	} else {
		Write-Warning "No connectivity to NetBIOS and SMB ports - skipping SMB Transfer test"
	}

	# Test Remote Schtasks
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing Remote Schtasks Execution..."
	if (($PortResults | Where-Object { $_.Port -eq 139}).Access -OR ($PortResults | Where-Object { $_.Port -eq 445}).Access) {

        $a = SCHTASKS /Create /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test /TR 'c:\windows\system32\cmd.exe /c Net Time' /SC ONCE /ST 23:59 /RU SYSTEM /F
        if ($a -match "SUCCESS") {
            Write-Host "SUCCESS: Remote task (test) created on $IP"
            Start-Sleep 1
            
            # Run the task
            $b = SCHTASKS /Run /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test
            if ($b -match "SUCCESS") {
                Write-Host "SUCCESS: Remote task (test) was initiated on $IP"
            } else {
                Write-Warning "FAIL: Remote task (test) failed to initiate"
                Write-Warning $b
            }
        
        } else {
            Write-Warning "FAIL: Remote task (test) failed on $IP" 
            Write-Warning $a
        }


        # Query Task status
        $a = SCHTASKS /query /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test
        if (($a -match "Running") -OR ($a -match "Ready")) {
            Write-Host "SUCCESS: Remote task (test) ran successfully on $IP"
        } else { 
            Write-Warning "FAIL: Remote task (test) ran into some issues on $IP"
            Write-Warning $a
        }

        #Delete the task (Cleanup)
        Start-Sleep 1
        SCHTASKS /delete /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test /F | Out-Null

	} else {
		Write-Warning "No connectivity to NetBIOS and SMB ports - skipping Remote Schtasks test"
	}


	# Test PSRemoting
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing Powershell Remoting Execution..."
	if (($PortResults | Where-Object { $_.Port -eq 5985}).Access -or ($PortResults | Where-Object { $_.Port -eq 5986}).Access) {

        try { 
            $errorActionPreference = "Stop" 
            $result = Invoke-Command -ComputerName $Hostname -Credential $Creds -ea Stop { 1 }
            Write-Host "SUCCESS: Powershell Remoting Session established with $IP" 
        } 
        catch {
			$ErrorMessage = $_.Exception.Message
			$FailedItem = $_.Exception.ItemName 
            Write-Warning "FAIL: PSRemoting to $IP failed - Error Item: $FailedItem"
			Write-Warning "Error Item: $FailedItem, Message: $Message"
        } 
    
	} else {
		Write-Warning "No connectivity to Powershell Remoting ports - skipping Powershell Remoting test"
	}
	#endregion Remote Execution Protocol Tests

	Write-Host -ForegroundColor Cyan "All Tests Complete!"
	Write-Host "Results are found here:"
	Write-Host "$PSScriptRoot\InfocyteTest_RSoP_$Hostname.txt"
	Write-Host "$PSScriptRoot\InfocyteTest_RSoP_localhost.html" 
	Write-Host "$PSScriptRoot\InfocyteTest.log"

    Stop-Transcript