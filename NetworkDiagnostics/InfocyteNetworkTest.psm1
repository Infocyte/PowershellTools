Write-Host "Importing Infocyte Network Test Module"
$PS = $PSVersionTable.PSVersion.tostring()
if ($PSVersionTable.PSVersion.Major -lt 3) {
  Write-Warning "Powershell Version not supported. Install version 3.x or higher"
  return
} else {
    Write-Host "Checking PSVersion [Minimum Supported: 3.0]: PASSED [$PS]!`n"
}

# FUNCTIONS

Function Get-DNSEntry ([String]$target) {

	try {
		Write-Verbose "Resolving $target"
		$Temp = [System.Net.Dns]::GetHostEntry($target)
	} catch {
		$Message = $_.Exception.Message
		$ErrorType = $_.Exception.GetType().FullName
		Write-Warning "[ERROR] Failed DNS Lookup against $target - No such host/IP is known - Message: $Message"
		Write-Warning "Using DNS $(nslookup $target)"
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

Function New-TCPListener {
	Param (
		[Parameter(Mandatory=$true, Position=0)]
		[ValidateNotNullOrEmpty()]
		[int] $Port
	)
	Try {
		# Set up endpoint and start listening

		$endpoint = new-object System.Net.IPEndPoint([ipaddress]::any,$port)
		Write-Host "TCP Listener being set up on $($endpoint.Address):$($port)"
		$listener = new-object System.Net.Sockets.TcpListener $EndPoint
		$listener.start()
		return $listener
	} Catch {
		Write-Error "$($Error[0])"
	}
}

Function Receive-TCPMessage {
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Net.Sockets.TcpListener]$Listener,

		[Parameter(Mandatory=$false)]
		[int]$timeout=15000
	)
	Try {
		# Wait for an incoming connection
		$timer = [system.diagnostics.stopwatch]::StartNew()
		while (-NOT $listener.Pending()) {
			if ($timer.Elapsed.TotalMilliseconds -gt $timeout) {
				# Close TCP connection and stop listening if hits timeout
				$listener.stop()
				# Timeout
				Write-Warning "No response from target before timeout!"
				return
			}
			Start-Sleep 1
		}

		$data = $listener.AcceptTcpClient()
		Write-Host "Connection Established!"
		if ($data -AND -NOT $data.Available) {
			return "Success!"
		}

		# Read data from stream and write it to host
		$stream = $data.GetStream()
		if (-NOT $stream.DataAvailable) {
			$stream.close()
			return "Success!"
		}
		$bytes = New-Object System.Byte[] 1024
		while (($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
			$EncodedText = New-Object System.Text.ASCIIEncoding
			$data = $EncodedText.GetString($bytes,0, $i)
			if ($data) {
				Write-Host "Got some data:"
				Write-Output $data
			}
		}
		$stream.close()
	} Catch {
		Write-Warning "ERROR: Listener failed with: $($Error[0])"
	} finally {
		# Close TCP connection and stop listening
		$listener.stop()
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
			3389 = "Remote Desktop (TCP 3389)"
			5985 = 	"PSRemoting-HTTP (TCP 5985)"
			5986 = 	"PSRemoting-HTTPS (TCP 5986)"
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
                "Name"   = $null
                "Access" = $Job.Pipe.EndInvoke($Job.Result)[0]
            }
            if ($portdict.Keys -contains $Job.Port) {
                $Result["Name"] = $portdict[$Job.Port]
            }
            elseif ($Job.Port -ge 49152 -AND $Job.Port -le 65535) {
                $Result["Name"] = "Dynamic Port (TCP 49152-65535)"
            }
            elseif ($Job.Port -ge 1024 -AND $Job.Port -le 5000){
                $Result["Name"] = "Legacy Dynamic Port (TCP 1024-5000)"
            }
            else {
                $Result["Name"] = "Unknown Port"
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

    $r = New-Object PSObject -Property @{
		Username = $Credential.UserName
        isValid = $False
        Error = $null
    }
	Add-Type -AssemblyName System.DirectoryServices.AccountManagement -IgnoreWarnings
	$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
	try {
		$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $Credential.GetNetworkCredential().Domain)
        $r.isValid = $pc.ValidateCredentials($Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
	} catch {
        $r.Error = "ERROR: Could not contact DirectoryServices on domain $($Credential.GetNetworkCredential().Domain)  - Message $($_.Exception.GetType().FullName): $($_.Exception.Message)"
	}
    return $r
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

Function New-Proxy {
	# Test HTTP Proxy Authentication (Basic, NTLM, Digest, Negotiate/Kerberos)
	Param(
		[Parameter(Position = 0, Mandatory = $True)]
        [ValidatePattern("http*")]
		[String]
		$ProxyAddress,

		[Parameter(Position = 1, Mandatory = $False)]
		[System.Management.Automation.PSCredential]
		$Credential,

		[Parameter(Position = 2, Mandatory = $False)]
        [ValidateSet("Basic", "NTLM", "Digest", "Kerberos", "Negotiate")]
		[String]
		$AuthType = "Negotiate"
	)

	$BypassLocal = $True
	$BypassList = @()
	#$BypassList.Insert(";*.$Domain")
    try {
        $proxyUri = new-object system.uri($ProxyAddress)
        $Proxy = new-object system.net.WebProxy($proxyUri, $bypassLocal)
    } catch {
        Write-Warning "$($_.Exception.Message)"
        return
    }
	if ($Credential) {
		# Configure Authenticated proxy
		Write-Verbose "Configuring Proxy ($ProxyAddress) using $AuthType authentication with credential: $($Credential.Username)"
		try {
			$Credentials = new-object system.net.CredentialCache
			$Credentials.Add($proxyUri, $AuthType, $Credential.GetNetworkCredential())
			$Proxy.Credentials = $cachedCredentials.GetCredential($proxyUri, $AuthType, $Domain)
		} catch {
			$Message = [String]$_.Exception.Message
			Write-Warning "ERROR: Could not add credentials to proxy - Message: $Message"
            return
		}
	} else {
		# Use Default System Proxy Settings (Internet Explorer Settings)
		Write-Verbose "Configuring Proxy ($ProxyAddress) using default (Internet Explorer) Proxy credentials"
		try {
			$Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
		} catch {
			$Message = $_.Exception.Message
			$ErrorType = $_.Exception.GetType().FullName
			Write-Warning "ERROR: Error while setting system's default proxy credentials - Message: $Message"
            return
		}
	}
    return $Proxy
}

function Test-WebPage ($URL = "https://incyte.infocyte.com", [System.Net.WebProxy]$Proxy, [Switch]$NoProxy) {
    $HTTP_Request = [System.Net.WebRequest]::Create($URL)
    $HTTP_Request.KeepAlive = $false
    $HTTP_Request.CachePolicy = new-Object System.Net.Cache.RequestCachePolicy("BypassCache")
    if ($NoProxy) {
        $HTTP_Request.UseDefaultCredentials = $False
    }
    elseif ($Proxy) {
        Write-Verbose "Adding Proxy"
        $HTTP_Request.Proxy = $Proxy
    } else {
        Write-Verbose "Using Default Credentials"
        $HTTP_Request.UseDefaultCredentials = $True
    }
    try {
        $response = $HTTP_Request.GetResponse()
        if ($response -AND [int]$response.StatusCode -eq 200) {
            return "Success!"
        } else {
            return "Error returned from $($URL): $($response.StatusCode)"
        }
    } catch {
        return "Error connecting to $($URL): $($_.Exception.InnerException.Message)"
    } finally {
        $response.Close()
    }
}

function Add-Error {
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [Ref]$Err,

        [Parameter(Mandatory=$true, Position=1)]
        [String]$Message
    )
    Write-Warning $Message
    $Err.Value += "$Message`n"
}

<#
	.SYNOPSIS
        Test-ICNetworkAccess Tests remote administration protocols and configurations for agentless scanning with Infocyte

    .DESCRIPTION
        Tests Domain, System, and Credential configuration for use with Infocyte HUNT.  Will attempt several
		tests of the credentials, permissions, remote connectivity, networking, and DNS Resolution.

    .PARAMETER Target
        (Mandantory) IP Address or FQDN of a remote system to test against

	.PARAMETER Credential
        (Mandatory) Network credentials to test (PSCredential Object)

    .PARAMETER ProxyAddress
        (Optional) Web Address of the proxy ie. http://192.168.1.2:8080

	.PARAMETER ProxyCredential
        (Optional) Proxy credentials (PSCredential Object)

	.PARAMETER Out
        (Optional) Output folder. Defaults to $env:Temp\ic\

    .EXAMPLE
        PS C:\> $Netcreds = Get-Credentials
        PS C:\> Test-ICNetworkAccess -Target 192.168.1.5 -Credential $Netcreds

    .EXAMPLE
        PS C:\> $Netcreds = Get-Credentials
		PS C:\> $Proxycreds = Get-Credentials
        PS C:\> Test-ICNetworkAccess -Target 192.168.1.5 -Credential $Netcreds -ProxyAddress "http://192.168.1.2:8080" -ProxyCredential $Proxycreds

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
		11. Test 443 Back to Infocyte from Remote Endpoint
#>
Function Test-ICNetworkAccess {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $True, HelpMessage = "The remote system to test connectivity to")]
		[ValidateNotNullOrEmpty()]
	  	[String]
	  	$Target,

		[Parameter(Position = 1, Mandatory = $True, HelpMessage = "Elevated account that will be used with HUNT")]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		$Credential,

	  	[Parameter(Mandatory = $False, HelpMessage = "Address of proxy in the form of: http://<myproxy-ip>:8080")]
        [ValidatePattern("http*")]
	  	[String]
	  	$ProxyAddress,

		[Parameter(Mandatory = $False, HelpMessage = "Proxy credentials for authenticated proxies")]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		$ProxyCredential,

		[String]
		$ReturnAddress="incyte.infocyte.com",

		[String]
		$Out="$Env:Temp\ic"
	)

	#$Admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
	#If (-NOT $Admin) {
	#	Write-Verbose "NOTE: Your shell is not running as Administrator (But you shouldn't need it for this script)."
	#}


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

    if ($ProxyAddress) {
        if ($ProxyAddress -match "http") {
            # "http://<myproxy-ip>:8012"
        } else {
            $ProxyAddress = "http://$ProxyAddress"
            Write-Warning "ProxyAddress ($ProxyAddress) may be in the wrong format: adding http://.  Should be http://myproxyaddress.com or http://192.168.1.80:8080"
        }
    }

	if (-NOT (Test-Path $out)) {
		mkdir $out
	}
	$OutputFileLocation = "$Out\InfocyteTest.log"
	$ports = 22,53,80,135,137,139,389,443,445,1025,1026,1027,3389,5985,5986,49152,49153,49154,61000,65535

    # Flush Local DNS Cache for testing
    Write-Host "`nFlushing DNS"
    ipconfig /flushdns | out-null

	$SourceExternalIP = (Invoke-WebRequest ifconfig.me/ip -UseBasicParsing).Content.Trim()
	$SourceIPAddress = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.ipenabled -AND $_.Ipaddress.length -gt 0 -AND $_.DefaultIPGateway.length -gt 0 }
    $SourceIP = $SourceIPAddress.ipaddress[0]
    $SourceHostname = $SourceIPAddress.DNSHostName
	If (-NOT $ReturnAddress) {
		$ReturnAddress = $SourceIP
	}
    $isLocal = $False
    If ($target -eq $SourceHostname -OR $target -eq $SourceIP) {
        Write-Warning "Attempting test against localhost. Might not get predictable/clean results for all tests."
        $isLocal = $True
    }
    $showcurrentproxy = ([string](netsh winhttp show proxy)).Trim() -replace "Current WinHTTP proxy settings:\s+"
    $Proxy = $Null
    if ($ProxyAddress) {
        $Proxy = New-Proxy $ProxyAddress $ProxyCredential
    }

	# Start transcript log of this script's output
	Start-Transcript -path $OutputFileLocation
	Write-Host "Running script with the following parameters:"
	Write-Host "Remote Test Target: $Target"
	Write-Host "Executed From: $SourceHostname / $SourceIP [ExtIP: $($ExternalIP)] by $(whoami)"
	Write-Host "Credential: $($Credential.Username)"
	Write-Host "Proxy Address: $(If ($ProxyAddress) {$ProxyAddress} Else {'None'})"
    Write-Host "Proxy Credential: $(If ($ProxyCredential) {$ProxyCredential.Username} Else {'None'})"
    Write-Host "Default Proxy: $showcurrentproxy"

    $Test = @{
        Config = $null
        Results = @()
    }

	$Test['Config'] = @{
		Target = $target
        Hostname = $null
        IP = $null
		ReturnAddress = $ReturnAddress
		SourceIP = $SourceIP
		DNSServers = $IPAddress.DNSServerSearchOrder
		SourceExternalIP = $SourceExternalIP
		Credential = $($Credential.Username)
		ProxyAddress = $ProxyAddress
		ProxyCredential = $($ProxyCredential.Username)
        DefaultProxy = $showcurrentproxy
        AsAdmin = $Admin
	}
    Write-Host "$Test['Config']"

    Write-Host -ForegroundColor Cyan "`n==========================================================================="
    Write-Host -ForegroundColor Cyan "==========================================================================="
    Write-Host -ForegroundColor Gray "This script will run several tests to test for remote connectivity, DNS, Internet Access, and permissions necessary to run Infocyte HUNT"
    Write-Host -ForegroundColor Gray "Any failed test or warning may be an issue that needs to be addressed before you use Infocyte HUNT"
	Write-Host -ForegroundColor Gray "Log File Location: $OutputFileLocation"
    Start-Sleep 3
    Write-Host -ForegroundColor Cyan "`n=== BEGINING TESTS ==="

    #region Internal DNS
	# Test Internal DNS Resolution to the target
    $Testnum += 1
    Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing DNS resolution to $Target"
    $Result = @{
        Name = "Internal DNS Test"
        Required = $True
        Test = $TestNum
        Description = "Testing DNS resolution to the provided target ($Target)"
        Success = $False
        SubResults = @()
        Error = $null
    }
    $DNSEntry = Get-DNSEntry $Target
    if ($DNSEntry) {
        Write-Host "SUCCESS: $Target has resolved to $($DNSEntry.Hostname) / $($DNSEntry.IP)"
        if ($DNSEntry.Hostname -notmatch $Domain) {
            $msg = "This system seems to have resolved to a domain that is different from the provided credentials for $($Domain)."
            $msg += "You may need to provide the correct credentials for the resolved domain or check your DNS provider. "
            $msg += "If this result is unexpected, ensure this system is pointed to the correct DNS server."
            Add-Error ([Ref]$Result['Error']) $msg
            $Result['SubResults'] += @{ DNSDomainAlignment = $False }
        } else {
            $Result['SubResults'] += @{ DNSDomainAlignment = $True }
        }
        if ($DNSEntry.IPs.count -gt 1) {
            Write-Warning "Multiple ($($DNSEntry.IPs.count)) IPs found associated to $($Target): $($DNSEntry.IPs). Should be fine..."
            $Test['Config']['Target IPs'] = $DNSEntry.IPs
        }
        $Hostname = $DNSEntry.Hostname
        $IP = $DNSEntry.IP
        $Test['Config']['Hostname'] = $DNSEntry.Hostname
        $Test['Config']['IP'] = $DNSEntry.IP
        $Result['Success'] = $True
    } else {
        $msg = "FAIL: DNS Resolution of $Target failed - You may not be pointed at the correct DNS Servers.`n"
        $msg += "Current DNS Servers: $($IPAddress.DNSServerSearchOrder)"
        Add-Error ([Ref]$Result['Error']) $msg
        $Result['Success'] = $False
    }
    $Test['Results'] += New-Object -Type PSObject -Property $Result
    #endregion Internal DNS

	#region Internet Tests
	# Test DNS Resolution and connectivity to the internet
	$Testnum += 1
	$TestAddr = "www.google.com"
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing DNS resolution and connectivity to the internet (Optional)"
	$Result = @{
        Name = "Internet Connectivity Test"
        Required = $False
        Test = $TestNum
        Description = "Testing DNS resolution and connectivity to the internet ($TestAddr)"
        Success = $False
        SubResults = @()
        Error = $null
   }

	$DNSEntry = Get-DNSEntry $TestAddr
	if ($DNSEntry) {
		Write-Host "SUCCESS: $TestAddr has resolved to $($DNSEntry.Hostname) => $($DNSEntry.IP)"
		$Result['SubResults'] += @{ ExternalDNS = $True }
	} else {
        Add-Error ([Ref]$Result['Error']) "FAIL: DNS Resolution of $TestAddr failed - Your internet may be down or restricted."
        $Result['SubResults'] += @{ ExternalDNS = $False }
	}

	try {
		$ICMP = Test-Connection -BufferSize 16 -Count 1 -ComputerName $TestAddr -ea STOP
		Write-Host "SUCCESS: Ping (ICMP) to $TestAddr ($($ICMP.IPV4Address)) in $($ICMP.ResponseTime) m/s"
        $Result['SubResults'] += @{ ICMP = $True }
	} catch {
        Add-Error ([Ref]$Result['Error']) "FAIL: Ping (ICMP) to $TestAddr failed - Message ($($_.Exception.GetType().FullName)): @($_.Exception.Message)"
        $Result['SubResults'] += @{ ICMP = $False }
	}

    $webtest = Test-WebPage "https://$TestAddr" -Proxy $Proxy
    if ($webtest -match "Success") {
        $Result['SubResults'] += @{ Web = $true }
        $Result['Success'] = $True
    } else {
        Add-Error ([Ref]$Result['Error']) "Could not connect to $($TestAddr): $webtest"
        $Result['SubResults'] += @{ Web = $False }
        $Result['Success'] = $False
    }
    $Test['Results'] += New-Object -Type PSObject -Property $Result


	# Test DNS Resolution and connectivity to Incyte
	$TestNum += 1
    $TestAddr = "incyte.infocyte.com"
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing DNS resolution and connectivity to Infocyte Cloud ($TestAddr)"
	$Result = @{
        Name = "Infocyte Cloud Connectivity Test"
        Required = $True
        Test = $TestNum
        Description = "Testing DNS resolution and connectivity to Infocyte Cloud ($TestAddr)"
        Success = $False
        SubResults = @()
        Error = $null
    }

	$DNSEntry = Get-DNSEntry $TestAddr
	if ($DNSEntry) {
		Write-Host "SUCCESS: $TestAddr resolved to $($DNSEntry.Hostname) / $($DNSEntry.IP)"
		$Result['SubResults'] += @{ DNS = $True }
	} else {
        Add-Error ([Ref]$Result['Error']) "FAIL: DNS Resolution of $TestAddr failed - Your internet may be down or restricted"
        $Result['SubResults'] += @{ DNS = $False }
	}

    if ($ProxyAddress) {
        Write-Host -ForegroundColor Cyan "[TEST $TestNum] Testing connectivity to $TestAddr with direct access (No Proxy)"
        $webtest = Test-WebPage "https://$TestAddr" -NoProxy
        if ($webtest -match "Success") {
            $Result['SubResults'] += @{ WebNoProxy = $True }
            $Result['Success'] = $True
        } else {
            Add-Error ([Ref]$Result['Error']) "Could not connect to $TestAddr with no proxy (Direct): $webtest"
            $Result['SubResults'] += @{ WebNoProxy = $False }
        }
    }
    Write-Host -ForegroundColor Cyan "[TEST $TestNum] Testing connectivity to $TestAddr with DefaultCredentials"
    Write-Host "Current System Proxy Settings: $showcurrentproxy"
    $webtest = Test-WebPage "https://$TestAddr"
    if ($webtest -match "Success") {
        $Result['SubResults'] += @{ WebDefaultProxy = $True }
        $Result['Success'] = $True
    } else {
        Add-Error ([Ref]$Result['Error']) "Could not connect to $($TestAddr) with DefaultCredentials: $webtest"
        $Result['SubResults'] += @{ WebDefaultProxy = $False }
    }

    Write-Host -ForegroundColor Cyan "[TEST $TestNum] Testing connectivity to $TestAddr with Provided Proxy: $ProxyAddress [$($ProxyCredential.username)]"
    $webtest = Test-WebPage "https://$TestAddr" -Proxy $Proxy
    if ($webtest -match "Success") {
        $Result['SubResults'] += @{ Web = $True }
        $Result['Success'] = $True
    } else {
        Add-Error ([Ref]$Result['Error']) "Could not connect to $($TestAddr) with $($ProxyAddress): $webtest"
        $Result['Success'] = $False
        $Result['SubResults'] += @{ Web = $False }
    }

	$Test['Results'] += New-Object -Type PSObject -Property $Result

	#endregion Internet Test

	#region Remote Target Connectivity Tests
	# Test connectivity to Target
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing connectivity to $target"
    Write-Host -ForegroundColor Cyan "ICMP and TCP ports:`n$ports"
	$Result = @{
        Name = "Target Connectivity Test"
        Required = $True
        Test = $TestNum
        Description = "Testing connectivity to $target on ICMP and TCP Ports: $ports"
        Success = $False
        SubResults = @()
        Error = $null
	}

	# Test Remote Connectivity (Ping)
	Write-Host "`nTesting Connectivity to $IP w/ ICMP"
	try {
		$ICMP = Test-Connection -BufferSize 16 -Count 1 -ComputerName $IP -ea STOP
		Write-Host "SUCCESS: Ping (ICMP) to $Hostname ($($ICMP.IPV4Address)) in $($ICMP.ResponseTime) m/s"
		$Result['SubResults'] += @{ ICMP = $True }
	} catch {
        Add-Error ([Ref]$Result['Error']) "FAIL: Ping (ICMP) to $Hostname (($($ICMP.IPV4Address)) - Message ($($_.Exception.GetType().FullName)): $($_.Exception.Message)"
		$Result['SubResults'] += @{ ICMP = $False }
	}

	$PortResults = $ports | Test-Connectivity -IP $IP
	$Result['SubResults'] += @{ Portscan = $PortResults}
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


	$opendynports = $PortResults | where { $_.Name -Match "Dynamic" } | where { $_.Access -eq $true }
	If ($opendynports) {
        $Result['SubResults'] += @{ DynamicPorts = $true}
	} else {
        $Result['SubResults'] += @{ DynamicPorts = $False}
        Add-Error ([Ref]$Result['Error']) "FAIL: No Access to Dynamic Ports (TCP 49152-65535 or 1025-5000 for 2k3/XP) on $IP - May affect WMI & RPC Execution and Deployment against a Windows-based Hosts"
	}

    if ($PortResults | where { $_.Port -eq 22 } | where { $_.Access -eq $true }) {
        $Result['SubResults'] += @{ SSH = $true}
    } else {
        $Result['SubResults'] += @{ SSH = $false}
        Add-Error ([Ref]$Result['Error']) "FAIL: No Access to SSH (TCP 22) on $IP - Will affect SSH Execution and Deployment against a Unix-based Hosts"
    }

    if ($PortResults | where { $_.Port -eq 139 -OR  $_.Port -eq 445} | where { $_.Access -eq $true }) {
        $Result['SubResults'] += @{ SMB = $true}
    } else {
        $Result['SubResults'] += @{ SMB = $false}
        Add-Error ([Ref]$Result['Error']) "FAIL: No Access to SMB on $IP - Will affect future file retrieval and may affect Deployments against a Windows-based Hosts"
    }

    if ($PortResults | where { $_.Port -eq 135 } | where { $_.Access -eq $true }) {
        $Result['SubResults'] += @{ 'WMI/RPC' = $true}
    } else {
        $Result['SubResults'] += @{ 'WMI/RPC' = $false}
        Add-Error ([Ref]$Result['Error']) "FAIL: No Access to WMI/RPC on $IP - Will affect WMI and RPC-based Execution and Deployment against a Windows-based Hosts"
    }

    if ($PortResults | where { $_.Port -eq 5985 -OR $_.Port -eq 5986 } | where { $_.Access -eq $true }) {
        $Result['SubResults'] += @{ 'PSRemote/WinRM' = $True }
    } else {
        $Result['SubResults'] += @{ 'PSRemote/WinRM' = $false }
        Add-Error ([Ref]$Result['Error']) "FAIL: No Access to PSRemote/WinRM on $IP - Will affect PSRemoting Execution and Deployment against a Windows-based Hosts"
	}

	$open = ($PortResults | where { $_.Access }).count
	if ($open -gt 0) {
		$Result['Success'] = $True
	}
	$Test['Results'] += New-Object -Type PSObject -Property $Result
	#endregion Remote Target Connectivity Test

	#region Permissions Tests
	# Test Credentials against domain
	$TestNum += 1
	Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Validating Credentials are valid..."
	$Result = @{
        Name = "Credential Test"
        Required = $True
        Test = $TestNum
        Description = "Validating Credentials are valid on $Domain"
        Success = $True
        SubResults = @()
        Error = $null
   }
	$TestCreds = Test-ADCredentials $Creds
	if ($TestCreds.isValid) {
		Write-Host "SUCCESS: Credentials for $Username are valid on $Domain"
	} else {
        Add-Error ([Ref]$Result['Error']) $TestCreds.Error
		$Result['Success'] = $False
	}
	$Test['Results'] += New-Object -Type PSObject -Property $Result

	# Get RSOP permissions
    Write-Host "Getting Resultant Set of Policy (RSoP) for localhost - output to file $Out\InfocyteTest_RSoP_localhost.html"
	GPResult.exe /USER $Username /H "$Out\InfocyteTest_RSoP_localhost.html" /F
	GPResult.exe /USER $Username /v > "$Out\InfocyteTest_RSoP_localhost.txt"

	<#
	Write-Host "Getting Resultant Set of Policy (RSoP) for $Hostname - output to file $Out\InfocyteTest_RSoP_$Hostname.txt"
	Gpresult /S $Hostname /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /USER $Username /v > "$Out\InfocyteTest_RSoP_$Hostname.txt"
	if ($res -match "does not have RSOP data") {
		Write-Warning "$res"
		Write-Warning "Fallback: Attempting to gather RSoP for current user"
		Gpresult /S $Hostname /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /v > "$Out\InfocyteTest_RSoP_$Hostname.txt"
	}
	#>
	#endregion Permissions Test

	#region Remote Execution Protocol Tests
	# Test WMI Execution
	$TestNum += 1
    Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing WMI Execution..."
	$Result = @{
        Name = "WMI Test"
        Required = $False
        Test = $TestNum
        Description = " Testing WMI Execution Against $Hostname ($target)"
        Success = $False
        SubResults = @()
        Error = $null
   }

	if (-NOT $Test.Results.SubResults.'WMI/RPC') {
        Add-Error ([Ref]$Result['Error']) "No connectivity to RPC - skipping WMI test"
		$Result['Success'] = $False
    } else {
        if (-NOT $opendynports) {
            Add-Error ([Ref]$Result['Error']) "Dynamic Ports were either blocked or not available - Might effect connection"
        }

        $GetWmiObjectParams = @{
            Class = "win32_OperatingSystem"
            Property = "Caption"
            ComputerName = $IP
            Credential = $Creds
            Impersonation = 'Impersonate'
        }
        if ($isLocal) {
            Try {
                $OS = (Get-WmiObject @GetWmiObjectParams -ea Stop).Caption
                Write-Host "SUCCESS: WMI succeeded to $($IP). $Hostname is a $OS System"
                $Result['SubResults'] += @{ Local = $True }
                $Result['Success'] = $True
            } Catch {
                Add-Error ([Ref]$Result['Error']) "FAIL: WMI connection failed to $IP"
                $Result['SubResults'] += @{ Local = $false }
            }
        } else {

            Write-Host "Testing WMI w/ NTLM authentication"
            $GetWmiObjectParams['Authority'] = "ntlmdomain:$Domain"
            Try {
                $OS = (Get-WmiObject @GetWmiObjectParams -ea Stop).Caption
                Write-Host "SUCCESS: WMI w/ NTLM succeeded to $($IP). $hostname is a $OS System"
                $Result['SubResults'] += @{ NTLM = $True }
                $Result['Success'] = $True
            } Catch {
                Add-Error ([Ref]$Result['Error']) "FAIL: WMI with NTLM failed to $IP"
                $Result['SubResults'] += @{ NTLM = $false }
            }

            # Test Kerberos
            Write-Host "Testing WMI w/ explicit Kerberos authentication (IP)"
            $GetWmiObjectParams['Authority'] = "kerberos:"+$Domain+"\"+$Hostname.Split('.')[0]+'$'
            Try {
                $OS = (Get-WmiObject @GetWmiObjectParams -ea Stop).Caption
                Write-Host "SUCCESS: WMI w/ Kerberos succeeded.  $Hostname ($IP) is a $OS System"
                $Result['SubResults'] += @{ KerberosByIP = $True }
                $Result['Success'] = $True
            } Catch {
                Add-Error ([Ref]$Result['Error']) "FAIL: WMI with Kerberos failed to $Domain\$Hostname ($IP)"
                $Result['SubResults'] += @{ KerberosByIP = $false }
            }

            Write-Host "Testing WMI w/ explicit Kerberos authentication (hostname)"
            $GetWmiObjectParams['ComputerName'] = $Hostname
            Try {
                $OS = (Get-WmiObject @GetWmiObjectParams -ea Stop).Caption
                Write-Host "SUCCESS: WMI w/ Kerberos succeeded to $($Hostname). $IP is a $OS System"
                $Result['SubResults'] += @{ KerberosByName = $True }
                $Result['Success'] = $True
            } Catch {
                Add-Error ([Ref]$Result['Error']) "FAIL: WMI with Kerberos failed to $Hostname ($IP)"
                $Result['SubResults'] += @{ KerberosByName = $false }
            }
        }
    }
	$Test['Results'] += New-Object -Type PSObject -Property $Result


	# Test SMB Connectivity
	$TestNum += 1
    Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing Server Message Block (SMB) connectivity to $($IP)/C$ ($target)"
	$Result = @{
        Name = "SMB Test"
        Test = $TestNum
        Description = "Testing Server Message Block (SMB) connectivity to $($IP)/C$ ($target)"
        Success = $False
        SubResults = @()
        Error = $null
    }

 	if (-NOT $Test.Results.SubResults.SMB) {
        Add-Error ([Ref]$Result['Error']) "No connectivity to NetBIOS and SMB ports - skipping SMB Transfer test"
		$Result['Success'] = $False
    } else {
        try {
            $mountdrive = New-PSDrive -Name test -PSProvider FileSystem -Root "\\$IP\C$" -Credential $Creds -ea STOP
            Write-Host "SUCCESS: Connected to $IP via SMB"
        } catch {
            Write-Warning "Could not mount \\$IP\C$ -- Trying again on \\$Hostname\C$"
            try {
                $mountdrive = New-PSDrive -Name test -PSProvider FileSystem -Root "\\$Hostname\C$" -Credential $Creds -ea STOP
                Write-Host "SUCCESS: Connected to $Hostname via SMB"
            } catch {
                Add-Error ([Ref]$Result['Error']) "FAIL: Could not connect to $Target via SMB - C$ administrative share may not be accessible - Message: $($_.Exception.Message)"
                $Result['Success'] = $False
            }
        }
    }
	$Test['Results'] += New-Object -Type PSObject -Property $Result


	# Test Remote Schtasks
	$TestNum += 1
    Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing Remote Schtasks (via RPC) Execution..."
	$Result = @{
        Name = "Remote SchTasks Test"
        Test = $TestNum
        Description = "Testing Remote Schtasks Execution to $IP ($target)"
        Success = $True
        SubResults = @()
        Error = $null
    }

    if (-NOT $Test.Results.SubResults.'WMI/RPC') {
        Add-Error ([Ref]$Result['Error']) "No connectivity to RPC - skipping Remote Schtasks test"
        $Result['Success'] = $False
    } else {
        if (-NOT $opendynports) {
            Add-Error ([Ref]$Result['Error']) "Dynamic Ports were either blocked or not available - Might effect connection"
        }
        $a = SCHTASKS /Create /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test /TR 'c:\windows\system32\cmd.exe /c Net Time' /SC ONCE /ST 23:59 /RU SYSTEM /F
        if ($a -match "SUCCESS") {
            Write-Host "SUCCESS: Remote task (test) created on $IP"
            Start-Sleep 1

            # Run the task
            $b = SCHTASKS /Run /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test
            if ($b -match "SUCCESS") {
                Write-Host "SUCCESS: Remote task (test) was initiated on $IP"
            } else {
                Add-Error ([Ref]$Result['Error']) "Remote task (test) failed to initiate: $b"
                $Result['Success'] = $False
            }
        } else {
            Add-Error ([Ref]$Result['Error']) "Remote task (test) failed on $($IP): $a"
            $Result['Success'] = $False
        }
    }

    # Query Task status
    $c = SCHTASKS /query /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test
    if (($c -match "Running") -OR ($c -match "Ready")) {
        Write-Host "SUCCESS: Remote task (test) ran successfully on $IP"
    } else {
        Add-Error ([Ref]$Result['Error']) "FAIL: Remote task (test) ran into some issues on $($IP): $c"
    }

    #Delete the task (Cleanup)
    Start-Sleep 1
    SCHTASKS /delete /S $IP /U $FQUsername /P ($Creds.GetNetworkCredential().Password) /TN test /F | Out-Null

    $Test['Results'] += New-Object -Type PSObject -Property $Result


	# Test PSRemoting
	$TestNum += 1
    Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing Powershell Remoting Execution..."
	$Result = @{
        Name = "WinRM Test"
        Test = $TestNum
        Description = "Testing Powershell Remoting (WinRM) Execution to $target"
        Success = $True
        SubResults = @()
        Error = $null
   }

	if (-NOT $Test.Results.SubResults.'PSRemote/WinRM') {
        Add-Error ([Ref]$Result['Error']) "No connectivity to Powershell Remoting ports - skipping Powershell Remoting test"
        $Result['Success'] = $False
    } else {
        # TrustedHosts
        $current=(get-item WSMan:\localhost\Client\TrustedHosts).value
        if ($current -ne "*" -AND $current -notmatch $IP) {
            Add-Error ([Ref]$Result['Error']) "$IP is not within TrustedHosts. Adding a temporary entry. Recommend setting to '*' on scanners."
            if ($current) {
                $new = $current + ",$IP"
            } else {
                $new = $IP
            }
            set-item WSMan:\localhost\Client\TrustedHosts –value $new
        }

        try {
            $errorActionPreference = "Stop"
            $r = Invoke-Command -ComputerName $IP -Credential $Creds -ea Stop { 1 }
            Write-Host "SUCCESS: Powershell Remoting Session established with $target"
        }
        catch {
            Write-Warning "Failed against IP. Attempting again using hostname."
            try {
                $r = Invoke-Command -ComputerName $Hostname -Credential $Creds -ea Stop { 1 }
                Write-Host "SUCCESS: Powershell Remoting Session established with $target"
            }
            catch {
                Add-Error ([Ref]$Result['Error']) "FAIL: PSRemoting to $target failed. Message: @($_.Exception.Message)"
        		$Result['Success'] = $False
            }
        }
        $errorActionPreference = "Continue"
        set-item WSMan:\localhost\Client\TrustedHosts –value $current
    }
	$Test['Results'] += New-Object -Type PSObject -Property $Result
	#endregion Remote Execution Protocol Tests


	# Test Endpoint Return Path to HUNT Server
	$TestNum += 1
    Write-Host -ForegroundColor Cyan "`n[TEST $TestNum] Testing remote endpoint TCP443 return path to $ReturnAddress..."
	$Result = @{
        Name = "Return Path Test"
        Test = $TestNum
        Description = "Testing remote endpoint TCP443 return path to $ReturnAddress"
        Success = $False
        SubResults = @()
        Error = $null
   }

   if ($isLocal) {
       $webtest = Test-WebPage "https://$ReturnAddress" -Proxy $Proxy
       if ($webtest -notmatch "Success") {
           Add-Error ([Ref]$Result['Error']) "Could not connect to $($ReturnAddress) with $($ProxyAddress): $($webtest). This will affect return communications."
           $Result['Success'] = $False
       }
   } else {
       if ($Test.Results.SubResults.'PSRemote/WinRM' -AND $ReturnAddress -ne $IP) {
           $ReturnAddress = "https://incyte.infocyte.com"
           $RemoteScript = [System.Management.Automation.ScriptBlock]::Create("`$HTTP_Request = [System.Net.WebRequest]::Create('$ReturnAddress'); try { if (`$HTTP_Request.GetResponse()) { `$true } } catch { `$false }")
           try {
               $r = Invoke-Command -ScriptBlock $RemoteScript -ComputerName 10.0.0.11 -Credential $Credential
               $Result['Success'] = $r
               if (-NOT $r) {
                   Add-Error ([Ref]$Result['Error']) "Remote return path to $($ReturnAddress) failed."
               }
            } catch {
                Add-Error ([Ref]$Result['Error']) "Could not test remote return path to $($ReturnAddress) - Command failed: $($_.Exception.Message)."
                $Result['Success'] = $False
            }
        }
        elseif ($Test.Results.SubResults.'WMI/RPC') {

            $RemoteScript = '
            #Infocyte Test
            function Test-Port ($target, $port=443) {
               $tcpclient = New-Object Net.Sockets.TcpClient
               try { $tcpclient.Connect($target,$port) } catch {}
               try { $tcpclient.Close() } catch {}
               if ($tcpclient.Connected) { $tcpclient.Close(); "Infocyte: SUCCESS" > C:\windows\temp\accesstest.txt }	else { "Infocyte: FAIL" > C:\windows\temp\accesstest.txt }
            }
            Test-Port '+$ReturnAddress

            $bytes = [System.Text.Encoding]::Unicode.GetBytes($RemoteScript)
            $encodedCommand = [Convert]::ToBase64String($bytes)
            try {
                if ($ReturnAddress -eq $IP) {
                    $server = New-TcpListener -Port 443
                    Start-Sleep 1
                    Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "powershell.exe -Nop -NoLogo -Win Hidden -encodedCommand $encodedCommand" -ComputerName $Target -Credential $Credential | Out-Null
                	$msg = if (Receive-TCPMessage) { "SUCCESS" } else { $false }
                } else {
                    Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "powershell.exe -Nop -NoLogo -Win Hidden -encodedCommand $encodedCommand" -ComputerName $Target -Credential $Credential | Out-Null
                	Start-Sleep 3
                	$msg = Get-Content test:\\result.txt -ea SilentlyContinue
                }

                if ($msg -notmatch "SUCCESS") {
                    Add-Error ([Ref]$Result['Error']) "Remote return path to $($ReturnAddress) failed."
                	$Result['Success'] = $False
                }
            } catch {
                Add-Error ([Ref]$Result['Error']) "FAIL: Could not test remote return path to $($ReturnAddress) - WMI Command Failed - Message: $($_.Exception.Message)"
                $Result['Success'] = $False
    		} finally {
                Remove-PSDrive test -ea SilentlyContinue
    		}
	    }
    }
	$Test['Results'] += New-Object -Type PSObject -Property $Result

	$Test | ConvertTo-Json -Depth 10 | Out-File "$Out\InfocyteTest.json"

	Write-Host -ForegroundColor Cyan "All Tests Complete!"
	Write-Host "Results are found here:"
	Write-Host "$Out\InfocyteTest_RSoP_localhost.txt"
	Write-Host "$Out\InfocyteTest_RSoP_localhost.html"
	Write-Host "$Out\InfocyteTest.log"
	Write-Host "$Out\InfocyteTest.json"

	"$Out\InfocyteTest_RSoP_localhost.txt\n" | out-file "$env:temp\ictestoutputfolders"
	"$Out\InfocyteTest_RSoP_localhost.html" | out-file "$env:temp\ictestoutputfolders" -Append
	"$Out\InfocyteTest.log" | out-file "$env:temp\ictestoutputfolders" -Append
	"$Out\InfocyteTest.json" | out-file "$env:temp\ictestoutputfolders" -Append

	return $Test
}
}
