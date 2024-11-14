$temp = "~\Desktop\rdptriage"
if (-NOT (Test-Path $temp)) {
	mkdir $temp
}
$startdate = (Get-date -hour 0 -minute 0 -second 0).AddDays(-20)
function ConvertFrom-WinEvent {
	[cmdletbinding()]
	param(
		[parameter(
			Mandatory=$true,
			ValueFromPipeline=$true)]
		[Object]$Event
	)

	PROCESS {
		$fields = $Event.Message.split("`n") #| Select-String "\w:"
		$event = new-object -Type PSObject -Property @{
			EventId = $Event.Id
			TimeCreated = $Event.TimeCreated
			Message = $Event.Message
		}
		$fields | % { 
			$line = $_.ToString()
			if ($line -match "^\w.*?:") {
				$addtoarray = $false
				$m = $line -split ":"
				Write-Verbose "Found Match at Root. $($m[0]): $($m[1])"
				if ($m[1] -AND $m[1] -notmatch "^\s+$") {
					$base = $false
					$m[1] = $m[1].trim()
					if ($m[1] -match "^0x[0-9a-fA-F]+" ) { $m[1] = [int]$m[1]}
					if ($m[1] -match "^\d+$" ) { $m[1] = [int]$m[1]}
					$event | Add-Member -MemberType NoteProperty -Name $m[0] -Value $m[1]; 
				} else {
					$base = $true
					$event | Add-Member -MemberType NoteProperty -Name $m[0] -Value (New-Object -Type PSObject); 
				}
			} 
			elseif ($Base -AND $m[0] -AND ($line -match '^\t{1}\w.*?:')) {
				Write-Verbose "sub: $line"
				$m2 = $line.trim() -split ":",2
				$m2[1] = $m2[1].trim().trim("{}")
				if ($m2[1] -match "^0x[0-9a-fA-F]+" ) { $m2[1] = [int]$m2[1]}
				if ($m2[1] -match "^\d+$" ) { $m2[1] = [int]$m2[1]}
				Write-Verbose "Found submatch off $($m[0]). $($m2[0]) : $($m2[1])"
				$event."$($m[0])" | Add-Member -MemberType NoteProperty -Name $m2[0] -Value $m2[1]; 
			} 
			elseif ($m -AND $m[0] -AND ($line -match '^\t{3}\w.*')) {
				Write-Verbose "sub: $line"
				$m2 = $line.trim()
				if ($m2 -match "^0x[0-9a-fA-F]+" ) { $m2 = [int]$m2}
				if ($m2 -match "^\d+$" ) { $m2 = [int]$m2}
				Write-Verbose "Found submatch off $($m[0]). $($m2) : $($m2)"
				if (-NOT $addtoarray) {
					$event."$($m[0])" = @($event."$($m[0])") 
					$event."$($m[0])" += $m2;
					$addtoarray = $true
				} else {
					$event."$($m[0])" += $m2;
				}
			}
			elseif ($line -AND $line -notmatch "^\s+$") {
				$base = $false
				$addtoarray = $false
				if ($line -notmatch "(^\w.*?\.\s?$|^\s-\s\w.*)") { Write-Warning "Unexpected line: $_" }
			}
		}
		return $event
	}
}

$RDP_Logons = Get-WinEvent -FilterHashtable @{logname="security";id=4624; StartTime=$startdate} -ea 0 | where { 
	$_.Message -match 'logon type:\s+(10|7)' -AND $_.Message -notmatch "Source Network Address:\s+LOCAL" } | ConvertFrom-WinEvent | foreach-object {
	new-object -Type PSObject -Property @{
		EventId = $_.EventId
		TimeCreated = $_.TimeCreated
		SourceIP = $_."Network Information"."Source Network Address"
		Username = $_."New Logon"."Account Name"
		Domain = $_."New Logon"."Account Domain"
		LogonType = if ($_."Logon Information"."Logon Type") {$_."Logon Information"."Logon Type"} else { $_."Logon Type" } 
		ElevatedToken = $_."Logon Information"."Elevated Token" #Windows10/2016+
		SecurityId = $_."New Logon"."Security ID"
		LogonId = [int]$_."New Logon"."Logon ID"
	}
} | where { $_.SecurityId -match "S-1-5-21" -AND $_.SourceIP -ne "LOCAL" -AND $_.SourceIP -ne "-" -AND $_.SourceIP -ne "::1" } | sort-object TimeCreated -Descending | 
	Select-object TimeCreated, EventId, SourceIP, ElevatedToken, SecurityId, LogonId, Username, Domain, @{N='LogonType';E={
		switch ([int]$_.LogonType) {
			2 {'Interactive (local) Logon [2]'}
			3 {'Network Connection (i.e. shared folder) [3]'}
			4 {'Batch [4]'}
			5 {'Service [5]'}
			7 {'Unlock/RDP Reconnect [7]'}
			8 {'NetworkCleartext [8]'}
			9 {'NewCredentials (local impersonation) [9]'}
			10 {'RDP [10]'}
			11 {'CachedInteractive [11]'}
			default {"LogonType Not Recognised: $($_.LogonType)"}
		}
	}
}
 
#This is just a connection attempt event, very noisy and not as useful
$RDP_RemoteConnectionManager = Get-WinEvent -FilterHashtable @{ logname='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ID=1149; StartTime=$startdate } -ea 0 |
	where { $_.Message -notmatch "Source Network Address:\s+LOCAL" } | ConvertFrom-WinEvent | foreach-object {
		new-object -Type PSObject -Property @{
			EventId = $_.EventId
			TimeCreated = $_.TimeCreated
			SourceIP = $_."Source Network Address"
			Username = $_."User"
			Domain = $_."Domain"
		}
	} | where { $_.SourceIP -ne "LOCAL" -AND $_.SourceIP -ne "-" -AND $_.SourceIP -ne "::1" } | sort TimeCreated -Descending | Select TimeCreated, EventId, SourceIP, Username, Domain

$RDP_LocalSessionManager = Get-WinEvent -FilterHashtable @{ logname='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ID=21,24,25; StartTime=$startdate } -ea 0 | 
	where { $_.Message -notmatch "Source Network Address:\s+LOCAL"} | ConvertFrom-WinEvent | foreach-object {
		new-object -Type PSObject -Property @{
			EventId = $_.EventId
			TimeCreated = $_.TimeCreated
			SourceIP = $_."Source Network Address"
			UserName = $_."User"
			Action = $_."Remote Desktop Services"
		}
	} | where { $_.SourceIP -ne "LOCAL" -AND $_.SourceIP -ne "::1" } | sort TimeCreated -Descending | Select TimeCreated, EventId, SourceIP, Username, Action

		  
$RDP_Processes = Get-WinEvent -FilterHashtable @{logname='security';id=4688; StartTime=$startdate}  -ea 0 | where { $_.Message -match "Creator Subject:\s+Security ID:\s+S-1-5-21" } | 
	ConvertFrom-WinEvent | where { $RDP_Logons.LogonId -contains $_."Creator Subject"."Logon ID" } | foreach-object {
		$LogonId = $_."Creator Subject"."Logon ID";
		$Session = $RDP_Logons | where-object { $_.LogonId -eq $LogonId };
		$SecurityId = $_."Creator Subject"."Security ID"
		if ($SecurityId -ne $Session.SecurityId) { Write-Error "SecurityIds do not match! ProcessSecurityId=$($_."Security ID"), SessionSecurityId=$($Session.SecurityId)" }

		new-object -Type PSObject -Property @{
			EventId = $_.EventId
			TimeCreated = $_.TimeCreated
			SecurityId = $_."Creator Subject"."Security ID"
			LogonId = $_."Creator Subject"."Logon ID"
			Username = $_."Creator Subject"."Account Name"
			Domain = $_."Creator Subject"."Account Domain"
			ProcessId = $_."Process Information"."New Process ID"
			ParentProcessId = $_."Process Information"."Creator Process ID"
			ParentProcessPath = $_."Process Information"."Creator Process Name"
			ProcessPath = $_."Process Information"."New Process Name"
			Commandline = $_."Process Information"."Process Command Line"
			LogonType = $Session.LogonType
			SourceIP = $Session.SourceIP
			SessionTimeCreated = $Session.TimeCreated
		}
		$proc
	} | sort TimeCreated -Descending | Select TimeCreated, EventId, SourceIP, SessionTimeCreated, LogonType, LogonId, ProcessId, ProcessPath, Commandline, SecurityId, Username, Domain, ParentProcessId, ParentProcessPath

$RDP_Logons | export-csv $temp\RDP_Logons.csv -NoTypeInformation -Force
$RDP_RemoteConnectionManager | export-csv $temp\RDP_RemoteConnectionManager.csv -NoTypeInformation -Force
$RDP_LocalSessionManager | export-csv $temp\RDP_LocalSessionManager.csv -NoTypeInformation -Force
$RDP_Processes | export-csv $temp\RDP_Processes.csv -NoTypeInformation -Force
Write-Host "Find output here: $temp"
invoke-item $temp