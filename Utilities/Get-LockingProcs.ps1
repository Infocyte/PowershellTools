<#
Import this file using dot sourcing:
PS> . ~\Downloads\Get-LockingProcs.ps1

Then run it using one of the below examples
#>

Function Get-LockingProcs {
    <#
    .SYNOPSIS
        Get list of processes locking a file.
    .DESCRIPTION
        This function returns a list of processes discovered to be locking a specified file. It leverages the SysInternals tool "handle.exe".

        If "handle.exe" is not found in "$env:temp\sysinternals\", the function will attempt to download it. If the download fails, the function will throw an exception.
    .PARAMETER Path
        Path(s) to potentialy locked file(s).
    .INPUTS
        Path(s) can be provided via pipeline.
    .OUTPUTS
        [PSCustomObject]@{
			Name
			PID        
			ProcessPath
			Commandline
			Type
			Owner
			Path
        }
    .EXAMPLE
        PS> Get-LockingProcs "c:\users\TestUser\Documents\Spreadsheet.xlsx"
		
		Name  PID   Owner               Commandline
		----  ---   -----               -----------
		agent 58312 NT AUTHORITY\SYSTEM C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\agent.exe --service
		
    .EXAMPLE
        PS> dir C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\ | Get-LockingProcs
		
		Get-LockingProcs : Searching for handles to [C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\logs]
		Get-LockingProcs : Found 2 unique processes with locks on [C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\logs]

		Name  PID   Owner               Commandline
		----  ---   -----               -----------
		agent 25560 NT AUTHORITY\SYSTEM "C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\agent.exe" datto-av datto_av-0szJjdKK VT3Ty1NqWjqnENKUlSRgfrVo
		agent 58312 NT AUTHORITY\SYSTEM C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\agent.exe --service


		Get-LockingProcs : Searching for handles to [C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\rwd]
		Get-LockingProcs : Found 1 unique processes with locks on [C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\rwd]

		Name       PID   Owner               Commandline
		----       ---   -----               -----------
		RWDWrapper 50972 NT AUTHORITY\SYSTEM "C:\ProgramData\CentraStage\AEMAgent\RMM.AdvancedThreatDetection\rwd\RWDWrapper.exe" -edr -productId "Datto EDR" -clientId dattoc8157-ccd9778b-e8d8-45da-bf73-4b5266ac34a..
						
    .LINK
        Inspired by: 	https://raw.githubusercontent.com/TheKojukinator/KojukiShell.Core/master/KojukiShell.Core/public/Get-LockingProcs.ps1
						https://stackoverflow.com/questions/958123/powershell-script-to-check-an-application-thats-locking-a-file
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Path', ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[ValidateNotNullorEmpty()]
		[Alias("PSPath")]
        [string] $Path,

        # Specifies a literal export location path.
        [Parameter(Mandatory, ParameterSetName = 'LiteralPath', ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[ValidateNotNullorEmpty()]
        [String] $LiteralPath
    )
    begin {
		
        try {
            # check if the tool is present, if not, attempt to download it from the web
			$sysinternalsFolder = "$env:temp\sysinternals"
            $exe = "$sysinternalsFolder\handle.exe"
            if (!(Test-Path $exe -ErrorAction Ignore)) {
                Write-Host -ForegroundColor Cyan "Get-LockingProcs : [$exe] not found, attempting to download"
				if (!(Test-Path $sysinternalsFolder -ErrorAction Ignore)) { New-Item -ItemType Directory $sysinternalsFolder -ErrorAction Ignore | Out-Null }
                Invoke-WebRequest -Uri "https://live.sysinternals.com/handle.exe" -OutFile $exe -Force
                if (!(Test-Path $exe -ErrorAction Ignore)) {
                    throw "Can't find [$exe]"
                }
            }
            Write-Host -ForegroundColor Cyan "Get-LockingProcs : Using [$exe]"
			$outputname = "get-lockingprocs_$(Get-Date -AsUTC -Format "yyyyMMdd_HHmm")UTC.txt"
			"Get-LockingProcs run on [$(Get-Date -AsUTC) UTC] Using [$exe]" | Out-file .\$outputname -Force

        } catch {
            if (!$PSitem.InvocationInfo.MyCommand) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        (New-Object "$($PSItem.Exception.GetType().FullName)" (
                                "$($PSCmdlet.MyInvocation.MyCommand.Name) : $($PSItem.Exception.Message)`n`nStackTrace:`n$($PSItem.ScriptStackTrace)`n"
                            )),
                        $PSItem.FullyQualifiedErrorId,
                        $PSItem.CategoryInfo.Category,
                        $PSItem.TargetObject
                    )
                )
            } else { $PSCmdlet.ThrowTerminatingError($PSitem) }
        }
    }
    process {
		if ($PSCmdlet.ParameterSetName -eq 'Path') {
			# Resolve any relative paths
			$Path = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path);
		} else {
			$Path = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LiteralPath);
		}
		
        try {

			Write-Host -ForegroundColor Cyan "`nGet-LockingProcs : Searching for handles to [$path]"

			# execute handle.exe and get output, pass arguments to accept license and hide banner
			$data = & $exe -u -accepteula -nobanner $path
			if ($data.count -eq 1){ Write-Verbose $data } else { $data | % {  Write-Verbose $_ } }
			# define regex including capture groups for each column we are interested in
			# unbroken regex: '^(?<Name>[\s\w\\\._-]+\.\w+)\s+pid:\s+(?<PID>\d+)\s+type:\s+(?<Type>\w+)\s+(?<User>[\w\\\._-]+)\s+\w+:\s+(?<Path>.*)$'
			[string]$pattern = '^' + # start of line
			'(?<Name>[\s\w\\\._-]+\.\w+)' + # name of the process, allow spaces, periods, dashes, and underscores
			'\s+pid:\s+' + # in-between data before pid
			'(?<PID>\d+)' + # pid of the process, allow numbers
			'\s+type:\s+' + # in-between data before type
			'(?<Type>\w+)' + # type of handle, allow alphanumeric
			'\s+' + # in-between data before user
			'(?<User>(NT )?[\w\\\._-]+)' + # user bound to handle, allows spaces, periods, dashes, underscores, and backslashes if domain is specified
			'\s+\w+\s+' + # in-between data before path
			'(?<Path>.*)' + # path to the locked file
			'$' # end of line
			# declare array to hold locking procs
			$lockingProcs = @()
			# iterate over the data lines and try to pull data out via pattern
			foreach ($line in $data) {
				# remove empty lines
				if ($line -match '^[\W\s]*$') { Write-Warning "Skipping empty line"; continue }
				
				$matchResult = [RegEx]::Match($line, $pattern)
				# if matchResult has any value, build the custom object to return
				if ($matchResult.Value) {
					$wmi = Get-WmiObject Win32_Process -Filter "ProcessId = $($matchResult.groups["PID"].value)"
					$obj = [PSCustomObject][ordered]@{
						#ProcessName    = $matchResult.groups["Name"].value
						Name    	   = $matchResult.groups["Name"].value.Substring(0, $matchResult.groups["Name"].value.LastIndexOf(".")) # truncating the extension
						PID            = $matchResult.groups["PID"].value
						ProcessPath    = $wmi.ExecutablePath # include the ExecutablePath of the process from WMI
						Commandline    = $wmi.CommandLine # include the command line of the process from WMI
						Type           = $matchResult.groups["Type"].value
						Owner 		   = $matchResult.groups["User"].value
						Path           = $matchResult.groups["Path"].value
					}
					# configure DefaultDisplayPropertySet for the custom object we made
					[string[]]$defaultProperties = "Name", "PID", "Owner", "Commandline"
					$defaultPropertySet = New-Object System.Management.Automation.PSPropertySet DefaultDisplayPropertySet, $defaultProperties
					$defaultMembers = [System.Management.Automation.PSMemberInfo[]]$defaultPropertySet
					Add-Member -InputObject $obj -MemberType MemberSet -Name PSStandardMembers -Value $defaultMembers
					# append the cusom object to the lockingProcs array
					$lockingProcs += $obj
					#Write-Verbose $($obj.pid)
				}
			}
			# if lockingProcs array size is zero, we didn't find anything
			if ($lockingProcs.Count -eq 0) {
				Write-Host -ForegroundColor Cyan "Get-LockingProcs : No matching handles found for [$path]"
			} else {
				#Write-Host "Get-LockingProcs : Found $($lockingProcs.count) processes with locks on [$path]"
				# remove duplicate entries
				$lockingProcs = ($lockingProcs | Sort-Object pid -unique)
				Write-Host -ForegroundColor Cyan "Get-LockingProcs : Found $($lockingProcs.count) unique processes with locks on [$path]"
				[array]$LockingProcs | select * | Out-String | Out-file .\$outputname -Append

				return [array]$lockingProcs | select *
			}
        } catch {
            if (!$PSitem.InvocationInfo.MyCommand) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        (New-Object "$($PSItem.Exception.GetType().FullName)" (
                                "$($PSCmdlet.MyInvocation.MyCommand.Name) : $($PSItem.Exception.Message)[0]`n`nStackTrace:`n$($PSItem.ScriptStackTrace)`n"
                            )),
                        $PSItem.FullyQualifiedErrorId,
                        $PSItem.CategoryInfo.Category,
                        $PSItem.TargetObject
                    )
                )
            } else { $PSCmdlet.ThrowTerminatingError($PSitem) }
        }
    }
	END {
		Write-Host "Output file written to: [./$outputname]"
	}
} # Get-LockingProcs