# For Extension Developers
function Test-ICExtension {
	[cmdletbinding()]
	[alias("Invoke-ICExtension")]
	param(
		[parameter(mandatory=$true)]
	  	[String]$Path,

	  	[Switch]$Compress
  	)

	# Clear-Host
    $Devpath = "C:\Program Files\Infocyte\dev"
	$AgentPath = "C:\Program Files\Infocyte\Agent\"
    if (Test-Path "$DevPath\s1.exe") {
        $Ver = (& "$DevPath\s1.exe" "--version").split(" ")[2]
		if (Test-Path "$AgentPath\s1.exe") {
			$Ver2 = (& "$AgentPath\s1.exe" "--version").split(" ")[2]
			if ($ver2 -gt $ver) {
				Write-Warning "s1.exe ($ver) has an update: ($Ver2). Copy s1.exe from $AgentPath\s1.exe to $Devpath\s1.exe to update this function."
			}
		}
		$Path = Get-item $Path | Select-Object -ExpandProperty FullName
		$ext = Get-item $Path | Select-Object -ExpandProperty name
    	Write-Verbose "Executing $ext with s1.exe (Version: $Ver)"
    } else {
        Write-Error "$Devpath not found! Cannot run extension"
        Write-Warning "Download the latest survey (s1.exe) for your platform and copy it to $Devpath"
        if (Test-Path "C:\Program Files\Infocyte\Agent\s1.exe") {
            $Ver2 = & "C:\Program Files\Infocyte\Agent\s1.exe" "--version"
            Write-Warning "You can also find the latest version ($Ver2) within your agent folder (C:\Program Files\Infocyte\Agent\)."
        }
		return
    }

	# & "s1.exe --no-delete --no-compress --verbose --only-extensions --extensions $Path"
	$a = @()
	$a += "--no-delete"
	if (-NOT $Compress) { $a += "--no-compress" }
	$a += "--no-results-file"
	$a += "--no-log-file"
	$a += "--no-events"
	$a += "--only-extensions"
	$a += "--extensions $Path"
	
	#$p = Start-Process -NoNewWindow -FilePath "$Devpath\s1.exe" -ArgumentList $a -PassThru
	
	$psi = New-object System.Diagnostics.ProcessStartInfo
	$psi.CreateNoWindow = $true
	$psi.UseShellExecute = $false
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $false
	$psi.FileName = "$Devpath\s1.exe"
	$psi.Arguments = $a
	$process = New-Object System.Diagnostics.Process
	$process.StartInfo = $psi
	$process.Start() | Out-Null
	#$process.WaitForExit()

	$line = $process.StandardOutput.ReadLine()
	$output = "`n$line"
	while ($line) {
		$line = $process.StandardOutput.ReadLine()
		$output += "`n$line"
		
		$reg1 = $line | select-string -Pattern "\d{4}-\d+-\d+T\d+:\d+:\d+\.\d+-\d+:\d+\s(!?.+)\ssurvey_types::response\s- (.+)"
		$reg2 = $line | select-string -Pattern "^[^\d]{4}" 
		if ($reg1) {
			Write-Output "[$($reg1.Matches.Groups[1].Value)] $($reg1.Matches.Groups[2].Value)"
		} 
		elseif ($reg2) {
			Write-Output "[] $line"
		}
	}
	Write-debug $output
}
