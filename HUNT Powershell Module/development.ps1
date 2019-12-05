# For Extension Developers
function Invoke-ICExtension {
	param(
		[parameter(mandatory=$true)]
	  	[String]$Path,

	  	[Switch]$Compress
  	)

	Clear
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
		$ext = (get-item $Path).name
    	Write-Host "Executing $ext with s1.exe (Version: $Ver)"
    } else {
        Write-Error "$Devpath not found! Cannot run extension"
        Write-Warning "Download the latest survey (s1.exe) for your platform and copy it to $Devpath"
        if (Test-Path "C:\Program Files\Infocyte\Agent\s1.exe") {
            $Ver2 = & "C:\Program Files\Infocyte\Agent\s1.exe" "--version"
            Write-Warning "You can also find the latest version ($Ver2) within your agent folder (C:\Program Files\Infocyte\Agent\)."
        }
    }

	# & "s1.exe --no-delete --no-compress --verbose --only-extensions --extensions $Path"
	$a = @()
	$a += "--no-delete"
	if (-NOT $Compress) { $a += "--no-compress" }
	$a += "--verbose"
	$a += "--only-extensions"
	$a += "--extensions $Path"
	Start-Process -NoNewWindow -FilePath "$Devpath\s1.exe" -ArgumentList $a
}
