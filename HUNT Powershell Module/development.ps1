# For Extension Developers
function Invoke-ICExtension ($Path) {
	Clear
    $Devpath = "C:\Program Files\Infocyte\dev"
    if (Test-Path "$DevPath\s1.exe") {
        $Ver = & "$DevPath\s1.exe" "--version"
    	Write-Verbose "Executing extension with s1.exe Version: $Ver"
    } else {
        Write-Error "$Devpath not found! Cannot run extension"
        Write-Warning "Download the latest survey (s1.exe) for your platform and copy it to this path."
        if (Test-Path "C:\Program Files\Infocyte\Agent\s1.exe") {
            $Ver2 = & "C:\Program Files\Infocyte\Agent\s1.exe" "--version"
            Write-Warning "You can also find the latest version ($Ver2) within your agent folder (C:\Program Files\Infocyte\Agent\)."
        }
    }

	# & "s1.exe --no-delete --no-compress --verbose --only-extensions --extensions $Path"
	$a = @()
	$a += "--no-delete"
	$a += "--no-compress"
	$a += "--verbose"
	$a += "--only-extensions"
	$a += "--extensions $Path"
	Start-Process -NoNewWindow -FilePath "$Devpath\s1.exe" -ArgumentList $a
}
