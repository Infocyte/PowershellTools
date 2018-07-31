Param(
	[Parameter(	Position = 0, 
					Mandatory = $true)]
	[ValidateScript({ 
			if ($_ -match "\.dump$") {                 #changed to dump
				if (Test-Path $_) {
					return $True
				} else {
					Write-Warning "Path does not exist"
					Throw "ERROR: Path does not exist"
				}
			} 
			elseif ($_ -notmatch "\.dump$") {         #changed to dump
				Write-Warning "$_ is not in a dump format"     #changed message
				Throw "$_ is not in dump format, this script only support version 2.11 and newer"     #changed message
			}
			else {   
				Write-Warning "$_ is not an dump file"
				Throw "$_ is not an dump file" 
			}
		})]
	[String]$Path # <path to your .dump file>
)


function CheckService($ServiceName) {
    <#
    .SYNPOSIS
    Check to see if a service is running
    .DESCRIPTION
    Check if service is running. TRUE if running. FALSE is not running.
    .PARAMETER ServiceName
    The name of the service we want to check if it is running or not
    #>
	Try 
	{
		$theService = Get-Service -Name $ServiceName
	}
	catch 
	{
		$ErrorMessage = $_.Exception.Message
		$FailedItem = $_.Exception.ItemName
		Write-Error "The service does not exist. Error message: " $ErrorMessage ". \n Failed item: " $FailedItem "."
	}
    
    if ($theService.Status -eq "Running") {
        return $True
    } elseif ($theService.Status -eq "Stopped") {
		return $False
	} else {
		Write-Host "The " $ServiceName " is not running nor is it stopped. The status is " $ServiceName.status "."
	}
}


$message  = 'WARNING: This script will overwrite any existing data within Infocyte HUNT.'
$question = 'Are you sure you want to proceed?'

$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
if ($decision -eq 0) {
  Write-Host 'Continuing'
} else {
  Write-Host 'Exiting'
  return
}

#psql is needed to drop db and create db, pgRestore is needed to restore the dump file
$psql = "C:\Program Files\Infocyte\Dependencies\Postgresql\bin\psql.exe"
$pgRestore = "C:\Program Files\Infocyte\Dependencies\Postgresql\bin\pg_restore.exe"


$PGConfig = (Get-Content "C:\Program Files\Infocyte\api\server\datasources.json" | ConvertFrom-Json).db
$username = "postgres"
$env:PGPASSWORD = $PGConfig.password

if (CheckService("huntNodeSvc") -eq $True) {
	# Stopping Infocyte Service
	Write-Host "Stopping HUNT service"
	Stop-Service huntNodeSvc
}

Write-Host "Stopping database"
&$psql -U $username -c "SELECT pg_terminate_backend( pid ) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname = 'pulse'"
Write-Host "`nDropping the pulse database in Infocyte"
&$psql -U $username -c "DROP DATABASE pulse"
Write-Host "`nCreating the pulse database in Infocyte"
&$psql -U $username -c "CREATE DATABASE pulse"
Write-Host "`nRestoring from backup: $Path"
&$pgRestore -U $username -d pulse $Path           #changed command

Write-Host "`nRestore completed.`n"

Invoke-Expression -Command .\RestartHuntServices.ps1