###
#  This script is responsible for restoring a the Infocyte HUNT database from a DUMP file. 
#  It purges the Infocyte pulse DB and replaces it with a new one, then cycles all of the services. 
#
# - This script needs to be run with elevated security privledges (administrator security context)
# - This script requires PowerShell 3.0. It will not work with 2.9 and older.
###
# PARAMETERS
# Param needs to be the first line of the script
#
Param(
	[Parameter(	Position = 0, 
					Mandatory = $false)]
    [String]$dbPw  # DB Password
)
###
# Confirmation Box
# Because this script overwrites data, have left in the warning box to make sure users actually want to proceed
# This was ooriginal and unmodified. 
###
$message  = 'WARNING: This script will remove all user accounts within Infocyte.'
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

# Variable for psql is needed to executs sql commands
$psql = "C:\Program Files\Infocyte\Dependencies\Postgresql\bin\psql.exe"

#Add hard coded password option and is found in C:\Program Files\Infocyte\api\server\datasources.json
if($dbPw.Equals("")){
    $dbpw = ""                        #this is the where you can hard-code the password to the database
}

#Get the datasources configurations loaded into object
$PGConfig = (Get-Content "C:\Program Files\Infocyte\api\server\datasources.json" | ConvertFrom-Json).db

#Get the password for the postgres account from the datasources.json file only if doesn't exist
if($dbPw.Equals("")){
    $username = "pulse"
    $env:PGPASSWORD = $PGConfig.password
}else{
    $env:PGPASSWORD = $dbPw
}

#Get the target database
$database = $PGConfig.database

#Do the sql deletions
Write-Host "Deleting users and relations..."

& $psql -U $username -c "DELETE FROM public.useridentity"
& $psql -U $username -c "DELETE FROM public.role"
& $psql -U $username -c "DELETE FROM public.rolemapping"

#Restart the node service
Write-Host "Restarting Node Service"
Restart-Service huntNodeSvc

#Let them know it's finisheds
Write-Host "Finished"