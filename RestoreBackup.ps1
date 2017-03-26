<#
.SYNOPSIS

	Purges the Infocyte database and restores from a backup.

	Project: Infocyte HUNT
	Author: Infocyte, Inc.
	License: Apache License 2.0
	Required Dependencies: Infocyte HUNT
	Optional Dependencies: None

 
.PARAMETER Path

	Path to backup .sql file.  Backups are gunzipped, recommend using 7zip to uncompress the backup first
#>

Param(
	[Parameter(	Position = 0, 
					Mandatory = $true)]
	[ValidateScript({ 
			if ($_ -match "\.sql$") {
				if (Test-Path $_) {
					return $True
				} else {
					Write-Warning "Path does not exist"
					Throw "ERROR: Path does not exist"
				}
			} 
			elseif ($_ -match "\.sql\.gz$") {
				Write-Warning "$_ is not in sql format, unzip it using 7zip first"
				Throw "$_ is not in sql format, unzip it using 7zip first"
			}
			else {
				Write-Warning "$_ is not an sql file"
				Throw "$_ is not an sql file" 
			}
		})]
	[String]$Path # <path to your .sql file>
)

Write-Warning "WARNING: This script will overwrite any existing data within Infocyte."

$psql = "C:\Program Files\Infocyte\Dependencies\Postgresql\bin\psql.exe"
<# 
$creds = Get-Credential "postgres"
$username = $creds.Username
$env:PGPASSWORD = $creds.GetNetworkCredential().Password
#>
# Grab postgres password from config file
$PGConfig = (gc "C:\Program Files\Infocyte\Hunt-UI-Server\server\datasources.json" | ConvertFrom-Json).db
$username = "postgres"
$env:PGPASSWORD = $PGConfig.password
$database = $PGConfig.database


&$psql -U $username -c "SELECT pg_terminate_backend( pid ) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname = 'pulse'"
Write-Verbose "Dropping the pulse database in Infocyte"
&$psql -U $username -c "DROP DATABASE pulse"
Write-Verbose "Creating the pulse database in Infocyte"
&$psql -U $username -c "CREATE DATABASE pulse"
Write-Verbose "Restoring from backup: $Path"
&$psql -U $username -d pulse -f $Path

