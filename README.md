# PowershellTools
Useful Powershell tools and modules for operating Infocyte HUNT.

## HUNT API Powershell Module


Need to import an offline scan? Here is how you do it!

## Offline Scanning and Analysis

Surveys can be run manually on a system without connectivity. The surveys can be found in the HUNT Server's install folder C:\Program Files\Infocyte\HUNT\Surveys\ (for On-Prem) or on the Admin:Downloads page on HUNT Cloud instances.

The result file is an `.json.gz` file and will be found in the temp folder or where ever you ran the survey from.

### Using the Import-ICSurvey function to analyze offline scans

The first thing you will need are the survey results copied over from the endpoint you have scanned offline (ran survey.exe on). Once that file or set of files is available, you are ready to setup Powershell.

Download the HUNT Powershell Module folder from this repository.

Open up a Powershell terminal and import the Infocyte HUNT API Powershell Module with this command: `Import-Module .\HUNT Powershell Module\InfocyteHUNTAPI.psd1`.

NOTE: If your system is configured not to permit the execution of scripts because of a restrictive local execution policy, open Powershell in an administrative context and execute the following command: `Set-ExecutionPolicy Bypass`. Once that is complete, use the `Import-Module` command again.

Establish a session with your HUNT instance with New-ICToken function.
> New-ICToken -HuntServer https://myinstance.infocyte.com

Import the survey or set of surveys using the following command:
> Import-ICSurvey -Path C:\Surveys\surveyresult.json.gz

OR for multiple

> Get-ChildItem C:\Surveys\ -filter *.json.gz | Import-ICSurvey

Review the results by logging in to the Infocyte HUNT server and selecting the "OfflineScans" target group. You should see the results there unless you specified a specific target group or scanid in the optional perameters of Import-ICSurvey:
> Get-Help Import-ICSurvey

If anything goes wrong, feel free to email us at support@infocyte.com, and we will assist you with any of your issues in regards to this script.
