# PowershellTools
Useful Powershell Tools for operating or testing Infocyte HUNT.

Need to import an offline scan? Here is how you do it!

## Offline Scanning and Analysis

### Using the Powershell Import Tool

The first thing you will need are the survey results copied over from the endpoint you have scanned offline. The file is an `.iclz` file, and it should be named like so: `[domain or computer name]_[account name].json.iclz`.

Once that file is available on the Hunt server, you are ready to setup the Powershell scripts.

Open up a Powershell terminal with administrative permissions. Download the `InfocyteAPIFunctions.ps1` and `Import-HuntICLZs.ps1` files from this repository and place them in a folder. Additionally, created a folder named `surveys` on the Hunt server in the same directory as the `.ps1` files you have downloaded. Drop your surveys into the `surveys` folder.

Next, you will need to import the `InfocyteAPIFunctions.ps1` file with this command: `Import-Module .\InfocyteAPIFunctions.ps1`.

If your Hunt server is configured not to permit the execution of scripts because of a restrictive local execution policy, open Powershell in an administrative context and execute the following command: `Set-ExecutionPolicy Bypass`. Once that is complete, use the `Import-Module` command again.

The `Import-HuntICLZs.ps1` script has several parameters, of which three are necessary to pass in to function correctly.

| Parameter | Description |
|-----------|-------------|
| -path   | The local windows folder that has the ICLZ survey files that are going to be imported |
| -TargetListName | The target list/group that the endpoints will be added to. The default value is "OfflineScans" and can be changed in the script itself. |
| -HuntServer  | The base URL of the Infocyte HUNT Server portal. The default value is "https://localhost:4443" and can be changed in the script itself. |
| -HuntCredential | The credentials are the local Infocyte HUNT login credentials. |
| -ScanCredential | The credentials are a local workstation, or domain account, that is a member of the local administrator group. |

To get the credentials for the local Infocyte HUNT login and to the local workstation or domain account, you can use these commands to store them in a variable.

```powershell
$HuntCredential = Get-Credential
$ScanCredential = Get-Credential
# Credential window will pop up
# Enter credentials for both according to the table above
```

If joined to a domain, enter a domain account that is a member of the local administrators' group. If not joined to a domain, enter a local account that is a member of the local administrators' group. Remember, the format is `[domain]\[accountName]` or `[machineName]\[accountName]`.

Run the command to begin the import: `.\Import-HuntICLZs.ps1 -Path ".\surveys\" -HuntCredential $HuntCredential -ScanCredential $ScanCredential`.

Upon execution, the following text (or similar) should appear in the PowerShell Prompt. 

```
Connecting https://localhost:4443 using account infocyte 
Login successful to https://localhost:4443 
Login Token id: QRCSo7vCUJGhREaWAwbTAeyU594AkfDCD119Qve6D7m55c05lgBiwKIeVJmHGlXB
Copying .iclz files to temp directory: C:\Program Files\Infocyte\Hunt\uploads\tempf0bd940e-af7f-47d6-a027-a51d0dcfb692 
Retrieving Last Job and ScanId 
Last Folder name: tempf0bd940e-af7f-47d6-a027-a51d0dcfb692 
Last Active ScanId: NO_SCAN 
Initiating Scan of localhost 
WARNING: No Active Scan! Waiting for scan to be initiated... 
WARNING: No Active Scan! Waiting for scan to be initiated...
```

When the warning about no active scans begin to appear, the process has been completed and there are no further scans to consume.

Remove the scans from the surveys directory - these will not automatically be deleted and removal ensures that they are not accidentally imported more than once.

Review the results by logging in to the Infocyte HUNT server and selecting the "OfflineScans" target group data. You should see the results there.

If anything goes wrong, feel free to email us at support@infocyte.com, and we will assist you with any of your issues in regards to this script.