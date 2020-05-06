[![latest version](https://img.shields.io/powershellgallery/v/InfocyteHUNTAPI.svg?label=latest+version)](https://www.powershellgallery.com/packages/InfocyteHUNTAPI)

# Infocyte HUNT API Module
Used to interface with the Infocyte API. Anything you can do in the interface can also be done with Powershell.
Tested on Powershell Version: 5.0

## Getting Started

#### Step 1: Install the module:
> PS> Install-Module -Name InfocyteHUNTAPI

Or Update the module:
> PS> Update-Module -Name InfocyteHUNTAPI

#### Step 2: Create an API Token
Create an API token in the Web Console within your profile or admin panel.

#### Step 3: Save your Token into Powershell
Use Set-ICToken to register your Infocyte instance or HUNT server with this API token. This will store your login token and server into a global variable for use by the other commands.
Example:
> PS> Set-ICToken -Instance alpo1 -Token ASASDFASDFSASDF12123 -Save

- Instance name is the first part of your address: https://alpo1.infocyte.com only requires `alpo1`


## Use the Module
If installed, just load up the Instance you want to interact with in your Powershell session using `Set-ICToken`.
> PS> Set-ICToken -Instance alpo1

### Retrieving Data and Interacting with Boxes
Raw data within Infocyte is either an event or forensic object (we call these instances). There are three pre-compiled aggregations of these events we call boxes that normalizes data (i.e. unique by hash+path) and calculates stats for the trailing 7, 30, and 90 days globally and for each target group. By default, getting data using a function like `Get-ICObject` will target the `Global Last 7 Day` box.  
**Setting the default box:**  
> PS> Set-ICBox -Global -Last 7  

OR  
> PS> $TG = Get-ICTargetGroup | where { $_.name -eq "Target Group 1" }  
> PS> Set-ICBox -TargetGroupId $TG.Id -Last 30


**Getting Data:**  
> $artifacts = Get-ICObject -Type Artifact -NoLimit

Data Export Functions:  
Data is currently seperated by object type though that will change in 2020. All the object and event data can be grabbed with `Get-ICObject` with a reference to object type. Apps and Vulns are treated a little differently so have their own functions.  

	Get-ICObject
	Get-ICApplication
	Get-ICVulnerability
	
Individual file reputation data can be grabbed for a file (by sha1) by using the following function:  
	
	Get-ICFileDetail


#### Filters
Filters on this API are constructed using LoopBack specifications/format. The module will convert the hashtable below into the json ingested by Loopback but you will need to use Loopback operators. 
https://loopback.io/doc/en/lb3/Where-filter.html#operators  

> PS> $whereFilter = @{ threatName = @{ regexp = "Unknown|Suspicious|Bad" } }  
> PS> $whereFilter += @{ commentCount = 0 }

> PS> Get-ICObject -Type File -where $whereFilter  

NOTE: While you can use Powershell piping to filter after retrieval, it is not recommended. the `-where` Loopback filter will be applied server-side which conserves bandwidth and avoids potential throttling.


### Target Group & Query Management
Target Groups are logical grouping of hosts and related data that you see in the Discover Tab in the Infocyte app. Each Target Group has an Address table listing hosts that have been discovered or agents that have been added to each Target Group.  

	New-ICTargetGroup, Get-ICTargetGroup, Remove-ICTargetGroup
	Get-ICAddress, Remove-ICAddress
	
Queries are used in Agentless discovery and will typically utilize a network credential from the credential store. Queries can be IP Ranges, hostnames, ldap queries, or aws queries.  

	New-ICCredential, Get-ICCredential, Remove-ICCredential
	New-ICQuery, Get-ICQuery, Remove-ICQuery
	
### Scan and Activity Status
Scans and other activity are tracked as a task. Each task can have multiple items (typically hosts) that action will iterate through. Individual item/host progress will also be tracked and can be grabbed using `Get-ICTaskItemProgress` with a reference to the TaskItemId.  
    Get-ICTask, Get-ICTaskItem, Get-ICTaskItemProgress

### Scanning
Scanning and enumerating is usually by Target Group so will require a TargetGroupId reference. 

**Enumerate:**  
	
	Invoke-ICFindHosts
	
**Scan:**  

	New-ICScanOptions
	Invoke-ICScan (by Target Group), Invoke-ICScanTarget (single target by IP/hostname)

**Schedule:**  
	
	Add-ICScanSchedule (w/ CronExpression), Get-ICScanchedule, Remove-ICScanSchedule

**Importing Offline Scans:**  

	Import-ICSurvey
