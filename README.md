# PowershellTools
Useful Powershell tools and modules for operating Infocyte HUNT.

## HUNT API Powershell Module

Contains API wrappers for interfacing and controlling Infocyte in Powershell. Also has extension development/testing utilities.
Open up a Powershell terminal and install the Infocyte HUNT API Powershell Module with this command:

> PS> Install-Module -Name InfocyteHUNTAPI

OR

> PS> Update-Module -Name InfocyteHUNTAPI


## Agent Deployment

To simplify deployment of Infocyte agents to windows boxes, there is a Powershell 1-liner that can be used to deploy and configure agents. Only requirement is Powershell 2.0 (Windows 7+ by default) and Admin rights.


## Network Diagnostic Script

This function will help you test and troubleshoot network problems and remote execution problems for agentless scans.
Open up a Powershell terminal and install the Infocyte network diagnostic with this command:

> PS> Install-Module -Name InfocyteNetworkTest  
> PS> Test-ICNetworkAccess -Target 10.0.0.1 -Credential <PSCredential>
