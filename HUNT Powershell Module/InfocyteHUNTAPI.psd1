#
# Module manifest for module 'InfocyteHUNTAPI'
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'InfocyteHUNTAPI.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'd3d4e089-48ba-47f1-963c-36a6c5b6a5c7'

# Author of this module
Author = 'Chris Gerritz'

# Company or vendor of this module
CompanyName = 'Infocyte, Inc.'

# Copyright statement for this module
Copyright = '(c) 2019 Infocyte, Inc. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Functions and Cmdlets to interface with the Infocyte HUNT API'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
  "Invoke-ICFindHosts",
  "Invoke-ICScan",
  "Invoke-ICScanTarget",
  "Import-ICSurvey",
  "Get-ICObjects",
  "Get-ICAlerts",
  "Get-ICConnections",
  "Get-ICAccounts",
  "Get-ICScripts",
  "Get-ICApplications",
  "Get-ICVulnerabilities",
  "Get-ICActivityTrace",
  "Get-ICFileDetail",
  "New-ICToken",
  "Set-ICToken",
  "New-ICTargetGroup",
  "Get-ICTargetGroups",
  "Remove-ICTargetGroup",
  "New-ICCredential",
  "Get-ICCredentials",
  "Remove-ICCredential",
  "New-ICQuery",
  "Get-ICQueries",
  "Remove-ICQuery",
  "Get-ICAddresses",
  "Remove-ICAddresses",
  "Get-ICScans",
  "Get-ICUserAuditLogs",
  "Get-ICUserTasks",
  "Get-ICBoxes",
  "Get-ICFlagColorCodes",
  "New-ICFlag",
  "Get-ICFlags",
  "Update-ICFlag",
  "Remove-ICFlag",
  "New-ICScanOptions",
  "Add-ICScanSchedule",
  "Get-ICScanSchedule",
  "Remove-ICScanSchedule",
  "Get-ICUserTaskItems",
  "Get-ICReports"
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
