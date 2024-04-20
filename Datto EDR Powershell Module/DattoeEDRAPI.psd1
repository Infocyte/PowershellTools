#
# Module manifest for module 'InfocyteHUNTAPI'
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'DattoEDRAPI.psm1'

# Version number of this module.
ModuleVersion = '3.0.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'd3d4e089-48ba-47f1-963c-36a6c5b6a5c7'

# Author of this module
Author = 'Chris Gerritz'

# Company or vendor of this module
CompanyName = 'Datto, Inc.'

# Copyright statement for this module
Copyright = '(c) 2023 Datto, Inc. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Functions and Cmdlets to interface with the Datto EDR API'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

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
    "Convert-ICExtensionHeader",
    "Set-ICToken",
    "Get-ICAPI",
    "Invoke-ICAPI",
    #"Invoke-ICFindHosts",
    "Invoke-ICScan",
    "Invoke-ICScanTarget",
    "Invoke-ICResponse",
    "Import-ICSurvey",
    "Get-ICEvent",
    "Get-ICResponseResult",
    "Get-ICHostScanResult",
    "Get-ICAlert",
    "Get-ICApplication",
    "Get-ICVulnerability",
    #"Get-ICActivityTrace",
    "Get-ICFileDetail",
    "Get-ICNote",
    "New-ICToken",
    "New-ICTargetGroup",
    "Get-ICTargetGroup",
    "Remove-ICTargetGroup",
    #"New-ICControllerGroup",
    #"Get-ICControllerGroup",
    #"Remove-ICControllerGroup",
    #"New-ICCredential",
    #"Get-ICCredential",
    #"Remove-ICCredential",
    #"New-ICQuery",
    #"Get-ICQuery",
    #"Remove-ICQuery",
    "Get-ICAddress",
    "Remove-ICAddress",
    "Get-ICScan",
    "Get-ICAuditLog",
    "Get-ICJob",
    "Add-ICComment",
    "Get-ICTask",
    "Get-ICTaskItems",
    "Get-ICLastScanTask",
    "Get-ICFlagColors",
    "New-ICFlag",
    "Get-ICFlag",
    "Update-ICFlag",
    "Remove-ICFlag",
    "New-ICScanOptions",
    #"Add-ICScanSchedule",
    #"Get-ICScanSchedule",
    #"Remove-ICScanSchedule",
    "Get-ICReport",
    "Get-ICHelp",
    "New-ICExtension",
    "Get-ICExtension",
    "Update-ICExtension",
    "Remove-ICExtension",
    "Import-ICExtension",
    "Test-ICExtension",
    "Get-ICAgent",
    "Remove-ICAgent",
    "Get-ICDwellTime",
    "Get-ICRule",
    "New-ICRule",
    "Import-ICRule",
    "Update-ICRule",
    "Remove-ICRule"
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

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
        ReleaseNotes = 'Changed name from Infocyte to Datto EDR'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}