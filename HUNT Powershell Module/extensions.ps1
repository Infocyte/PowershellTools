
function Get-ICExtension {
    [cmdletbinding(DefaultParameterSetName="List")]
    Param(
        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ParameterSetName='Id')]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('extensionId')]
        [String]$Id,

        [parameter(
            ParameterSetName='Guid')]
        [String]$Guid,
        
        [parameter(
            ParameterSetName='Id')]
        [parameter(
            ParameterSetName='Guid')]
        [Parameter(
            ParameterSetName='List')]
        [Switch]$IncludeBody,

        [parameter(
            ParameterSetName='List',
            HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},

        [parameter(
            ParameterSetName='List')]
        [Switch]$NoLimit,

        [parameter(
            ParameterSetName='List')]
        [Switch]$CountOnly,

        [Parameter(
            ParameterSetName='Id',
            HelpMessage = "Filepath and name to save extension to. Recommending ending as .lua")]
        [ValidateScript( { Test-Path -Path $_ -IsValid })]
        [String]$SavePath
    )

    PROCESS {

        if ($Id) {
            Write-Verbose "Looking up extension by Id."
            $Endpoint = "extensions/$Id"
            $ext = Get-ICAPI -Endpoint $Endpoint -ea 0
            if (-NOT $ext) {
                Write-Warning "Could not find extension with Id: $($Id)"
                return
            }
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName guid -NotePropertyValue $ext.description

            $ext2= Get-ICAPI -Endpoint "$Endpoint/LatestVersion" -fields body, sha256
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName body -NotePropertyValue $ext2.body
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName sha256 -NotePropertyValue $ext2.sha256
            Write-Verbose "Parsing Extension Header"
            $header = Parse-ICExtensionHeader $ext.body
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptGuid -NotePropertyValue $header.guid
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptName -NotePropertyValue $header.name
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptDescription -NotePropertyValue $header.Description
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptAuthor -NotePropertyValue $header.author
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptCreated -NotePropertyValue $header.created
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptUpdated -NotePropertyValue $header.updated
            Write-Verbose "Looking up user: $($ext.createdBy) and $($ext.updatedBy)"
            $ext.createdBy = (Get-ICAPI -endpoint users -where @{ id = $ext.createdBy } -fields email -ea 0).email
            $ext.updatedBy = (Get-ICAPI -endpoint users -where @{ id = $ext.updatedBy } -fields email -ea 0).email
            if ($SavePath) {
                $ext.body | Out-File $SavePath | Out-Null
            }
            Write-Output $ext

        } 
        elseif ($Guid) {
            Write-Verbose "Looking up extension by Guid."
            $Endpoint = "extensions"
            $ext = Get-ICAPI -Endpoint $Endpoint -where @{ description = $Guid } -fields Id -ea 0
            <#
                        $ext.id | ForEach-Object {
                $body = Get-ICAPI -Endpoint "$Endpoint/$_" -fields body -ea 0
                if ($body.contains($Guid)) {
                    return Get-ICExtension -Id $_ -IncludeBody
                }
            #>
            if ($ext) {
                return $ext
            } else {
                Write-Warning "Could not find extension with Guid: $($Guid)"
                return
            }
            
        }
        else {
            $Endpoint = "extensions"
            $ext = Get-ICAPI -Endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
            if ($CountOnly) { return $ext }
            $n = 1
            if ($ext -eq $null) { $c = 0}
            elseif ($ext.count -eq $null) { $c = 1}
            else { $c -eq $ext.count }
            $ext | ForEach-Object {
                try { $pc = [math]::Floor(($n/$c)*100) } catch { $pc = -1 }
                $guid = $_.description
                Write-Progress -Activity "Getting Extentions from Infocyte API" -status "Requesting Body from Extension $n of $c" -PercentComplete $pc
                $_ | Add-Member -TypeName NoteProperty -NotePropertyName guid -NotePropertyValue $guid
                if ($IncludeBody) {
                    Write-Output (Get-ICExtension -id $_.Id)
                } else {
                    Write-Verbose "Looking up user: $($_.createdBy) and $($_.updatedBy)"
                    $_.createdBy = (Get-ICAPI -endpoint users -where @{ id = $_.createdBy } -fields email).email
                    $_.updatedBy = (Get-ICAPI -endpoint users -where @{ id = $_.updatedBy } -fields email).email
                    Write-Output $_
                }
                $n += 1
            }
            Write-Progress -Activity "Getting Extentions from Infocyte API" -status "Complete" -Completed
        }
    }
}
function New-ICExtension {
	[cmdletbinding()]
	param(
		[parameter(mandatory=$true)]
		[String]$Name,
        
        [Parameter()]
        [String]$Author,

        [Parameter()]
        [String]$Description,

		[Parameter()]
		[ValidateSet(
          "Collection",
          "Action"
        )]
        [String]$Type = "Collection",

        [Parameter(HelpMessage="Filepath and name to save new extension to. Recommending ending as .lua")]
        [ValidateScript({ Test-Path -Path $_ -IsValid })]
        [String]$SavePath
	)
	
	$CollectionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/master/examples/collection_template.lua"
	$ActionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/master/examples/action_template.lua"

	if ($Type -eq "Collection"){
		$template = (new-object Net.WebClient).DownloadString($CollectionTemplate)
	} else {
		$template = (new-object Net.WebClient).DownloadString($ActionTemplate)
    }
    
    $template = $template -replace '(?si)(?<start>^--\[\[.+?Name:\s)(?<field>.+?)(?<end>\n)', "`${start}$name`${end}"
    $template = $template -replace '(?si)(?<start>^--\[\[.+?Author:\s)(.+?)(?<end>\n)', "`${start}$Author`${end}"
    $template = $template -replace '(?si)(?<start>^--\[\[.+?Description:\s)([^|].+?|\|.+?\|)(?<end>\n)', "`${start}| $Description |`${end}"
    $template = $template -replace '(?si)(?<start>^--\[\[.+?Guid:\s)(.+?)(?<end>\n)', "`${start}$([guid]::NewGuid().guid)`${end}"
    $currentdate = Get-Date
    $dt = "$($currentdate.Year)$($currentdate.Month)$($currentdate.Day)"
    $template = $template -replace '(?si)(?<start>^--\[\[.+?Created:\s)(.+?)(?<end>\n)',"`${start}$dt`${end}"
    $template = $template -replace '(?si)(?<start>^--\[\[.+?Updated:\s)(.+?)(?<end>\n)',"`${start}$dt`${end}"
    
    
    if ($SavePath) {
        Write-Host "`nCreated $Type extension from template and saved to $SavePath"
        $template | Out-File -FilePath $SavePath
        return $true
    }
    else {
        return $template
    }    
}
function Import-ICExtension {
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ParameterSetName = 'Path',
            ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Path, # path to extension file

        [parameter(
            mandatory = $true,
            ParameterSetName  = 'String'
        )]
        [ValidateNotNullorEmpty()]
        [String]$Body,

        [parameter(
            mandatory=$false,
            ParameterSetName  = 'String'
        )]
        [String]$Name,

        [parameter(
            mandatory=$false,
            ParameterSetName  = 'String'
        )]
        [ValidateSet("collection","action", $null)]
        [String]$Type,

        [Switch]$Active,

        [Switch]$Force
    )

    PROCESS {
        $Endpoint = "extensions"
        $postbody = @{}
        if ($Active) {
            $postbody['active'] = $true
        } else {
            $postbody['active'] = $false
        }

        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Write-Verbose "Testing path: $Path"
            if (Test-Path $Path) {
                Write-Verbose "Using filename for Extension Name."
                $Body = Get-Content $Path -Raw
            } else {
                Write-Error "$Path does not exist!"
                return
            }
        }

        $postbody['body'] = $Body
        $header = Parse-ICExtensionHeader $Body
        if (-NOT $header.name -OR -NOT $header.type) { 
            Write-Warning "Extension Header is incomplete. Recommend using a template header" 
        }
        
        if ($Name) {
            $postbody['name'] = $Name 
        } 
        elseif ($header.name) {
            $postbody['name'] = $header.name 
        }
        else {
            Write-Warning "Name not provided or found in header. Aborting import."
            return
        }

        if ($Type) {  
            $postbody['type'] = $Type
        }
        elseif ($header.type) {
            $postbody['type'] = ([string]$header.type).toLower()
        } 
        else {
            Write-Verbose "Type not provided or found in header. Defaulting to action extension."
            $postbody['type'] = 'action'
        }

        if ($header.guid) {
            $postbody['description'] = $header.guid
        }

        if ($header.guid) {
            $ext = Get-ICExtension -Guid $header.guid -WarningAction 0
            if ($ext) {
                if (-NOT $Force) {
                    Write-Warning "There is already an existing extension named $($ext.name) [$($ext.Id)] with guid $($ext.guid). Try using Update-ICExtension or use -Force flag."
                    return
                }
                Write-Warning "There is already an existing extension named $($ext.name) [$($ext.Id)] with guid $($ext.guid). Forcing update."
                $postbody['id'] = $ext.id
            } 
        }
        else {
            Write-Verbose "Adding new Extension named: $($postbody['name'])"
        }
        $ext = Invoke-ICAPI -Endpoint $Endpoint -body $postbody -method POST
        Write-Verbose "Looking up user: $($ext.createdBy) and $($ext.updatedBy)"
        $ext.createdBy = (Get-ICAPI -endpoint users -where @{ id = $ext.createdBy } -fields email -ea 0).email
        $ext.updatedBy = (Get-ICAPI -endpoint users -where @{ id = $ext.updatedBy } -fields email -ea 0).email
        if ($ext.Description -match $GUID_REGEX) {
            $ext | Add-Member -Type NoteProperty -Name guid -Value $ext.Description
        }
        Write-Output $ext
    }
}

function Update-ICExtension {
    <#
        Updates an existing extension with a new body from a file or string.
    #>
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(
            mandatory=$false,
            ParameterSetName = 'Path'
        )]
        [parameter(
            mandatory=$false,
            ParameterSetName  = 'String'
        )]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('extensionId')]
        [String]$Id,

        [parameter(
            Mandatory = $true,
            ParameterSetName = 'Path',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [alias('FullName')]
        [string]$Path, # <paths of the survey results (.bz2) files to upload>

        [parameter(
            mandatory = $true,
            ParameterSetName  = 'String'
        )]
        [ValidateNotNullorEmpty()]
        [String]$Body
    )
    
    PROCESS {
        $Endpoint = "extensions"
        $postbody = @{}

        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Write-Verbose "Getting Script body from $Path"
            if (Test-Path $Path) {
                $Body = Get-Content $Path -Raw 
            } else {
                Write-Warning "$Path does not exist!"
                return
            }
        }

        $header = Parse-ICExtensionHeader $Body
        Write-Verbose "Extension Header:`n$($header | ConvertTo-Json)"
        $postbody['body'] = $Body
        $postbody['name'] = $header.name
        $postbody['type'] = $header.Type
        $postbody['description'] = $header.Guid

        if ($Id) {
            Write-Verbose "Looking up extension by Id"
            $ext = Get-ICExtension -id $Id
            if ($ext) {
                Write-Verbose "Extension found: `n$($ext | ConvertTo-Json)"
                $postbody['id'] = $Id
                $postbody['active'] = $ext.active
                if (-NOT $postbody['name']) { $postbody['name'] = $ext.name }
                if (-NOT $postbody['type']) { $postbody['type'] = $ext.type }
                if (-NOT $postbody['description']) { $postbody['description'] = $ext.description }
                if ($ext.guid -AND ($header.guid -ne $ext.guid)) {
                    Write-Warning "Extension Guids do not match. Cannot be updated, try importing the new extension!`nCurrent: $($ext.guid)`nNew: $($header.guid)"
                    return
                }
            } else {
                Write-Warning "Extension with id $id not found!"
                return
            }
        } 
        else {
            Write-Verbose "Looking up extension by Guid"
            $ext = Get-ICExtension -Guid $header.guid -IncludeBody -ea 0
            if ($ext) {
                $header2 = Parse-ICExtensionHeader $Body
                Write-Verbose "Founding existing extension with matching guid ($header.guid). Updating id $($ext.id)"
                $postbody['id'] = $ext.id
                if (-NOT $postbody['name']) { $postbody['name'] = $ext.name }
                if (-NOT $postbody['type']) { $postbody['type'] = $ext.type }
                if (-NOT $postbody['description']) { $postbody['description'] = $header2.description }
            } 
            else {
                Write-Warning "Could not find existing extension with Guid: $($header.guid)"
                return
            }
        }
        Write-Verbose "Updating Extension: $($ext['name']) [$($ext.id)] with `n$($postbody|convertto-json)"
        if ($PSCmdlet.ShouldProcess($($ext.name), "Will update extension $($postbody['name']) [$postbody['id'])]")) {
            $ext = Invoke-ICAPI -Endpoint $Endpoint -body $postbody -method POST
            Write-Verbose "Looking up user: $($ext.createdBy) and $($ext.updatedBy)"
            $ext.createdBy = (Get-ICAPI -endpoint users -where @{ id = $ext.createdBy } -fields email -ea 0).email
            $ext.updatedBy = (Get-ICAPI -endpoint users -where @{ id = $ext.updatedBy } -fields email -ea 0).email
            if ($ext.Description -match $GUID_REGEX) {
                $ext | Add-Member -Type NoteProperty -Name guid -Value $ext.Description
            }
            Write-Output $ext
        }
    }
}
function Remove-ICExtension {
    [cmdletbinding(DefaultParameterSetName = 'Id', SupportsShouldProcess=$true)]
    Param(
        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Id')]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [alias('extensionId')]
        [String]$Id,

        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'guid')]
        [ValidateNotNullorEmpty()]
        [String]$Guid
    )
    PROCESS {
        if ($Id) {
            $Endpoint = "extensions/$Id"
            $ext = Get-ICExtension -id $Id
            if (-NOT $ext) {
                Write-Error "Extension with id $id not found!"
                return
            }
        } else {
            $Endpoint = "extensions"
            $ext = Get-ICExtension -Guid $Guid
            if (-NOT $ext) {
                Write-Error "Extension with guid $Guid not found!"
                return
            }
        }
        
        if ($PSCmdlet.ShouldProcess($($ext.Id), "Will remove $($ext.name) with extensionId '$($ext.Id)'")) {
            if (Invoke-ICAPI -Endpoint $Endpoint -method DELETE) {
                Write-Verbose "Removed extension $($ext.name) [$($ext.Id)]"
                return $true
            } else {
                Write-Error "Extension $($ext.name) [$($ext.Id)] could not be removed!"
            }
        }
    }
}

function Import-ICOfficialExtensions {
    [cmdletbinding()]
    Param(
        [Switch]$IncludeContributed,
        [Switch]$Update
    )

    $InstanceExtensions = Get-ICExtension -IncludeBody -NoLimit
    Write-Verbose "Pulling Official Extensions from Github: https://api.github.com/repos/Infocyte/extensions/contents/official/"
    try {
        $Extensions = Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/collection" | Select-Object -ExpandProperty content | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not download extensions from https://api.github.com/repos/Infocyte/extensions/contents/official/collection"
    }
    try {
        $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/action" | Select-Object -ExpandProperty content | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not download extensions from https://api.github.com/repos/Infocyte/extensions/contents/official/action"
    }
    If ($IncludeContributed) {
        Write-Verbose "Pulling Official Extensions from Github: https://api.github.com/repos/Infocyte/extensions/contents/contrib/"
        try {
            $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/contrib/collection" | Select-Object -ExpandProperty content | ConvertFrom-Json
        }
        catch {
            Write-Warning "Could not download extensions from https://api.github.com/repos/Infocyte/extensions/contents/contrib/collection"
        }
        try {
            $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/contrib/action" | Select-Object -ExpandProperty content | ConvertFrom-Json
        }
        catch {
            Write-Warning "Could not download extensions from https://api.github.com/repos/Infocyte/extensions/contents/contrib/action"
        }
    }
    $Results = @()
    $Extensions | ForEach-Object {
        $filename = ($_.name -split "\.")[0]
        try {
            $ext = (new-object Net.WebClient).DownloadString($_.download_url)
        } catch {
            Write-Warning "Could not download extension. [$_]"
            continue
        }
        try {
            $header = Parse-ICExtensionHeader $ext
        } catch {
            Write-Warning "Could not parse header on $($filename)"; 
            continue
        }       
        $existingExt = $InstanceExtensions | Where-Object { $_.guid -eq $header.guid }
        if ($existingExt) {
            if ($Update) {
                Write-Verbose "Updating extension $($header.name) [$($existingExt.id)] with guid $($header.guid):`n$existingExt"
                Update-ICExtension -Id $existingExt.id -Body $ext | Select-Object id, name, type, guid, active, versionCount    
            }
            else {
                Write-Warning "Extension $($header.name) [$($existingExt.id)] with guid $($header.guid) already exists. Try using -Update to update it."
            }
        } else {
            Write-Verbose "Importing extension $($header.name) [$($header.Type)] with guid $($header.guid)"
            Import-ICExtension -Body $ext -Active -Type $header.Type -Force:$Force | Select-Object id, name, type, guid, active, versionCount    
        }
    }
}

# For Extension Developers
function Test-ICExtension {
	[cmdletbinding()]
	[alias("Invoke-ICExtension")]
	param(
	    [parameter(mandatory=$true)]
        [String]$Path,
        
        [Switch]$Legacy
    )

    $LoggingColor = 'Green'
      	  
	If ($env:OS -match "windows" -AND (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
		Throw "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    } elseif ($IsLinux -AND (id -u) -ne 0) {
        Throw "You do not have permissions to run this script!`nPlease re-run this with sudo!"
    }

    if (-NOT (Test-Path $Path)) {
        Throw "$Path not found"
    }
    
    # Clear-Host
    if ($Legacy){
        $agentname = "s1.exe"
    }
    else {
        $agentname = "agent.exe"
    }
    if ($IsWindows -OR $env:OS -match "windows") {
        $Devpath = "C:/Program Files/Infocyte/dev"
        $AgentPath = "C:/Program Files/Infocyte/Agent"
    } else {
        $Devpath = "opt/infocyte/dev"
        $AgentPath = "opt/infocyte/agent"
    }

    # Check for Agent
    if (Test-Path "$DevPath/$agentname") {
        if ($Legacy){
             $DevVer = (& "$DevPath/$agentname" "--version").split(" ")[2]
        } else {
            $DevVer = (& "$DevPath/$agentname" "--version").split(" ")[2]
        }
    } else {
		New-Item $Devpath -ItemType Directory | Out-Null
		if (Test-Path "$AgentPath/$agentname") {
            if ($Legacy) {
                $AgentVer = (& "$AgentPath/$agentname" "--version").split(" ")[2]
            }
            else {
                $AgentVer = (& "$AgentPath/$agentname" "--version").split(" ")[2]
            }
			Write-Warning "$Devpath/$agentname not found but latest version ($Ver2) was found within your agent folder ($AgentPath). Copying this over."
			Copy-Item -Path "$AgentPath/$agentname" -Destination "$Devpath" | Out-Null
		} else {
            Write-Warning "Infocyte Agent not found. Install an Agent or download it into $DevPath"
            return
        }
	}
    # Update Agent
    if (Test-Path "$AgentPath/$agentname") {
        if ($Legacy) {
            $AgentVer = (& "$AgentPath/$agentname" "--version").split(" ")[2]
        }
        else {
            $AgentVer = (& "$AgentPath/$agentname" "--version").split(" ")[2]
        }
        if ($AgentVer -gt $DevVer) {
            Write-Warning "$agentname ($DevVer) has an update: ($AgentVer). Copy '$AgentPath/$agentname' to '$Devpath/$agentname'.`n
                `tRun this command to do so: Copy-Item -Path '$AgentPath/$agentname' -Destination '$Devpath/$agentname'"
        }
    }

    $Path = Get-item $Path | Select-Object -ExpandProperty FullName
    $ext = Get-item $Path | Select-Object -ExpandProperty name
    

    if (($env:OS -match "windows" -OR $isWindows) -AND (-NOT (Test-Path "$DevPath/luacheck.exe"))) {
		$url = "https://github.com/mpeterv/luacheck/releases/download/0.23.0/luacheck.exe"
        Write-Host -ForegroundColor $LoggingColor "$Devpath/luacheck.exe not found (used for linting). Attempting to download from Github."
		# Download luacheck from Github
		#[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13
		$wc = New-Object Net.WebClient
		$wc.Encoding = [System.Text.Encoding]::UTF8
		$wc.UseDefaultCredentials = $true
		try {
			$wc.DownloadFile($URL, "$Devpath/luacheck.exe")
		} catch {
            Write-Warning "Could not download luacheck.exe from $URL."
        }
        $Config = "C:\Program Files\Infocyte\dev\.luacheckrc"
        if (-NOT (Test-Path $Config)) {
            'globals = { "hunt" }' > $Config
            'allow_defined = true' >> $Config
            'ignore = { "611", "612", "613", "614" }' >> $Config
        }
    }
    if (($env:OS -match "windows" -OR $isWindows) -AND (Test-Path "$DevPath/luacheck.exe")) {
        Write-Host -ForegroundColor $LoggingColor "Linting $Path"
        Get-Content $Path | & "$Devpath\luacheck.exe" - --codes --config "C:\Program Files\Infocyte\dev\.luacheckrc"
    }

    # & "agent.exe --no-delete --no-compress --verbose --only-extensions --extensions $Path"
    $a = @()
    if ($Legacy) {
        $a += "--no-compress"
        $a += "--no-install"
        $a += "--only-extensions"
        $a += "--extensions $Path"
    } else {
        $a += "--verbose"
        $a += "--extension $Path"
        $a += "survey --no-compress --only-extensions"
    }

    Write-Host -ForegroundColor $LoggingColor "Executing $ext with $agentname (Version: $DevVer)"
    Write-Host -ForegroundColor $LoggingColor "$Devpath/$agentname $a"
	$psi = New-object System.Diagnostics.ProcessStartInfo
	$psi.CreateNoWindow = $true
	$psi.UseShellExecute = $false
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $false
	$psi.FileName = "$Devpath/$agentname"
	$psi.Arguments = $a
	$process = New-Object System.Diagnostics.Process
	$process.StartInfo = $psi
	$process.Start() | Out-Null
	#$process.WaitForExit()
    $line = $true
    if ($process.HasExited) {
        Write-Warning "Something went wrong on survey running: $Devpath/$agentname $($a.ToString())"
    }
    #$output = "`n$line"
    $completedsuccessfully = $false
    $agentOutputRegex = '^\[(?<datestamp>\d{4}-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\.\d+\sUTC)\]\[(?<level>!?.+)\]\[(?<logtype>!?.+)\]\s(?<msg>.+)'
    $color = 'green'
	while ($line -OR -NOT $process.HasExited) {
        $line = $process.StandardOutput.ReadLine()
        if ($line -Match $agentOutputRegex) {
            if ($exitError) {
                return $false
            }
            $AgentOutput = $Matches
            
            # End
            if ($AgentOutput.msg -match "System inspections complete") {
                Write-Verbose "Completed!"
                return $true
            }
            elseif ($AgentOutput.logtype -eq "agent::survey") {
                Write-Verbose "$line"
            }
            elseif ($AgentOutput.msg -match "Logging initialized") {
                Write-Host -ForegroundColor $LoggingColor "Running Extension..."
            }
            else {
                #Color code output
                Switch ($AgentOutput.level) {
                    "ERROR" { $color = 'Red' }
                    "WARN" { $color = 'Orange' }
                    "DEBUG" { $color = 'Yellow' }
                    "VERBOSE" { $color = 'Yellow' }
                    "TRACE" { $color = 'Yellow' }
                    "INFO" { $color = 'Blue' }
                    default {
                        Write-Warning "[Unknown] $($AgentOutput.msg)"        
                    }
                } 

                if ($AgentOutput.logtype -eq "agent::extensions" -AND $AgentOutput.level -eq "ERROR") {
                    Write-Host -ForegroundColor $color "[$($AgentOutput.level)][$($AgentOutput.logtype)] $($AgentOutput.msg)"
                    $exitError = $true
                }
                else {
                    Write-Host -ForegroundColor $color "[$($AgentOutput.level)] $($AgentOutput.msg)"
                }
            } 
        } else {
            # print and error output
            if ($color -eq 'Red') {
                Write-Host -ForegroundColor Red "$line"
            } else {
                Write-Host -ForegroundColor DarkGray "[PRINT] $line"
            }
        }
    }
    if ($exitError) {
        Write-Warning "Survey did not complete successfully. Address any bugs in the extension and try again."
    }
    -NOT $exitError
}

function Parse-ICExtensionHeader ($ExtensionBody){

    $header = [PSCustomObject]@{
        name = $null
        type = $null
        description = $null
        author = $null
        guid = $null
        created = $null
        updated = $null
    }
    if ($ExtensionBody -match '(?si)^--\[\[[\n\r]+(?<preamble>.+?)-*\]\]') {
        $preamble = $matches.preamble
    } else {
        Write-Error "Could not parse header (should be a comment section wrapped by --[[ <header> --]] )"
        return
    }

    #$regex = '(?mi)\s*Name:\s(?<name>.+?)\n|\s*Type:\s(?<type>.+?)\n|\s*Description:\s(\|(?<description>.+?)\||(?<description>.+?)\n)|\s*Updated:\s(?<updated>.+?)\n|\s*Guid:\s(?<guid>.+?)\n'
    if ($preamble -match '(?mi)^\s*Name:\s(.+?)\n') { $header.name = $Matches[1] }
    if ($preamble -match '(?mi)^\s*Guid:\s(.+?)\n') { $header.guid = $Matches[1] }
    if ($preamble -match '(?mi)^\s*Author:\s(.+?)\n') { $header.author = $Matches[1] }
    if ($preamble -match '(?si)\s*Description:\s(?<a>\|\s*(?<desc>.+?)\s*\||(?<desc>.+?)\n)') { $header.description = $Matches.desc }
    if ($preamble -match '(?mi)^\s*Type:\s(.+?)\n') { $header.type = $Matches[1] }
    if ($preamble -match '(?mi)^\s*Created:\s(\d{8})\s*') {
        $header.created = ($matches[1].split(" ")[0] | ForEach-Object { get-date -year $_.substring(0,4) -Month $_.substring(4,2) -Day $_.substring(6,2) }).date 
    }
    if ($preamble -match '(?mi)^\s*Updated:\s(\d{8})\s*') {
        $header.updated = ($matches[1].split(" ")[0] | ForEach-Object { get-date -year $_.substring(0,4) -Month $_.substring(4,2) -Day $_.substring(6,2) }).date 
    }
    if ($header.guid -notmatch $GUID_REGEX) { 
        Write-Error "Incorrect guid format: $($header.guid).  Should be a guid of form: $GUID_REGEX. 
            Use the following command to generate a new one: [guid]::NewGuid().Guid" 
    }
    return $header
}
