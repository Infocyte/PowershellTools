
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
            ParameterSetName='List',
            HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},

        [parameter(
            ParameterSetName='List')]
        [Switch]$NoLimit,

        [parameter(
            ParameterSetName='List')]
        [Switch]$CountOnly,

        [Parameter()]
        [Switch]$Save,

        [parameter(
            ParameterSetName = 'Id')]
        [parameter(
            ParameterSetName = 'List')]
        [Switch]$IncludeBody
    )

    PROCESS {

        if ($Id) {
            Write-Verbose "Looking up extension by Id."
            $Endpoint = "extensions/$Id"
            $exts = Get-ICAPI -Endpoint $Endpoint -ea 0
            if (-NOT $exts) {
                Write-Warning "Could not find extension with Id: $($Id)"
                return
            }
        } else {
            Write-Verbose "Getting extensions"
            $Endpoint = "extensions"
            $exts = Get-ICAPI -endpoint $Endpoint -where $where -NoLimit:$NoLimit -CountOnly:$CountOnly
            if (-NOT $exts) {
                Write-Verbose "Could not find any extensions loaded with filter: $($where|convertto-json -Compress)"
                return
            }
            if ($CountOnly) { return $exts }
        }
        if (-NOT $IncludeBody) {
            return $exts
        }

        $n = 1
        if ($null -eq $exts.count) {
            $c = 1
        } else { 
            $c = $exts.count 
        }
        $exts | ForEach-Object {
            $ext = $_
            Write-Verbose "Getting Extension $($ext.name) [$($ext.id)]"
            try { $pc = [math]::Floor(($n / $c) * 100) } catch { $pc = -1 }
            Write-Progress -Id 1 -Activity "Getting Extention Body from Infocyte API" -Status "Requesting Body from Extension $n of $c" -PercentComplete $pc
            $extBody = Get-ICAPI -endpoint "extensions/$($ext.id)/LatestVersion" -fields body, sha256
            $Script = @{
                body = $extBody.body 
                sha256 = $extBody.sha256
            }
            Write-Verbose "Looking up user: $($ext.createdBy) and $($ext.updatedBy)"
            $ext.createdBy = (Get-ICAPI -endpoint users -where @{ id = $ext.createdBy } -fields email -ea 0).email
            $ext.updatedBy = (Get-ICAPI -endpoint users -where @{ id = $ext.updatedBy } -fields email -ea 0).email

            Write-Verbose "Parsing Extension Header for $($ext.name) [$($ext.id)]"
            try {
                $header = Parse-ICExtensionHeader -Body $Script.body
                if ($header) {
                    $h = @{}
                    $header.psobject.properties | % {
                        $h[$_.name] = $_.value
                    }
                }
                $ext | Add-Member -MemberType NoteProperty -Name args -Value $h.args
                $ext | Add-Member -MemberType NoteProperty -Name globals -Value $h.globals
                $ext | Add-Member -MemberType NoteProperty -Name header -Value $h
            } catch {
                Write-Warning "Could not parse header on $($ext.name) [$($ext.id)]: $($_)"
            }
            $ext | Add-Member -MemberType NoteProperty -Name script -Value $Script
            $n += 1
        }
        Write-Progress -Id 1 -Activity "Getting Extentions from Infocyte API" -Status "Complete" -Completed
        
        $SavePath = (Resolve-Path .\).Path
        if ($Save) {
            $exts | Foreach-Object {
                $FilePath = "$SavePath\$($($_.name).replace(" ","_")).lua" 
                Remove-Item $FilePath -Force | Out-Null
                [System.IO.File]::WriteAllLines($FilePath, $exts.script.body)
                Write-Verbose "Saved extension to $FilePath"
                # $exts.body | Out-File $SavePath | Out-Null
            }
        }
        Write-Output $exts
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
            "Response"
        )]
        [String]$Type = "Collection"
	)
	
	$CollectionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/master/examples/collection_template.lua"
    $ActionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/master/examples/response_template.lua"

	if ($Type -eq "Collection"){
		$template = (new-object Net.WebClient).DownloadString($CollectionTemplate)
	} else {
		$template = (new-object Net.WebClient).DownloadString($ActionTemplate)
    }
    
    $template = $template -replace '(?si)(?<start>^--\[=\[.+?name\s*=\s*")(?<field>.+?)(?<end>"\n)', "`${start}$Name`${end}"
    $template = $template -replace '(?si)(?<start>^--\[=\[.+?author\s*=\s*")(.+?)(?<end>"\n)', "`${start}$Author`${end}"
    $template = $template -replace '(?si)(?<start>^--\[=\[.+?description\s*=\s*)([^|].+?|\|.+?\|)(?<end>"\n)', "`${start}| $Description |`${end}"
    $template = $template -replace '(?si)(?<start>^--\[=\[.+?guid\s*=\s*)(.+?)(?<end>"\n)', "`${start}$([guid]::NewGuid().guid)`${end}"
    $dt = Get-Date -UFormat "%F"
    $template = $template -replace '(?si)(?<start>^--\[=\[.+?created\s*=\s*)(.+?)(?<end>"\n)',"`${start}$dt`${end}"
    $template = $template -replace '(?si)(?<start>^--\[=\[.+?updated\s*=\s*)(.+?)(?<end>"\n)',"`${start}$dt`${end}"
    
    
    $SavePath = (Resolve-Path ".\").path + "\$($Type)_extension.lua"
    Write-Host "`nCreated $Type extension from template and saved to $SavePath"
    Remove-Item $SavePath -Force | Out-Null
    [System.IO.File]::WriteAllLines($SavePath, $template)
    # $template | Out-File -FilePath $SavePath
    return $template    
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
                Throw "$Path does not exist!"
            }
        }

        $postbody['body'] = $Body
        $header = Parse-ICExtensionHeader -Body $Body
        if (-NOT $header.name -OR -NOT $header.type) { 
            Throw "Extension Header is incomplete or incorrectly formatted. Recommend using a template header" 
        }
        
        $postbody['name'] = $header.name 
        if (($header.type).toLower() -eq "collection") {
            $postbody['type'] = "collection"
        } else {
            $postbody['type'] = "response"
        }
        $postbody['description'] = $header.guid

        if ($header.guid) {
            $ext = Get-ICExtension -where @{ description = $header.guid }
            if ($ext) {
                if (-NOT $Force) {
                    Write-Warning "There is already an existing extension named $($ext.name) [$($ext.Id)] with guid $($ext.description). Try using Update-ICExtension or use -Force flag."
                    return
                }
                Write-Warning "There is already an existing extension named $($ext.name) [$($ext.Id)] with guid $($ext.description). Forcing update."
                $postbody['id'] = $ext.id
            } 
        }
        else {
            Write-Verbose "Adding new Extension named: $($postbody['name'])"
        }
        Invoke-ICAPI -Endpoint $Endpoint -body $postbody -method POST
        $globals = Get-ICAPI -endpoint ExtensionGlobalVariables -nolimit
        $header.globals | where-object { $_.name -notin $globals.name -AND $_.default } | ForEach-Object {
            $varbody = @{
                name = $_.name
                type = $_.type
                value = $_.default
            }
            Invoke-ICAPI -Endpoint ExtensionGlobalVariables -Method POST -body $varbody
        }
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

        $header = Parse-ICExtensionHeader -Body $Body
        Write-Verbose "Extension Header:`n$($header | ConvertTo-Json)"
        $postbody['body'] = $Body
        $postbody['name'] = $header.name
        if ($header.type -match "collection") {
            $postbody['type'] = "collection"
        } else {
            $postbody['type'] = "response"
        }
        $postbody['description'] = $header.guid

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
                if ($ext.description -AND ($header.guid -ne $ext.description)) {
                    Write-Warning "Extension Guids do not match. Cannot be updated, try importing the new extension!`nCurrent: $($ext.description)`nNew: $($header.guid)"
                    return
                }
            } else {
                Write-Warning "Extension with id $id not found!"
                return
            }
        } 
        else {
            Write-Verbose "Looking up extension by Guid"
            $ext = Get-ICExtension -ea 0 -where @{ description = $header.guid }
            if ($ext) {
                Write-Verbose "Founding existing extension with matching guid $($header.guid). Updating id $($ext.id)"
                $postbody['id'] = $ext.id
                if (-NOT $postbody['name']) { $postbody['name'] = $ext.name }
                if (-NOT $postbody['type']) { $postbody['type'] = $ext.type }
                if (-NOT $postbody['description']) { $postbody['description'] = $ext.description }
            } 
            else {
                Write-Warning "Could not find existing extension with Guid: $($header.guid)"
                return
            }
        }
        Write-Verbose "Updating Extension: $($ext['name']) [$($ext.id)] with `n$($postbody|convertto-json)"
        if ($PSCmdlet.ShouldProcess($($ext.name), "Will update extension $($postbody['name']) [$postbody['id'])]")) {
            Invoke-ICAPI -Endpoint $Endpoint -body $postbody -method POST
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
        [String]$Id
    )

    PROCESS {
        $Endpoint = "extensions/$Id"
        $ext = Get-ICExtension -id $Id
        if (-NOT $ext) {
            Write-Error "Extension with id $id not found!"
            return
        }
        
        if ($PSCmdlet.ShouldProcess($($ext.Id), "Will remove $($ext.name) with extensionId '$($ext.Id)'")) {
            try {
                Invoke-ICAPI -Endpoint $Endpoint -Method DELETE
                Write-Verbose "Removed extension $($ext.name) [$($ext.Id)]"
                $true
            } catch {
                Write-Warning "Extension $($ext.name) [$($ext.Id)] could not be removed!"
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

    $InstanceExtensions = Get-ICExtension -NoLimit
    Write-Verbose "Pulling Official Extensions from Github: https://api.github.com/repos/Infocyte/extensions/contents/official/"
    try {
        $Extensions = Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/collection" | Select-Object -ExpandProperty content | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not download extensions from https://api.github.com/repos/Infocyte/extensions/contents/official/collection"
    }
    try {
        $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/response" | Select-Object -ExpandProperty content | ConvertFrom-Json
    }
    catch {
        Write-Warning "Could not download extensions from https://api.github.com/repos/Infocyte/extensions/contents/official/response"
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
            $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/contrib/response" | Select-Object -ExpandProperty content | ConvertFrom-Json
        }
        catch {
            Write-Warning "Could not download extensions from https://api.github.com/repos/Infocyte/extensions/contents/contrib/response"
        }
    }

    $Extensions | ForEach-Object {
        $filename = ($_.name -split "\.")[0]
        try {
            $ext = (new-object Net.WebClient).DownloadString($_.download_url)
        } catch {
            Write-Warning "Could not download extension. [$_]"
            continue
        }
        try {
            $header = Parse-ICExtensionHeader -Body $ext
        } catch {
            Write-Warning "Could not parse header on $($filename)"; 
            continue
        }       
        $existingExt = $InstanceExtensions | Where-Object { $_.description -eq $header.guid }
        if ($existingExt) {
            if ($Update) {
                Write-Verbose "Updating extension $($header.name) [$($existingExt.id)] with guid $($header.guid):`n$existingExt"
                Update-ICExtension -Id $existingExt.id -Body $ext   
            }
            else {
                Write-Warning "Extension $($header.name) [$($existingExt.id)] with guid $($header.guid) already exists. Try using -Update to update it."
            }
        } else {
            Write-Verbose "Importing extension $($header.name) [$($header.Type)] with guid $($header.guid)"
            Import-ICExtension -Body $ext -Active -Force:$Update
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
        
        [Object]$Globals,

        [Object]$Arguments
    )

    $LoggingColor = 'DarkCyan'
      	  
	If ($env:OS -match "windows" -AND (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
		Throw "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    } elseif ($IsLinux -AND (id -u) -ne 0) {
        Throw "You do not have permissions to run this script!`nPlease re-run this with sudo!"
    }

    if (-NOT (Test-Path $Path)) {
        Throw "$Path not found"
    }
    
    # Clear-Host
    $agentname = "agent.exe"
    if ($IsWindows -OR $env:OS -match "windows") {
        $Devpath = "C:/Program Files/Infocyte/dev"
        $AgentPath = "C:/Program Files/Infocyte/Agent"
    } else {
        $Devpath = "/opt/infocyte/dev"
        $AgentPath = "/opt/infocyte/agent"
    }


    # Check for Agent
    if (Test-Path "$DevPath/$agentname") {     
        $DevVer = (& "$DevPath/$agentname" "--version").split(" ")[2]
    } else {
		New-Item $Devpath -ItemType Directory | Out-Null
		if (Test-Path "$AgentPath/$agentname") {
            $AgentVer = (& "$AgentPath/$agentname" "--version").split(" ")[2]
            Write-Warning "$Devpath/$agentname not found but latest version ($AgentVer) was found within your agent folder ($AgentPath). Copying this over."
			Copy-Item -Path "$AgentPath/$agentname" -Destination "$Devpath" | Out-Null
            $DevVer = (& "$DevPath/$agentname" "--version").split(" ")[2]
		} else {
            Write-Warning "Infocyte Agent not found. Install an Agent or download it into $DevPath"
            return
        }
	}
    # Update Agent
    if (Test-Path "$AgentPath/$agentname") {
        $AgentVer = (& "$AgentPath/$agentname" "--version").split(" ")[2]
        if ($AgentVer -gt $DevVer) {
            Write-Warning "$agentname ($DevVer) has an update: ($AgentVer). Copy '$AgentPath/$agentname' to '$Devpath/$agentname'.`n
                `tRun this command to do so: Copy-Item -Path '$AgentPath/$agentname' -Destination '$Devpath/$agentname'"
        }
    }

    $Path = Get-item $Path | Select-Object -ExpandProperty FullName
    $ext = Get-item $Path | Select-Object -ExpandProperty name
    
    # Check for luacheck
    if ($env:OS -match "windows" -OR $isWindows) {

        if (-NOT (Test-Path "$DevPath/luacheck.exe")) {
            $url = "https://github.com/mpeterv/luacheck/releases/download/0.23.0/luacheck.exe"
            Write-Host -ForegroundColor $LoggingColor "$Devpath/luacheck.exe not found (used for linting). Attempting to download from Github."
            # Download luacheck from Github
            #[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13
            $wc = New-Object Net.WebClient
            $wc.Encoding = [System.Text.Encoding]::UTF8
            $wc.UseDefaultCredentials = $true
            try {
                $wc.DownloadFile($URL, "$Devpath/luacheck.exe") | Out-Null
            } catch {
                Write-Warning "Could not download luacheck.exe from $URL."
            }
        }
    }
    else {
        $luacheck = (which luacheck)
        if ($luacheck -match "not found") {
            Write-Warning "luacheck not found (used for linting). Try installing it first"
        }
    }

    # luacheck config setup
    $Config = "$Devpath/.luacheckrc"
    if (-NOT (Test-Path $Config)) {
        $configString = 'globals = { "hunt" }'
        $configString += 'allow_defined = true'
        $configString += 'ignore = { "113", "611", "612", "613", "614", "631" }'
        [System.IO.File]::WriteAllLines($Config, $configString)
    }

    # Run luacheck
    if (($env:OS -match "windows" -OR $isWindows) -AND (Test-Path "$DevPath/luacheck.exe")) {        
        Write-Host -ForegroundColor $LoggingColor "Linting $Path"
        $luacheck = Get-Content $Path | & "$Devpath/luacheck.exe" - --codes --config $Config
        $luacheck | ForEach-Object {
            Write-Host $_
        }
    } 
    elseif ($IsLinux -AND $luacheck -notmatch "not found") {
        Write-Host -ForegroundColor $LoggingColor "Linting $Path"
        $luacheck = Get-Content $Path | luacheck - --codes --config $Config
        $luacheck | ForEach-Object {
            Write-Host $_
        }
    }

    Remove-Item "$Devpath/args.json" -ea 0 | Out-Null
    Remove-Item "$Devpath/globals.json" -ea 0 | Out-Null

    $a = @()
    $a += "--debug"
    $a += "--extension `"$Path`""
    if ($Globals) {
        [System.IO.File]::WriteAllLines("$Devpath/globals.json", ($Globals | ConvertTo-Json))
        $a += "--extension-globals `"$Devpath/globals.json`""
    }
    if ($Arguments) {
        [System.IO.File]::WriteAllLines("$Devpath/args.json", ($Arguments | ConvertTo-Json))
        $a += "--extension-args `"$Devpath/args.json`""
    }
    $a += "survey --no-compress --only-extensions"

    $completedsuccessfully = $false
    $agentOutputRegex = '^\[(?<datestamp>\d{4}-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\.\d+\sUTC)\]\[(?<level>.+?)\]\[(?<logtype>.+?)\]\s(?<msg>.+)'
    $color = 'green'

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
    Write-Verbose "Args: $($psi.Arguments)"
	#$process.WaitForExit()
    if ($process.HasExited) {
        Write-Warning "Something went wrong on survey running: $Devpath/$agentname $($a.ToString())"
    }
	while ($line -OR -NOT $process.HasExited) {
        $line = $process.StandardOutput.ReadLine()
        if ($line -Match $agentOutputRegex) {
            $AgentOutput = $Matches
            
            if ($AgentOutput.msg -match "System inspections complete") {
                # End
                Write-Verbose "System inspections complete!"
                break
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
                    "WARN" { $color = 'DarkYellow' }
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
                Write-Host -ForegroundColor Red "[ERROR] $line"
            } else {
                Write-Host -ForegroundColor DarkGray "$line"
            }
        }
    }
    if ($exitError) {
        Write-Warning "Survey did not complete successfully. Address any bugs in the extension and try again."
    }
    -NOT $exitError
}

function Parse-ICExtensionHeader {
    [cmdletbinding(DefaultParameterSetName = 'Body')]
    Param(
        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ParameterSetName = 'Body')]
        [ValidateNotNullOrEmpty()]
        [String]$Body,

        [parameter(
            Mandatory, 
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Path')]
        [ValidateNotNullorEmpty()]
        [String]$Path
    )

    if ($Path) {
        $Body = Get-Content $Path -Raw
        #$reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $Path
    }
    if ($Body -match '(?si)^--\[=\[(?<preamble>.+?)\]=\]') {
        $preamble = $matches.preamble.trim()
    } else {
        Write-Error "Could not parse header (should be a comment section wrapped by --[=[ <header> ]=] )"
        return
    }

    $header = ConvertFrom-Yaml $preamble

    if ($header.filetype -ne "Infocyte Extension") {
        Throw "Incorrect filetype. Not an Infocyte Extension"
    }    
    if ($header.guid -notmatch $GUID_REGEX) { 
        Throw "Incorrect guid format: $($header.guid).  Should be a guid of form: $GUID_REGEX. 
            Use the following command to generate a new one: [guid]::NewGuid().Guid" 
    }

    $header.created = [datetime]$header.created
    $header.updated = [datetime]$header.updated    

    $header
}
