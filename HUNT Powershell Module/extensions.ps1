
function Get-ICExtension {
    [cmdletbinding(DefaultParameterSetName='List')]
    Param(
        [parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            ParameterSetName = 'Id')]
        [alias('extensionId')]
        [String]$Id,

        [parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            ParameterSetName = 'guid')]
        [String]$Guid,
        
        [Parameter(
            Mandatory = $false, 
            ParameterSetName = 'List')]
        [Switch]$IncludeBody,

        [parameter(
            Mandatory = $false, 
            ParameterSetName = 'List',
            HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},

        [parameter(
            Mandatory = $false, 
            ParameterSetName = 'List',
            HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order,

        [parameter(
            Mandatory = $false, 
            ParameterSetName = 'List')]
        [Switch]$NoLimit,

        [parameter(
            Mandatory = $false, 
            ParameterSetName = 'List')]
        [Switch]$CountOnly
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
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName gcriptGuid -NotePropertyValue $header.guid
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptName -NotePropertyValue $header.name
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptDescription -NotePropertyValue $header.Description
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptAuthor -NotePropertyValue $header.author
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptCreated -NotePropertyValue $header.created
            $ext | Add-Member -TypeName NoteProperty -NotePropertyName scriptUpdated -NotePropertyValue $header.updated
            Write-Verbose "Looking up user: $($ext.createdBy) and $($ext.updatedBy)"
            $ext.createdBy = (Get-ICAPI -endpoint users -where @{ id = $ext.createdBy } -fields email -ea 0).email
            $ext.updatedBy = (Get-ICAPI -endpoint users -where @{ id = $ext.updatedBy } -fields email -ea 0).email
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
            $ext = Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
            if ($CountOnly) { return $ext }
            $n = 1
            $c = $ext.count
            $ext | ForEach-Object {
                $pc = [math]::Floor(($n/$c)*100)
                Write-Progress -Activity "Getting Extentions from Infocyte API" -status "Requesting Body from Extension $n of $c" -PercentComplete $pc
                $_ | Add-Member -TypeName NoteProperty -NotePropertyName guid -NotePropertyValue $ext.description
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
		[String]$Type = "Collection"  
	)
	
	$CollectionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/draft/examples/collection_template.lua"
	$ActionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/draft/examples/action_template.lua"

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
    
    $template | Out-File -Encoding utf8 -FilePath "$pwd\$Name.lua"
    Write-Output $template
    
    Write-Host "`nCreated $Type extension from template and saved to $pwd\$Name.lua"
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
            mandatory=$true,
            ParameterSetName  = 'String'
        )]
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
            Write-Output $ext
        }
    }
}
function Remove-ICExtension {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName = 'Id')]
        [ValidateNotNullorEmpty()]
        [alias('extensionId')]
        [String]$Id,

        [parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ParameterSetName = 'guid')]
        [ValidateNotNullorEmpty()]
        [String]$Guid
    )
    PROCESS {
        if ($Id) {
            $Endpoint = "extensions/$Id"
            $ext = Get-ICExtension -id $Id
            if (-NOT $ext) {
                Write-Warning "Extension with id $id not found!"
                return
            }
        } else {
            $Endpoint = "extensions"
            $ext = Get-ICExtension -Guid $Guid
            if (-NOT $ext) {
                Write-Warning "Extension with guid $Guid not found!"
                return
            }
        }
        
        if ($PSCmdlet.ShouldProcess($($ext.Id), "Will remove $($ext.name) with extensionId '$($ext.Id)'")) {
            if (Invoke-ICAPI -Endpoint $Endpoint -method DELETE) {
                Write-Host "Removed extension $($ext.name) [$($ext.Id)]"
            } else {
                Throw "Extension $($ext.name) [$($ext.Id)] could not be removed!"
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
    $Extensions = Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/collection" | Select-Object -ExpandProperty content | ConvertFrom-Json
    $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/action" | Select-Object -ExpandProperty content | ConvertFrom-Json
    If ($IncludeContributed) {
        Write-Verbose "Pulling Official Extensions from Github: https://api.github.com/repos/Infocyte/extensions/contents/contrib/"
        $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/contrib/collection" | Select-Object -ExpandProperty content | ConvertFrom-Json
        $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/contrib/action" | Select-Object -ExpandProperty content | ConvertFrom-Json
    }
    $Extensions | ForEach-Object {
        #$filename = ($_.name -split "\.")[0]
        try {
            $ext = (new-object Net.WebClient).DownloadString($_.download_url)
            $header = Parse-ICExtensionHeader $ext
        } catch {
            Write-Warning "Could not download extension. [$_]"
            continue
        }

        $existingExt = $InstanceExtensions | Where-Object { $_.guid -eq $header.guid }
        if ($existingExt) {
            if ($Update) {
                Write-Verbose "Updating extension $($header.name) [$($existingExt.id)] with guid $($header.guid):`n$existingExt"

                Update-ICExtension -Id $existingExt.id -Body $ext
            }
            else {
                Write-Warning "Extension $($header.name) [$($existingExt.id)] with guid $($header.guid) already exists. Try using -Update to update it."
            }
        } else {
            Write-Verbose "Importing extension $($header.name) with guid $($header.guid)"
            Import-ICExtension -Body $ext -Active -Force:$Force
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

	  	[Switch]$DropSurveyFile
	  )
	  
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
		Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
		return
	}

	# Clear-Host
    $Devpath = "C:\Program Files\Infocyte\dev"
	$AgentPath = "C:\Program Files\Infocyte\Agent"
	$URL = ""

    if (Test-Path "$DevPath\s1.exe") {
        $Ver = (& "$DevPath\s1.exe" "--version").split(" ")[2]
		if (Test-Path "$AgentPath\s1.exe") {
			$Ver2 = (& "$AgentPath\s1.exe" "--version").split(" ")[2]
			if ($ver2 -gt $ver) {
                Write-Warning "s1.exe ($ver) has an update: ($Ver2). Copy s1.exe from '$AgentPath\s1.exe' to '$Devpath\s1.exe' to update this function."
                Write-Warning "Run this command to do so: Copy-Item -Path '$AgentPath\s1.exe' -Destination '$Devpath\s1.exe'"
			}
		}
		$Path = Get-item $Path | Select-Object -ExpandProperty FullName
		$ext = Get-item $Path | Select-Object -ExpandProperty name
    	Write-Verbose "Executing $ext with s1.exe (Version: $Ver)"
    } else {
		New-Item $Devpath -ItemType Directory | Out-Null
		if (Test-Path "$AgentPath\s1.exe") {
            $Ver2 = & "$AgentPath\s1.exe" "--version"
			Write-Warning "$Devpath\s1.exe not found but latest version ($Ver2) was found within your agent folder ($AgentPath\s1.exe). Copying this over."
			Copy-Item -Path "$AgentPath\s1.exe" -Destination "$Devpath\s1.exe" | Out-Null
		}
		else {
			Write-Warning "$Devpath\s1.exe not found! Attempting to download from Infocyte"
			# Download Survey from S3
			[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
			$wc = New-Object Net.WebClient
			$wc.Encoding = [System.Text.Encoding]::UTF8
			$wc.UseDefaultCredentials = $true
			try {
				$wc.DownloadFile($URL, "$Devpath\s1.exe")
			} catch {
				Write-Warning "Could not download S1.exe from $URL. You will need to manually download a copy from your Infocyte instance's Download page and add it to $DevPath\s1.exe"
				return
			}
		}
    }

	# & "s1.exe --no-delete --no-compress --verbose --only-extensions --extensions $Path"
	$a = @()
	$a += "--no-delete"
	if (-NOT $DropSurveyFile) { $a += "--no-results-file" }
	$a += "--no-log-file"
	$a += "--no-events"
	$a += "--only-extensions"
	$a += "--extensions $Path"
	
	#$p = Start-Process -NoNewWindow -FilePath "$Devpath\s1.exe" -ArgumentList $a -PassThru
	
	$psi = New-object System.Diagnostics.ProcessStartInfo
	$psi.CreateNoWindow = $true
	$psi.UseShellExecute = $false
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $false
	$psi.FileName = "$Devpath\s1.exe"
	$psi.Arguments = $a
	$process = New-Object System.Diagnostics.Process
	$process.StartInfo = $psi
	$process.Start() | Out-Null
	#$process.WaitForExit()

	$line = $process.StandardOutput.ReadLine()
	$output = "`n$line"
	while ($line) {
		$line = $process.StandardOutput.ReadLine()
		$output += "`n$line"
		
        $reg1 = $line -Match "\d{4}-\d+-\d+T\d+:\d+:\d+\.\d+-\d+:\d+\s(?<type>!?.+)\ssurvey_types::(response|extensions.*?)\s- (?<message>.+)"
        $reg2 = $line -Match "^[^\d]{4}" 
        if ($reg1) {
			Write-Output "[$($Matches.type)] $($Matches.message)"
		} 
		elseif ($reg2) {
			Write-Output "[PRINT] $line"
        } 
        elseif ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            Write-Output "[VERBOSE] $line"
        }
	}
	Write-debug $output
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
    if ($ExtensionBody -match '(?si)^--\[\[[\n\r]+(?<preamble>.+?)--\]\]') {
        $preamble = $matches.preamble
    } else {
        Write-Warning "Could not parse header (should be a section wrapped by --[[ ... --]])"
        return $header
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
    return $header
}
