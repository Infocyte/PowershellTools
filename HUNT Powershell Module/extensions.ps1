
function Get-ICExtension {
    [cmdletbinding()]
    Param(
        [parameter(ValueFromPipeline=$true)]
        [alias('extensionId')]
        [String]$Id,

        [Switch]$IncludeBody,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},
        [parameter(HelpMessage="The field or fields to order the results on: https://loopback.io/doc/en/lb2/Order-filter.html")]
        [String[]]$order,

        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        if ($Id) {
            $Endpoint = "extensions/$Id"
            $CountOnly = $false
            $order = $null
            if ($IncludeBody) {
                $Endpoint += "/latestVersion"
            }
        } else {
            $Endpoint = "extensions"
        }
        Get-ICAPI -Endpoint $Endpoint -where $where -order $order -NoLimit:$NoLimit -CountOnly:$CountOnly
    }
}

function Import-ICExtension {
    [cmdletbinding()]
    Param(
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
        [String]$ScriptBody,

        [parameter(
            mandatory=$false,
            ParameterSetName = 'Path'
        )]
        [parameter(
            mandatory=$true,
            ParameterSetName  = 'String'
        )]
        [ValidateNotNullorEmpty()]
        [String]$Name,

        [parameter()]
        [String]$Description,

        [parameter()]
        [ValidateSet("collection","action")]
        [String]$Type='action',

        [Switch]$Active
    )

    PROCESS {
        $Endpoint = "extensions"
        $body = @{
            type = $Type
        }
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Write-Verbose "Testing path: $Path"
            if (Test-Path $Path) {
                $scriptfile = Get-Item $Path
                Write-Verbose "Using filename for Extension Name."
                $body['name'] = $scriptfile.BaseName
                $ScriptBody = Get-Content $Path -Raw
            } else {
                Write-Error "$Path does not exist!"
                return
            }
        } else {
            $body['name'] = $Name
        }
        $body['body'] = $ScriptBody
        if ($Active) {
            $body['active'] = $true
        }
        if ($Description) {
            $body['description'] = $Description
        }
        Write-Host "Adding new Extension named: $($body['name'])"
        $ext = Get-ICExtension -where @{ name = $($body['name']); deleted = $False }
        if ($ext) {
            Write-Error "There is already an extension named $($body['name'])"
            return
        } else {
            Invoke-ICAPI -Endpoint $Endpoint -body $body -method POST
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
		[Switch]$Type = "Collection"  
	)
	
	$CollectionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/draft/examples/collection_template.lua"
	$ActionTemplate = "https://raw.githubusercontent.com/Infocyte/extensions/draft/examples/action_template.lua"

	if ($Type == "Collection"){
		$template = (new-object Net.WebClient).DownloadString($CollectionTemplate)
	} else {
		$template = (new-object Net.WebClient).DownloadString($ActionTemplate)
    }
    
    $template -replace '(?si)--\[\[.+?\n\s*Name:\s(.+?)\n',$name
    if ($Author) { $template -replace '(?si)--\[\[.+?\n\s*Name:\s(.+?)\n',$Author }
    if ($Description) { $template -replace '(?si)--\[\[.+?\n\s*Name:\s(.+?)\n',$Description }
    $template -replace '(?si)--\[\[.+?\n\s*Id:\s(.+?)\n',[guid]::NewGuid().guid
    $currentdate = Get-Date
    $dt = "$($currentdate.Year)$($currentdate.Month)$($currentdate.Day)"
    $template -replace '(?si)--\[\[.+?\n\s*Created:\s(.+?)\n',$dt
    $template -replace '(?si)--\[\[.+?\n\s*Update:\s(.+?)\n',$dt

    Write-Host "Created $Type extension from template at $pwd\$Name.lua"
    
	$template | Out-File -Encoding utf8 -FilePath "$pwd\$Name.lua"
}

function Update-ICExtension {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        
        [parameter(
            mandatory=$false,
            ParameterSetName = 'Official'
        )]
        [Switch]$InfocytePublished,

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
        [String]$ScriptBody
    )

    PROCESS {
        $Endpoint = "extensions"
        $body = @{}
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            Write-Verbose "Testing path: $Path"
            if (Test-Path $Path) {
                $scriptfile = Get-Item $Path
                $body['body'] = Get-Content $Path -Raw
                $scriptname = $scriptfile.BaseName
            } else {
                Write-Error "$Path does not exist!"
                return
            }
        }
        else if ($PSCmdlet.ParameterSetName -eq 'String') {
            $body['body'] = $ScriptBody
        }
        else if ($InfocytePublished) {
            # Update Infocyte Official extensions
            

        }

        if ($Id) {
            Write-Verbose "Looking up extension by Id"
            $obj = Get-ICExtension -id $Id
            if ($obj) {
                Write-Verbose "Extension found: `n$($obj | converto-json)"
                $body['id'] = $obj.id
                $body['name'] = $obj.name
            } else {
                Write-Error "Extension with id $id not found!"
                return
            }
        } else {
            Write-Verbose "Looking up existing extension by name: $($scriptfile.BaseName)"
            $obj = Get-ICExtension -where @{ name = $scriptfile.BaseName; deleted = $false }
            if ($obj) {
                if ($obj.count) {
                    Write-Error "More than one extension named $($scriptfile.BaseName)"
                    return
                }
                Write-Verbose "Found existing extension named $($scriptfile.BaseName) with id $($obj.id)"
                $body['id'] = $obj.id
                $body['name'] = $scriptfile.BaseName

            } else {
                Write-Error "Extension named $($scriptfile.BaseName) not found!"
                return
            }
        }
        $body['type'] = $obj.type
        $body['description'] = $obj.description
        $body['active'] = $obj.active

        Write-Host "Updating Extension: $($obj.name) [$Id] with `n$($b|convertto-json)"
        if ($PSCmdlet.ShouldProcess($($obj.name), "Will update extension $($obj.name) [$Id]")) {
            Invoke-ICAPI -Endpoint $Endpoint -body $b -method POST
        }
    }
}

function Remove-ICExtension {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullorEmpty()]
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
        if ($PSCmdlet.ShouldProcess($Id, "Will remove $($ext.name) with extensionId '$Id'")) {
            Write-Host "Removing $($ext.name) with extensionId '$Id'"
            Invoke-ICAPI -Endpoint $Endpoint -method DELETE
        }
    }
}

function Import-ICOfficialExtensions {
    [cmdletbinding()]
    Param(
        [Switch]$IncludeContributed
    )

    $InstanceExtensions = Get-ICExtension -IncludeBody -NoLimit
    $Extensions = Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/collection" | select -ExpandProperty content | ConvertFrom-Json
    $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/official/action" | select -ExpandProperty content | ConvertFrom-Json
    If ($IncludeContributed) {
        $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/contrib/collection" | select -ExpandProperty content | ConvertFrom-Json
        $Extensions += Invoke-WebRequest -Uri "https://api.github.com/repos/Infocyte/extensions/contents/contrib/action" | select -ExpandProperty content | ConvertFrom-Json
    }

    $Extensions | % {
        $filename = ($_.name -split "\.")[0]
        $ext = (new-object Net.WebClient).DownloadString($_.download_url)
        $ext.body -match '(?si)^--\[\[[\n\r]+(?<preamble>.+?)\]\]--' | Out-Null
        $preamble = $matches.preamble
        $header = @{}
        #$regex = '(?mi)\s*Name:\s(?<name>.+?)\n|\s*Type:\s(?<type>.+?)\n|\s*Description:\s(\|(?<description>.+?)\||(?<description>.+?)\n)|\s*Updated:\s(?<updated>.+?)\n|\s*Guid:\s(?<guid>.+?)\n'
        if ($preamble -match '(?mi)^\s*Name:\s(.+?)\n') { $header += @{ name = $Matches[1] } }
        if ($preamble -match '(?mi)^\s*Id:\s(.+?)\n') { $header += @{ id = $Matches[1] } }
        if ($preamble -match '(?si)\s*Description:\s(\|\s*(.+?)\s*\||(.+?)\n)') { $header += @{ description = $Matches[2] }}
        if ($preamble -match '(?mi)^\s*Type:\s(.+?)\n') { $header += @{ exttype = $Matches[1] }}
        if ($preamble -match '(?mi)^\s*Updated:\s(.+?)\n') {
            $header += @{ updated = ($matches[1].split(" ")[0] | % { get-date -year $_.substring(0,4) -Month $_.substring(4,2) -Day $_.substring(6,2) }).date }
        }
        $existingExt += $InstanceExtensions | ? { $_.name -eq $extname -OR $_.Description -eq $ExtId } 
        if ($existingExt) {
            Update-ICExtension -Id $existingExt.id -ScriptBody $ext.body
        } else {
            Import-ICExtension -Name $header.name -ScriptBody $ext.body -Type $header.type -Description $header.id -Active
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
		Write-Error "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
		return
	}

	# Clear-Host
    $Devpath = "C:\Program Files\Infocyte\dev"
	$AgentPath = "C:\Program Files\Infocyte\Agent\"
	$URL = ""

    if (Test-Path "$DevPath\s1.exe") {
        $Ver = (& "$DevPath\s1.exe" "--version").split(" ")[2]
		if (Test-Path "$AgentPath\s1.exe") {
			$Ver2 = (& "$AgentPath\s1.exe" "--version").split(" ")[2]
			if ($ver2 -gt $ver) {
				Write-Warning "s1.exe ($ver) has an update: ($Ver2). Copy s1.exe from $AgentPath\s1.exe to $Devpath\s1.exe to update this function."
			}
		}
		$Path = Get-item $Path | Select-Object -ExpandProperty FullName
		$ext = Get-item $Path | Select-Object -ExpandProperty name
    	Write-Verbose "Executing $ext with s1.exe (Version: $Ver)"
    } else {
		New-Item $Devpath -ItemType Directory | Out-Null
		if (Test-Path "$AgentPath\s1.exe") {
            $Ver2 = & "$AgentPath\s1.exe" "--version"
			Write-Warning "$Devpath\s1.exe not found but latest version ($Ver2) was found within your agent folder ($AgentPath). Copying this over."
			Copy-Item -Path "$AgentPath\s1.exe" -Destination "$Devpath\s1.exe" | Out-Null
		}
		else {
			Write-Error "$Devpath\s1.exe not found! Attempting to download from Infocyte"
			# Download Survey from S3
			[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
			$wc = New-Object Net.WebClient
			$wc.Encoding = [System.Text.Encoding]::UTF8
			$wc.UseDefaultCredentials = $true
			try {
				$wc.DownloadFile($URL, "$Devpath\s1.exe")
			} catch {
				Write-Error "Could not download S1.exe from $URL. You will need to manually download a copy from your Infocyte instance's Download page and add it to $DevPath\s1.exe"
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
		
		$reg1 = $line | select-string -Pattern "\d{4}-\d+-\d+T\d+:\d+:\d+\.\d+-\d+:\d+\s(!?.+)\ssurvey_types::response\s- (.+)"
		$reg2 = $line | select-string -Pattern "^[^\d]{4}" 
		if ($reg1) {
			Write-Output "[$($reg1.Matches.Groups[1].Value)] $($reg1.Matches.Groups[2].Value)"
		} 
		elseif ($reg2) {
			Write-Output "[] $line"
		}
	}
	Write-debug $output
}
function _Parse-ExtensionHeader ($ExtensionBody){
    if ($ExtensionBody -match '(?si)^--\[\[[\n\r]+(?<preamble>.+?)\]\]--') {
        $preamble = $matches.preamble
    } else {
        Throw "Could not parse header (wrapped by --[[ ]]--)"
    }

    $header = [PSCustomObject]@{
        name = $null
        type = $null
        description = $null
        id = $null
        created = $null
        updated = $null
    }
    #$regex = '(?mi)\s*Name:\s(?<name>.+?)\n|\s*Type:\s(?<type>.+?)\n|\s*Description:\s(\|(?<description>.+?)\||(?<description>.+?)\n)|\s*Updated:\s(?<updated>.+?)\n|\s*Guid:\s(?<guid>.+?)\n'
    if ($preamble -match '(?mi)^\s*Name:\s(.+?)\n') { $header.name = $Matches[1] }
    if ($preamble -match '(?mi)^\s*Id:\s(.+?)\n') { $header.id = $Matches[1] }
    if ($preamble -match '(?si)\s*Description:\s(\|\s*(.+?)\s*\||(.+?)\n)') { $header.description = $Matches[2] }
    if ($preamble -match '(?mi)^\s*Type:\s(.+?)\n') { $header.type = $Matches[1] }
    if ($preamble -match '(?mi)^\s*Created:\s(\d+)') {
        $header.created = ($matches[1].split(" ")[0] | % { get-date -year $_.substring(0,4) -Month $_.substring(4,2) -Day $_.substring(6,2) }).date 
    }
    if ($preamble -match '(?mi)^\s*Updated:\s(\d+)') {
        $header.updated = ($matches[1].split(" ")[0] | % { get-date -year $_.substring(0,4) -Month $_.substring(4,2) -Day $_.substring(6,2) }).date 
    }
    return $header
}
