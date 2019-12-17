
# HElPER FUNCTIONS

# Used with most Infocyte Get methods.
# Takes a filter object (hashtable) and adds authentication and passes it as the body for URI encoded parameters.
# NoLimit will iterate 1000 results at a time to the end of the data set.
function Get-ICAPI {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [String]$endpoint,

        [parameter(Mandatory=$false, HelpMessage="Provide a hashtable and it will be converted to json-stringified query params. Reference format and operators here: https://loopback.io/doc/en/lb3/Where-filter.html")]
        [HashTable]$where=@{},

        [String[]]$order,

        [String[]]$fields,

        [Switch]$NoLimit,

        [Switch]$OverrideGlobalLimit,

        [Switch]$CountOnly
    )

    # Set access token
    if ($Global:ICToken) {
        $body = @{
            access_token = $Global:ICToken
        }
    } else {
        Write-Error "API Token not set! Use Set-ICToken to connect to an Infocyte instance."
        return
    }

    $Globallimit = 100000 # trying to control strains on the database. Add a filter to keep it reasonable.
    $resultlimit = 1000 # limits the number of results that come back. 1000 is max supported by Infocyte API. Use NoLimit flag on functions to iterate 1000 at a time for all results.
    $skip = 0
    $count = 0
    $more = $true
    $url = "$($Global:HuntServerAddress)/api/$Endpoint"

    $filter = @{
        skip = $skip
        limit = $resultlimit
    }
    if ($fields) {
        $filter['fields'] = $fields
    }
    if ($order) {
        $filter['order'] = $order
    }
    if ($where) {
        $filter['where'] = $where
    }

    Write-Verbose "Requesting data from $url"
    if ($where -AND $where.count -gt 0) {
        Write-Verbose "where-filter:`n$($where | ConvertTo-JSON -Depth 10)"
    }

    if ($Endpoint -match "/count$") {
        # if it matches /count or an id guid, there is no count
        $CountOnly = $true
        # JSON Stringify the where on body
        $body['where'] = $where | ConvertTo-JSON -Depth 10 -Compress
    }
    elseif ($Endpoint -match "[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}$" -OR
            $Endpoint -match "[0-9a-f]{40}$" -OR
            $Endpoint -match "/.*\d+$") {
        # Querying a single object. Don't try to count.
        Write-Debug "$Endpoint matches id filter. Adding filter."
        $body['filter'] = $filter | ConvertTo-JSON -Depth 10 -Compress
        $total = 1
    }
    elseif ($CountOnly) {
        $url += "/count"
        Write-Debug "Counting using /count"
        $body['where'] = $where | ConvertTo-JSON -Depth 10 -Compress
    }
    else {
        Write-Debug "Counting results first"
        $body['where'] = $where | ConvertTo-JSON -Depth 10 -Compress
        Write-Debug "Body:`n$($body|convertto-json)"
        try {
            $tcnt = Invoke-RestMethod "$url/count" -body $body -Method GET -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
            $total = [int]$tcnt.'count'
        } catch {
            Write-Verbose "Couldn't get a count from $url/count"
            $total = "Unknown"
        }
        if ($NoLimit -AND ($total -ge $Globallimit)) {
            Write-Warning "Your filter will return $total objects! You are limited to $GlobalLimit results per query."
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "`tDatabase performance can be severely degraded in large queries."
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "`tTry refining your query further with a 'where' filter or"
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "`task Infocyte for a data export by emailing support@infocyte.com."
            Read-Host -Prompt " Press any key to continue pulling first $GlobalLimit or CTRL+C to quit"
        }
        elseif ($NoLimit) {
            Write-Verbose "Retrieving $total objects that match this filter."
        }
        elseif ($total -gt $resultlimit -AND $total -ne "Unknown") {
            Write-Warning "Found $total objects with this filter. Returning first $resultlimit."
            Write-Host -ForegroundColor Yellow -BackgroundColor Black "`tUse a tighter 'where' filter or the -NoLimit switch to get more."
        } else {
            Write-Verbose "Found $total objects with this filter."
        }
        # JSON Stringify the filter on body
        $body.remove('where') | Out-Null
        $body['filter'] = $filter | ConvertTo-JSON -Depth 10 -Compress
    }

    $timer = [system.diagnostics.stopwatch]::StartNew()
    $times = @()

    while ($more) {
        try {
            $pc = $skip/$total
        } catch {
            $pc = -1
        }
        Write-Progress -Id 1 -Activity "Getting Data from Infocyte API" -status "Requesting data from $url [$skip of $total]" -PercentComplete $pc
        Write-Debug "Sending $url this Body as 'application/json':`n$($body|convertto-json)"
        $at = $timer.Elapsed
        try {
            $Objects = Invoke-RestMethod $url -body $body -Method GET -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
        } catch {
            Write-Error "ERROR: $($_.Exception.Message)"
            return
        }
        $bt = $timer.Elapsed
        $e = ($bt - $at).TotalMilliseconds
        $times += $e
        Write-Debug "Last Request: $($e.ToString("#.#"))ms"

        if ($CountOnly) {
            write-debug $Objects
            return [int]$Objects.count
        }
        if ($Objects) {
            if ($Objects.count) {
                $count += $Objects.count
            } else {
                write-debug "Couldn't count $objects. Using 1."
                $count += 1
            }

            Write-Output $Objects

            if (-NOT $NoLimit) {
                $more = $false
            }
            elseif ($Objects.count -lt $resultlimit) {
                $more = $false
            }
            elseif ($count -ge $Globallimit -AND -NOT $OverrideGlobalLimit) {
                Write-Warning "Reached Global Limit of $GlobalLimit results."
                $more = $false
            }
            # Set up next Page
            $body.remove('filter') | Out-Null
            $skip += $resultlimit
            $filter['skip'] = $skip
            $body['filter'] = $filter | ConvertTo-JSON -Depth 10 -Compress
        } else {
            Write-Debug "No results from last call."
            $more = $false
        }
    }
    $timer.Stop()
    $TotalTime = $timer.Elapsed
    $AveTime = ($times | Measure-Object -Average).Average
    $MaxTime = ($times | Measure-Object -Maximum).Maximum

    Write-Progress -Id 1 -Activity "Getting Data from Infocyte API" -Completed
    Write-Verbose "Received $count objects from $url in $($TotalTime.TotalSeconds.ToString("#.####")) Seconds (Page Request times: Ave= $($AveTime.ToString("#"))ms, Max= $($MaxTime.ToString("#"))ms)"
}

# Used with all other rest methods. Pass a body (hashtable) and it will add authentication.
function Invoke-ICAPI {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [String]$Endpoint,

        [parameter(Mandatory=$false, HelpMessage="Provide a hashtable.")]
        [HashTable]$body=$null,

        [parameter(Mandatory=$false)]
        [ValidateSet(
            "POST",
            "DELETE",
            "PUT",
            "PATCH"
        )]
        [String]$Method="POST"
    )

    if ($Global:ICToken) {
        $headers = @{
            Authorization = $Global:ICToken
        }
    } else {
        Write-Error "API Token not set! Use Set-ICToken to set your token to an Infocyte instance."
        return
    }

    $url = "$($Global:HuntServerAddress)/api/$Endpoint"
    Write-verbose "Sending $method command to $url"
    Write-verbose "Body: `n$($body | ConvertTo-JSON -Depth 10)"
    if ($body) {
        $json = $body | ConvertTo-JSON -Depth 10 -Compress
    }
	try {
		$Result = Invoke-RestMethod -Uri $url -headers $headers -body $json -Method $method -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
	} catch {
        if ($($_.Exception.Message) -match "422") {
            Write-Warning "Cannot process request."
            Write-Error "$($_.Exception.Message)"
        } else {
            Write-Error "$($_.Exception.Message)"
        }
	}
    if ($Method -like "DELETE") {
        if ($Result.'count') {
            return $true
        } else {
            Write-Warning "DELETE action returned unexpected result: $Result"
            return
        }
    }

	if ($Result) {
		Write-Output $Result
	} else {
        Write-Verbose "Nothing returned from call."
		return
	}
}


function Join-Object
{
    <#
    .SYNOPSIS
        Join data from two sets of objects based on a common value

    .DESCRIPTION
        Join data from two sets of objects based on a common value

        For more details, see the accompanying blog post:
            http://ramblingcookiemonster.github.io/Join-Object/

        For even more details,  see the original code and discussions that this borrows from:
            Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections
            Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

    .PARAMETER Left
        'Left' collection of objects to join.  You can use the pipeline for Left.

        The objects in this collection should be consistent.
        We look at the properties on the first object for a baseline.

    .PARAMETER Right
        'Right' collection of objects to join.

        The objects in this collection should be consistent.
        We look at the properties on the first object for a baseline.

    .PARAMETER LeftJoinProperty
        Property on Left collection objects that we match up with RightJoinProperty on the Right collection

    .PARAMETER RightJoinProperty
        Property on Right collection objects that we match up with LeftJoinProperty on the Left collection

    .PARAMETER LeftProperties
        One or more properties to keep from Left.  Default is to keep all Left properties (*).

        Each property can:
            - Be a plain property name like "Name"
            - Contain wildcards like "*"
            - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                 Name is the output property name
                 Expression is the property value ($_ as the current object)

                 Alternatively, use the Suffix or Prefix parameter to avoid collisions
                 Each property using this hashtable syntax will be excluded from suffixes and prefixes

    .PARAMETER RightProperties
        One or more properties to keep from Right.  Default is to keep all Right properties (*).

        Each property can:
            - Be a plain property name like "Name"
            - Contain wildcards like "*"
            - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                 Name is the output property name
                 Expression is the property value ($_ as the current object)

                 Alternatively, use the Suffix or Prefix parameter to avoid collisions
                 Each property using this hashtable syntax will be excluded from suffixes and prefixes

    .PARAMETER Prefix
        If specified, prepend Right object property names with this prefix to avoid collisions

        Example:
            Property Name                   = 'Name'
            Suffix                          = 'j_'
            Resulting Joined Property Name  = 'j_Name'

    .PARAMETER Suffix
        If specified, append Right object property names with this suffix to avoid collisions

        Example:
            Property Name                   = 'Name'
            Suffix                          = '_j'
            Resulting Joined Property Name  = 'Name_j'

    .PARAMETER Type
        Type of join.  Default is AllInLeft.

        AllInLeft will have all elements from Left at least once in the output, and might appear more than once
          if the where clause is true for more than one element in right, Left elements with matches in Right are
          preceded by elements with no matches.
          SQL equivalent: outer left join (or simply left join)

        AllInRight is similar to AllInLeft.

        OnlyIfInBoth will cause all elements from Left to be placed in the output, only if there is at least one
          match in Right.
          SQL equivalent: inner join (or simply join)

        AllInBoth will have all entries in right and left in the output. Specifically, it will have all entries
          in right with at least one match in left, followed by all entries in Right with no matches in left,
          followed by all entries in Left with no matches in Right.
          SQL equivalent: full join

    .EXAMPLE
        #
        #Define some input data.

        $l = 1..5 | Foreach-Object {
            [pscustomobject]@{
                Name = "jsmith$_"
                Birthday = (Get-Date).adddays(-1)
            }
        }

        $r = 4..7 | Foreach-Object{
            [pscustomobject]@{
                Department = "Department $_"
                Name = "Department $_"
                Manager = "jsmith$_"
            }
        }

        #We have a name and Birthday for each manager, how do we find their department, using an inner join?
        Join-Object -Left $l -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type OnlyIfInBoth -RightProperties Department


            # Name    Birthday             Department
            # ----    --------             ----------
            # jsmith4 4/14/2015 3:27:22 PM Department 4
            # jsmith5 4/14/2015 3:27:22 PM Department 5

    .EXAMPLE
        #
        #Define some input data.

        $l = 1..5 | Foreach-Object {
            [pscustomobject]@{
                Name = "jsmith$_"
                Birthday = (Get-Date).adddays(-1)
            }
        }

        $r = 4..7 | Foreach-Object{
            [pscustomobject]@{
                Department = "Department $_"
                Name = "Department $_"
                Manager = "jsmith$_"
            }
        }

        #We have a name and Birthday for each manager, how do we find all related department data, even if there are conflicting properties?
        $l | Join-Object -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type AllInLeft -Prefix j_

            # Name    Birthday             j_Department j_Name       j_Manager
            # ----    --------             ------------ ------       ---------
            # jsmith1 4/14/2015 3:27:22 PM
            # jsmith2 4/14/2015 3:27:22 PM
            # jsmith3 4/14/2015 3:27:22 PM
            # jsmith4 4/14/2015 3:27:22 PM Department 4 Department 4 jsmith4
            # jsmith5 4/14/2015 3:27:22 PM Department 5 Department 5 jsmith5

    .EXAMPLE
        #
        #Hey!  You know how to script right?  Can you merge these two CSVs, where Path1's IP is equal to Path2's IP_ADDRESS?

        #Get CSV data
        $s1 = Import-CSV $Path1
        $s2 = Import-CSV $Path2

        #Merge the data, using a full outer join to avoid omitting anything, and export it
        Join-Object -Left $s1 -Right $s2 -LeftJoinProperty IP_ADDRESS -RightJoinProperty IP -Prefix 'j_' -Type AllInBoth |
            Export-CSV $MergePath -NoTypeInformation

    .EXAMPLE
        #
        # "Hey Warren, we need to match up SSNs to Active Directory users, and check if they are enabled or not.
        #  I'll e-mail you an unencrypted CSV with all the SSNs from gmail, what could go wrong?"

        # Import some SSNs.
        $SSNs = Import-CSV -Path D:\SSNs.csv

        #Get AD users, and match up by a common value, samaccountname in this case:
        Get-ADUser -Filter "samaccountname -like 'wframe*'" |
            Join-Object -LeftJoinProperty samaccountname -Right $SSNs `
                        -RightJoinProperty samaccountname -RightProperties ssn `
                        -LeftProperties samaccountname, enabled, objectclass

    .NOTES
        This borrows from:
            Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections/
            Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

        Changes:
            Always display full set of properties
            Display properties in order (left first, right second)
            If specified, add suffix or prefix to right object property names to avoid collisions
            Use a hashtable rather than ordereddictionary (avoid case sensitivity)

    .LINK
        http://ramblingcookiemonster.github.io/Join-Object/

    .FUNCTIONALITY
        PowerShell Language

    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeLine = $true)]
        [object[]] $Left,

        # List to join with $Left
        [Parameter(Mandatory=$true)]
        [object[]] $Right,

        [Parameter(Mandatory = $true)]
        [string] $LeftJoinProperty,

        [Parameter(Mandatory = $true)]
        [string] $RightJoinProperty,

        [object[]]$LeftProperties = '*',

        # Properties from $Right we want in the output.
        # Like LeftProperties, each can be a plain name, wildcard or hashtable. See the LeftProperties comments.
        [object[]]$RightProperties = '*',

        [validateset( 'AllInLeft', 'OnlyIfInBoth', 'AllInBoth', 'AllInRight')]
        [Parameter(Mandatory=$false)]
        [string]$Type = 'AllInLeft',

        [string]$Prefix,
        [string]$Suffix
    )
    Begin
    {
        function AddItemProperties($item, $properties, $hash)
        {
            if ($null -eq $item)
            {
                return
            }

            foreach($property in $properties)
            {
                $propertyHash = $property -as [hashtable]
                if($null -ne $propertyHash)
                {
                    $hashName = $propertyHash["name"] -as [string]
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $expressionValue = $expression.Invoke($item)[0]

                    $hash[$hashName] = $expressionValue
                }
                else
                {
                    foreach($itemProperty in $item.psobject.Properties)
                    {
                        if ($itemProperty.Name -like $property)
                        {
                            $hash[$itemProperty.Name] = $itemProperty.Value
                        }
                    }
                }
            }
        }

        function TranslateProperties
        {
            [cmdletbinding()]
            param(
                [object[]]$Properties,
                [psobject]$RealObject,
                [string]$Side)

            foreach($Prop in $Properties)
            {
                $propertyHash = $Prop -as [hashtable]
                if($null -ne $propertyHash)
                {
                    $hashName = $propertyHash["name"] -as [string]
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $ScriptString = $expression.tostring()
                    if($ScriptString -notmatch 'param\(')
                    {
                        Write-Verbose "Property '$HashName'`: Adding param(`$_) to scriptblock '$ScriptString'"
                        $Expression = [ScriptBlock]::Create("param(`$_)`n $ScriptString")
                    }

                    $Output = @{Name =$HashName; Expression = $Expression }
                    Write-Verbose "Found $Side property hash with name $($Output.Name), expression:`n$($Output.Expression | out-string)"
                    $Output
                }
                else
                {
                    foreach($ThisProp in $RealObject.psobject.Properties)
                    {
                        if ($ThisProp.Name -like $Prop)
                        {
                            Write-Verbose "Found $Side property '$($ThisProp.Name)'"
                            $ThisProp.Name
                        }
                    }
                }
            }
        }

        function WriteJoinObjectOutput($leftItem, $rightItem, $leftProperties, $rightProperties)
        {
            $properties = @{}

            AddItemProperties $leftItem $leftProperties $properties
            AddItemProperties $rightItem $rightProperties $properties

            New-Object psobject -Property $properties
        }

        #Translate variations on calculated properties.  Doing this once shouldn't affect perf too much.
        foreach($Prop in @($LeftProperties + $RightProperties))
        {
            if($Prop -as [hashtable])
            {
                foreach($variation in ('n','label','l'))
                {
                    if(-not $Prop.ContainsKey('Name') )
                    {
                        if($Prop.ContainsKey($variation) )
                        {
                            $Prop.Add('Name',$Prop[$Variation])
                        }
                    }
                }
                if(-not $Prop.ContainsKey('Name') -or $Prop['Name'] -like $null )
                {
                    Throw "Property is missing a name`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }


                if(-not $Prop.ContainsKey('Expression') )
                {
                    if($Prop.ContainsKey('E') )
                    {
                        $Prop.Add('Expression',$Prop['E'])
                    }
                }

                if(-not $Prop.ContainsKey('Expression') -or $Prop['Expression'] -like $null )
                {
                    Throw "Property is missing an expression`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }
            }
        }

        $leftHash = @{}
        $rightHash = @{}

        # Hashtable keys can't be null; we'll use any old object reference as a placeholder if needed.
        $nullKey = New-Object psobject

        $bound = $PSBoundParameters.keys -contains "InputObject"
        if(-not $bound)
        {
            [System.Collections.ArrayList]$LeftData = @()
        }
    }
    Process
    {
        #We pull all the data for comparison later, no streaming
        if($bound)
        {
            $LeftData = $Left
        }
        Else
        {
            foreach($Object in $Left)
            {
                [void]$LeftData.add($Object)
            }
        }
    }
    End
    {
        foreach ($item in $Right)
        {
            $key = $item.$RightJoinProperty

            if ($null -eq $key)
            {
                $key = $nullKey
            }

            $bucket = $rightHash[$key]

            if ($null -eq $bucket)
            {
                $bucket = New-Object System.Collections.ArrayList
                $rightHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        foreach ($item in $LeftData)
        {
            $key = $item.$LeftJoinProperty

            if ($null -eq $key)
            {
                $key = $nullKey
            }

            $bucket = $leftHash[$key]

            if ($null -eq $bucket)
            {
                $bucket = New-Object System.Collections.ArrayList
                $leftHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        $LeftProperties = TranslateProperties -Properties $LeftProperties -Side 'Left' -RealObject $LeftData[0]
        $RightProperties = TranslateProperties -Properties $RightProperties -Side 'Right' -RealObject $Right[0]

        #I prefer ordered output. Left properties first.
        [string[]]$AllProps = $LeftProperties

        #Handle prefixes, suffixes, and building AllProps with Name only
        $RightProperties = foreach($RightProp in $RightProperties)
        {
            if(-not ($RightProp -as [Hashtable]))
            {
                Write-Verbose "Transforming property $RightProp to $Prefix$RightProp$Suffix"
                @{
                    Name="$Prefix$RightProp$Suffix"
                    Expression=[scriptblock]::create("param(`$_) `$_.'$RightProp'")
                }
                $AllProps += "$Prefix$RightProp$Suffix"
            }
            else
            {
                Write-Verbose "Skipping transformation of calculated property with name $($RightProp.Name), expression:`n$($RightProp.Expression | out-string)"
                $AllProps += [string]$RightProp["Name"]
                $RightProp
            }
        }

        $AllProps = $AllProps | Select -Unique

        Write-Verbose "Combined set of properties: $($AllProps -join ', ')"

        foreach ( $entry in $leftHash.GetEnumerator() )
        {
            $key = $entry.Key
            $leftBucket = $entry.Value

            $rightBucket = $rightHash[$key]

            if ($null -eq $rightBucket)
            {
                if ($Type -eq 'AllInLeft' -or $Type -eq 'AllInBoth')
                {
                    foreach ($leftItem in $leftBucket)
                    {
                        WriteJoinObjectOutput $leftItem $null $LeftProperties $RightProperties | Select $AllProps
                    }
                }
            }
            else
            {
                foreach ($leftItem in $leftBucket)
                {
                    foreach ($rightItem in $rightBucket)
                    {
                        WriteJoinObjectOutput $leftItem $rightItem $LeftProperties $RightProperties | Select $AllProps
                    }
                }
            }
        }

        if ($Type -eq 'AllInRight' -or $Type -eq 'AllInBoth')
        {
            foreach ($entry in $rightHash.GetEnumerator())
            {
                $key = $entry.Key
                $rightBucket = $entry.Value

                $leftBucket = $leftHash[$key]

                if ($null -eq $leftBucket)
                {
                    foreach ($rightItem in $rightBucket)
                    {
                        WriteJoinObjectOutput $null $rightItem $LeftProperties $RightProperties | Select $AllProps
                    }
                }
            }
        }
    }
}


Function IsPrivateNetwork( [String]$IP)
{
    If ($IP.Contains("/"))
    {
        $Temp = $IP.Split("/")
        $IP = $Temp[0]
    }
    try {
      $IPAddress = [Net.IPAddress]::Parse($IP)
      $BinaryIP = [String]::Join('.', $( $IPAddress.GetAddressBytes() | % { [Convert]::ToString($_, 2).PadLeft(8, '0') } ))
    } catch {
      Write-Warning "Error on parsing IP"
      return $null
    }

    $Private = $False

    Switch -RegEx ($BinaryIP)
    {
        "^1111" { $Class = "E"; $SubnetBitMap = "1111" }
        "^1110" { $Class = "D"; $SubnetBitMap = "1110" }
        "^110"  { $Class = "C"
                    If ($BinaryIP -Match "^11000000.10101000") { $Private = $True }
                }
        "^10"   { $Class = "B"
                    If ($BinaryIP -Match "^10101100.0001") { $Private = $True } }
        "^0"    { $Class = "A"
                    If ($BinaryIP -Match "^00001010") { $Private = $True }
                }
    }
    return $Private
}


function _Get-ICTimeStampUTC {
  return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}
