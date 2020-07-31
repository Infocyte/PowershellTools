
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

        [String[]]$fields,

        [Switch]$NoLimit,

        [Switch]$CountOnly
    )

    # Set access token
    if ($Global:ICToken) {
        $body = @{
            access_token = $Global:ICToken
        }
    } else {
        throw "API Token not set! Use Set-ICToken to connect to an Infocyte instance."
    }

    $resultlimit = 1000 # limits the number of results that come back. 1000 is max supported by Infocyte API. Use NoLimit flag on functions to iterate 1000 at a time for all results.
    $Globallimit = 150000 # trying to control strains on the database. Add a filter to keep it reasonable.
    $skip = 0
    $lastId = $null
    $count = 0
    $more = $true
    $url = "$($Global:HuntServerAddress)/api/$Endpoint"

    $filter = @{
        order = 'id'
        limit = $resultlimit
    }
    if ($fields) { 
        if (-NOT $fields.Contains('id')) {
            $fields += 'id'
        }
        $filter['fields'] = $fields 
    }
    if ($where) { $filter['where'] = $where }

    $str = "Requesting data from $url"
    if ($where -AND $where.count -gt 0) {
        $str +=  "with where-filter:`n$($where | ConvertTo-Json -Depth 10)"
    }
    Write-Verbose $str


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
        $tcnt = Get-ICAPI -endpoint "$endpoint/count" -where $where -ErrorAction 0 -WarningAction 0 -verbose:$false
        if ($tcnt) {
            $total = [int]$tcnt.'count'
        } else {
            Write-Debug "Couldn't get a count from $url/count"
            $total = "N/A"       
        }

        if ($total.Gettype() -ne [int]) {
            $NoCount = $true
        }
        elseif ($total -ge $Globallimit) {
            Write-Warning "Your filter will return $total objects! You are limited to $GlobalLimit results per query.
                Database performance can be severely degraded in large queries so dumping the database via the API is not advised. 
                Try refining your query further with a 'where' filter or ask Infocyte for a data export by emailing support@infocyte.com. "
            return
        }
        elseif ($total -gt $resultlimit -AND -NOT $NoLimit) {
            Write-Warning "Found $total objects with this filter. Returning first $resultlimit.
                Use a tighter 'where' filter or the -NoLimit switch to get more."
        } 
        else {
            Write-Debug "Found $total objects with this filter."
        }

        $body['filter'] = $filter | ConvertTo-JSON -Depth 10 -Compress
    }

    $timer = [system.diagnostics.stopwatch]::StartNew()
    $times = @()

    while ($more) {
        try {
            $pc = [math]::floor($skip*100/$total); if ($pc -gt 100) { Write-Debug "`$pc is above 100! `$n=$n"; $pc = 100 }
        } catch {
            $pc = -1
        }
        if (-NOT $NoCount -AND $total -ge 100) {
            Write-Progress -Activity "Getting Data from Infocyte API" -status "Requesting data from $url [$skip of $total] ($pc)" -PercentComplete $pc
        }
        Write-Debug "Sending $url this Body as 'application/json':`n$($body|convertto-json)"
        $at = $timer.Elapsed
        #try {
        $Objects = Invoke-RestMethod $url -Body $body -Method GET -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential -Verbose:$DebugPreference
        #} catch {
        #    $StatusCode = "$($_.Exception.Response.StatusCode)($($_.Exception.Response.StatusCode.value__))"
        #    Write-Warning "ERROR[$StatusCode]: $url`n$($body|convertto-json -compress)`n$($_.Exception.Message)"
        #}
        $bt = $timer.Elapsed
        $e = ($bt - $at).TotalMilliseconds
        $times += $e
        Write-Debug "Last Request: $($e.ToString("#.#"))ms"

        if ($CountOnly) {
            if ($Objects.count -AND $Objects.count.GetType() -in @([int],[int64])) {
                return [int]$Objects.count
            } else {
                return $Objects
            }
        }

        if ($Objects) {
            if ($Objects.count) {
                $count += $Objects.count
            } else {
                write-debug "Couldn't count $objects. Using 1."
                $count += 1
            }

            Write-Output $Objects

            if ($count -ge $Globallimit) {
                Write-Warning "Reached Global Limit of $GlobalLimit results."
                $more = $false
            }
            elseif ($Objects.count -lt $resultlimit -OR -NOT $NoLimit) {
                $more = $false
            }
            
            # Set up next Page
            if ($more) {
                $body.remove('filter') | Out-Null
                $skip += $resultlimit
            
                if ($more -AND $null -eq $lastId) {
                    $lastId = $Objects[-1].id
                    $filter['where'] += @{ id = @{ gt = $lastId } }
                } 
                elseif ($more) {
                    $lastId = $Objects[-1].id
                    $filter['where']['id']['gt'] = $lastId
                }
                $body['filter'] = $filter | ConvertTo-Json -Depth 10 -Compress
            }   
            
        } else {
            Write-Debug "No results from last call."
            $more = $false
        }
    }
    $timer.Stop()
    $TotalTime = $timer.Elapsed
    $AveTime = ($times | Measure-Object -Average).Average
    $MaxTime = ($times | Measure-Object -Maximum).Maximum
    if (-NOT $NoCount -AND $total -gt 100) {
        Write-Progress -Activity "Getting Data from Infocyte API" -Completed
    }
    if (-NOT $NoCount) {
        Write-Verbose "Received $count of $total objects from $url in $($TotalTime.TotalSeconds.ToString("#.####")) Seconds (Page Request times: Ave= $($AveTime.ToString("#"))ms, Max= $($MaxTime.ToString("#"))ms)"
    }
}


# Used with all other rest methods. Pass a body (hashtable) and it will add authentication.
function Invoke-ICAPI {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [String]$Endpoint,

        [parameter(Mandatory=$true)]
        [ValidateSet(
            "GET",
            "POST",
            "DELETE",
            "PUT",
            "PATCH"
        )]
        [String]$Method,

        [parameter(Mandatory=$false, HelpMessage="Provide a hashtable.")]
        [HashTable]$body
    )

    if ($Global:ICToken) {
        $headers = @{
            Authorization = $Global:ICToken
        }
    } else {
        Throw "API Token not set! Use Set-ICToken to set your token to an Infocyte instance."
    }

    $url = "$($Global:HuntServerAddress)/api/$Endpoint"
    Write-verbose "Sending $method command to $url with Body: `n$($body | ConvertTo-JSON -Depth 10)"
    if ($body) {
        $json = $body | ConvertTo-JSON -Depth 10 -Compress
    }
    Invoke-RestMethod -Uri $url -headers $headers -body $json -Method $method -ContentType 'application/json' -Proxy $Global:Proxy -ProxyCredential $Global:ProxyCredential
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

<#
.SYNOPSIS
	Helper function to simplify creating dynamic parameters

.DESCRIPTION
	Helper function to simplify creating dynamic parameters.

	Example use cases:
		Include parameters only if your environment dictates it
		Include parameters depending on the value of a user-specified parameter
		Provide tab completion and intellisense for parameters, depending on the environment

	Please keep in mind that all dynamic parameters you create, will not have corresponding variables created.
		Use New-DynamicParameter with 'CreateVariables' switch in your main code block,
		('Process' for advanced functions) to create those variables.
		Alternatively, manually reference $PSBoundParameters for the dynamic parameter value.

	This function has two operating modes:

	1. All dynamic parameters created in one pass using pipeline input to the function. This mode allows to create dynamic parameters en masse,
	with one function call. There is no need to create and maintain custom RuntimeDefinedParameterDictionary.

	2. Dynamic parameters are created by separate function calls and added to the RuntimeDefinedParameterDictionary you created beforehand.
	Then you output this RuntimeDefinedParameterDictionary to the pipeline. This allows more fine-grained control of the dynamic parameters,
	with custom conditions and so on.

.NOTES
	Credits to jrich523 and ramblingcookiemonster for their initial code and inspiration:
		https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1
		http://ramblingcookiemonster.wordpress.com/2014/11/27/quick-hits-credentials-and-dynamic-parameters/
		http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/

	Credit to BM for alias and type parameters and their handling

.PARAMETER Name
	Name of the dynamic parameter

.PARAMETER Type
	Type for the dynamic parameter.  Default is string

.PARAMETER Alias
	If specified, one or more aliases to assign to the dynamic parameter

.PARAMETER Mandatory
	If specified, set the Mandatory attribute for this dynamic parameter

.PARAMETER Position
	If specified, set the Position attribute for this dynamic parameter

.PARAMETER HelpMessage
	If specified, set the HelpMessage for this dynamic parameter

.PARAMETER DontShow
	If specified, set the DontShow for this dynamic parameter.
	This is the new PowerShell 4.0 attribute that hides parameter from tab-completion.
	http://www.powershellmagazine.com/2013/07/29/pstip-hiding-parameters-from-tab-completion/

.PARAMETER ValueFromPipeline
	If specified, set the ValueFromPipeline attribute for this dynamic parameter

.PARAMETER ValueFromPipelineByPropertyName
	If specified, set the ValueFromPipelineByPropertyName attribute for this dynamic parameter

.PARAMETER ValueFromRemainingArguments
	If specified, set the ValueFromRemainingArguments attribute for this dynamic parameter

.PARAMETER ParameterSetName
	If specified, set the ParameterSet attribute for this dynamic parameter. By default parameter is added to all parameters sets.

.PARAMETER AllowNull
	If specified, set the AllowNull attribute of this dynamic parameter

.PARAMETER AllowEmptyString
	If specified, set the AllowEmptyString attribute of this dynamic parameter

.PARAMETER AllowEmptyCollection
	If specified, set the AllowEmptyCollection attribute of this dynamic parameter

.PARAMETER ValidateNotNull
	If specified, set the ValidateNotNull attribute of this dynamic parameter

.PARAMETER ValidateNotNullOrEmpty
	If specified, set the ValidateNotNullOrEmpty attribute of this dynamic parameter

.PARAMETER ValidateRange
	If specified, set the ValidateRange attribute of this dynamic parameter

.PARAMETER ValidateLength
	If specified, set the ValidateLength attribute of this dynamic parameter

.PARAMETER ValidatePattern
	If specified, set the ValidatePattern attribute of this dynamic parameter

.PARAMETER ValidateScript
	If specified, set the ValidateScript attribute of this dynamic parameter

.PARAMETER ValidateSet
	If specified, set the ValidateSet attribute of this dynamic parameter

.PARAMETER Dictionary
	If specified, add resulting RuntimeDefinedParameter to an existing RuntimeDefinedParameterDictionary.
	Appropriate for custom dynamic parameters creation.

	If not specified, create and return a RuntimeDefinedParameterDictionary
	Aappropriate for a simple dynamic parameter creation.

.EXAMPLE
	Create one dynamic parameter.

	This example illustrates the use of New-DynamicParameter to create a single dynamic parameter.
	The Drive's parameter ValidateSet is populated with all available volumes on the computer for handy tab completion / intellisense.

	Usage: Get-FreeSpace -Drive <tab>

	function Get-FreeSpace
	{
		[CmdletBinding()]
		Param()
		DynamicParam
		{
			# Get drive names for ValidateSet attribute
			$DriveList = ([System.IO.DriveInfo]::GetDrives()).Name

			# Create new dynamic parameter
			New-DynamicParameter -Name Drive -ValidateSet $DriveList -Type ([array]) -Position 0 -Mandatory
		}

		Process
		{
			# Dynamic parameters don't have corresponding variables created,
			# you need to call New-DynamicParameter with CreateVariables switch to fix that.
			New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters

			$DriveInfo = [System.IO.DriveInfo]::GetDrives() | Where-Object {$Drive -contains $_.Name}
			$DriveInfo |
				ForEach-Object {
					if(!$_.TotalFreeSpace)
					{
						$FreePct = 0
					}
					else
					{
						$FreePct = [System.Math]::Round(($_.TotalSize / $_.TotalFreeSpace), 2)
					}
					New-Object -TypeName psobject -Property @{
						Drive = $_.Name
						DriveType = $_.DriveType
						'Free(%)' = $FreePct
					}
				}
		}
	}

.EXAMPLE
	Create several dynamic parameters not using custom RuntimeDefinedParameterDictionary (requires piping).

	In this example two dynamic parameters are created. Each parameter belongs to the different parameter set, so they are mutually exclusive.

	The Drive's parameter ValidateSet is populated with all available volumes on the computer.
	The DriveType's parameter ValidateSet is populated with all available drive types.

	Usage: Get-FreeSpace -Drive <tab>
		or
	Usage: Get-FreeSpace -DriveType <tab>

	Parameters are defined in the array of hashtables, which is then piped through the New-Object to create PSObject and pass it to the New-DynamicParameter function.
	Because of piping, New-DynamicParameter function is able to create all parameters at once, thus eliminating need for you to create and pass external RuntimeDefinedParameterDictionary to it.

	function Get-FreeSpace
	{
		[CmdletBinding()]
		Param()
		DynamicParam
		{
			# Array of hashtables that hold values for dynamic parameters
			$DynamicParameters = @(
				@{
					Name = 'Drive'
					Type = [array]
					Position = 0
					Mandatory = $true
					ValidateSet = ([System.IO.DriveInfo]::GetDrives()).Name
					ParameterSetName = 'Drive'
				},
				@{
					Name = 'DriveType'
					Type = [array]
					Position = 0
					Mandatory = $true
					ValidateSet = [System.Enum]::GetNames('System.IO.DriveType')
					ParameterSetName = 'DriveType'
				}
			)

			# Convert hashtables to PSObjects and pipe them to the New-DynamicParameter,
			# to create all dynamic paramters in one function call.
			$DynamicParameters | ForEach-Object {New-Object PSObject -Property $_} | New-DynamicParameter
		}
		Process
		{
			# Dynamic parameters don't have corresponding variables created,
			# you need to call New-DynamicParameter with CreateVariables switch to fix that.
			New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters

			if($Drive)
			{
				$Filter = {$Drive -contains $_.Name}
			}
			elseif($DriveType)
			{
				$Filter =  {$DriveType -contains  $_.DriveType}
			}

			$DriveInfo = [System.IO.DriveInfo]::GetDrives() | Where-Object $Filter
			$DriveInfo |
				ForEach-Object {
					if(!$_.TotalFreeSpace)
					{
						$FreePct = 0
					}
					else
					{
						$FreePct = [System.Math]::Round(($_.TotalSize / $_.TotalFreeSpace), 2)
					}
					New-Object -TypeName psobject -Property @{
						Drive = $_.Name
						DriveType = $_.DriveType
						'Free(%)' = $FreePct
					}
				}
		}
	}

.EXAMPLE
	Create several dynamic parameters, with multiple Parameter Sets, not using custom RuntimeDefinedParameterDictionary (requires piping).

	In this example three dynamic parameters are created. Two of the parameters are belong to the different parameter set, so they are mutually exclusive.
	One of the parameters belongs to both parameter sets.

	The Drive's parameter ValidateSet is populated with all available volumes on the computer.
	The DriveType's parameter ValidateSet is populated with all available drive types.
	The DriveType's parameter ValidateSet is populated with all available drive types.
	The Precision's parameter controls number of digits after decimal separator for Free Space percentage.

	Usage: Get-FreeSpace -Drive <tab> -Precision 2
		or
	Usage: Get-FreeSpace -DriveType <tab> -Precision 2

	Parameters are defined in the array of hashtables, which is then piped through the New-Object to create PSObject and pass it to the New-DynamicParameter function.
	If parameter with the same name already exist in the RuntimeDefinedParameterDictionary, a new Parameter Set is added to it.
	Because of piping, New-DynamicParameter function is able to create all parameters at once, thus eliminating need for you to create and pass external RuntimeDefinedParameterDictionary to it.

	function Get-FreeSpace
	{
		[CmdletBinding()]
		Param()
		DynamicParam
		{
			# Array of hashtables that hold values for dynamic parameters
			$DynamicParameters = @(
				@{
					Name = 'Drive'
					Type = [array]
					Position = 0
					Mandatory = $true
					ValidateSet = ([System.IO.DriveInfo]::GetDrives()).Name
					ParameterSetName = 'Drive'
				},
				@{
					Name = 'DriveType'
					Type = [array]
					Position = 0
					Mandatory = $true
					ValidateSet = [System.Enum]::GetNames('System.IO.DriveType')
					ParameterSetName = 'DriveType'
				},
				@{
					Name = 'Precision'
					Type = [int]
					# This will add a Drive parameter set to the parameter
					Position = 1
					ParameterSetName = 'Drive'
				},
				@{
					Name = 'Precision'
					# Because the parameter already exits in the RuntimeDefinedParameterDictionary,
					# this will add a DriveType parameter set to the parameter.
					Position = 1
					ParameterSetName = 'DriveType'
				}
			)

			# Convert hashtables to PSObjects and pipe them to the New-DynamicParameter,
			# to create all dynamic paramters in one function call.
			$DynamicParameters | ForEach-Object {New-Object PSObject -Property $_} | New-DynamicParameter
		}
		Process
		{
			# Dynamic parameters don't have corresponding variables created,
			# you need to call New-DynamicParameter with CreateVariables switch to fix that.
			New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters

			if($Drive)
			{
				$Filter = {$Drive -contains $_.Name}
			}
			elseif($DriveType)
			{
				$Filter = {$DriveType -contains  $_.DriveType}
			}

			if(!$Precision)
			{
				$Precision = 2
			}

			$DriveInfo = [System.IO.DriveInfo]::GetDrives() | Where-Object $Filter
			$DriveInfo |
				ForEach-Object {
					if(!$_.TotalFreeSpace)
					{
						$FreePct = 0
					}
					else
					{
						$FreePct = [System.Math]::Round(($_.TotalSize / $_.TotalFreeSpace), $Precision)
					}
					New-Object -TypeName psobject -Property @{
						Drive = $_.Name
						DriveType = $_.DriveType
						'Free(%)' = $FreePct
					}
				}
		}
	}

.Example
	Create dynamic parameters using custom dictionary.

	In case you need more control, use custom dictionary to precisely choose what dynamic parameters to create and when.
	The example below will create DriveType dynamic parameter only if today is not a Friday:

	function Get-FreeSpace
	{
		[CmdletBinding()]
		Param()
		DynamicParam
		{
			$Drive = @{
				Name = 'Drive'
				Type = [array]
				Position = 0
				Mandatory = $true
				ValidateSet = ([System.IO.DriveInfo]::GetDrives()).Name
				ParameterSetName = 'Drive'
			}

			$DriveType =  @{
				Name = 'DriveType'
				Type = [array]
				Position = 0
				Mandatory = $true
				ValidateSet = [System.Enum]::GetNames('System.IO.DriveType')
				ParameterSetName = 'DriveType'
			}

			# Create dictionary
			$DynamicParameters = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

			# Add new dynamic parameter to dictionary
			New-DynamicParameter @Drive -Dictionary $DynamicParameters

			# Add another dynamic parameter to dictionary, only if today is not a Friday
			if((Get-Date).DayOfWeek -ne [DayOfWeek]::Friday)
			{
				New-DynamicParameter @DriveType -Dictionary $DynamicParameters
			}

			# Return dictionary with dynamic parameters
			$DynamicParameters
		}
		Process
		{
			# Dynamic parameters don't have corresponding variables created,
			# you need to call New-DynamicParameter with CreateVariables switch to fix that.
			New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters

			if($Drive)
			{
				$Filter = {$Drive -contains $_.Name}
			}
			elseif($DriveType)
			{
				$Filter =  {$DriveType -contains  $_.DriveType}
			}

			$DriveInfo = [System.IO.DriveInfo]::GetDrives() | Where-Object $Filter
			$DriveInfo |
				ForEach-Object {
					if(!$_.TotalFreeSpace)
					{
						$FreePct = 0
					}
					else
					{
						$FreePct = [System.Math]::Round(($_.TotalSize / $_.TotalFreeSpace), 2)
					}
					New-Object -TypeName psobject -Property @{
						Drive = $_.Name
						DriveType = $_.DriveType
						'Free(%)' = $FreePct
					}
				}
		}
	}
#>
Function New-DynamicParameter {
    [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'DynamicParameter')]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$Type = [int],

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$Alias,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$Mandatory,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$Position,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$HelpMessage,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DontShow,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipeline,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipelineByPropertyName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromRemainingArguments,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$ParameterSetName = '__AllParameterSets',

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyString,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyCollection,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNullOrEmpty,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2, 2)]
        [int[]]$ValidateCount,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2, 2)]
        [int[]]$ValidateRange,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2, 2)]
        [int[]]$ValidateLength,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidateSet,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {
                if (!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary])) {
                    Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
                }
                $true
            })]
        $Dictionary = $false,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$CreateVariables,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {
                # System.Management.Automation.PSBoundParametersDictionary is an internal sealed class,
                # so one can't use PowerShell's '-is' operator to validate type.
                if ($_.GetType().Name -ne 'PSBoundParametersDictionary') {
                    Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
                }
                $true
            })]
        $BoundParameters
    )

    Begin {
        Write-Verbose 'Creating new dynamic parameters dictionary'
        $InternalDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        Write-Verbose 'Getting common parameters'
        function _temp { [CmdletBinding()] Param() }
        $CommonParameters = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if ($CreateVariables) {
            Write-Verbose 'Creating variables from bound parameters'
            Write-Debug 'Picking out bound parameters that are not in common parameters set'
            $BoundKeys = $BoundParameters.Keys | Where-Object { $CommonParameters -notcontains $_ }

            foreach ($Parameter in $BoundKeys) {
                Write-Debug "Setting existing variable for dynamic parameter '$Parameter' with value '$($BoundParameters.$Parameter)'"
                Set-Variable -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
            }
        }
        else {
            Write-Verbose 'Looking for cached bound parameters'
            Write-Debug 'More info: https://beatcracker.wordpress.com/2014/12/18/psboundparameters-pipeline-and-the-valuefrompipelinebypropertyname-parameter-attribute'
            $StaleKeys = @()
            $StaleKeys = $PSBoundParameters.GetEnumerator() |
                ForEach-Object {
                    if ($_.Value.PSobject.Methods.Name -match '^Equals$') {
                        # If object has Equals, compare bound key and variable using it
                        if (!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                            $_.Key
                        }
                    }
                    else {
                        # If object doesn't has Equals (e.g. $null), fallback to the PowerShell's -ne operator
                        if ($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                            $_.Key
                        }
                    }
                }
            if ($StaleKeys) {
                [string[]]"Found $($StaleKeys.Count) cached bound parameters:" + $StaleKeys | Write-Debug
                Write-Verbose 'Removing cached bound parameters'
                $StaleKeys | ForEach-Object { [void]$PSBoundParameters.Remove($_) }
            }

            # Since we rely solely on $PSBoundParameters, we don't have access to default values for unbound parameters
            Write-Verbose 'Looking for unbound parameters with default values'

            Write-Debug 'Getting unbound parameters list'
            $UnboundParameters = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator() |
                # Find parameters that are belong to the current parameter set
                Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                Select-Object -ExpandProperty Key |
                # Find unbound parameters in the current parameter set
                Where-Object { $PSBoundParameters.Keys -notcontains $_ }

            # Even if parameter is not bound, corresponding variable is created with parameter's default value (if specified)
            Write-Debug 'Trying to get variables with default parameter value and create a new bound parameter''s'
            $tmp = $null
            foreach ($Parameter in $UnboundParameters) {
                $DefaultValue = Get-Variable -Name $Parameter -ValueOnly -Scope 0
                if (!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                    $PSBoundParameters.$Parameter = $DefaultValue
                    Write-Debug "Added new parameter '$Parameter' with value '$DefaultValue'"
                }
            }

            if ($Dictionary) {
                Write-Verbose 'Using external dynamic parameter dictionary'
                $DPDictionary = $Dictionary
            }
            else {
                Write-Verbose 'Using internal dynamic parameter dictionary'
                $DPDictionary = $InternalDictionary
            }

            Write-Verbose "Creating new dynamic parameter: $Name"

            # Shortcut for getting local variables
            $GetVar = { Get-Variable -Name $_ -ValueOnly -Scope 0 }

            # Strings to match attributes and validation arguments
            $AttributeRegex = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $ValidationRegex = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $AliasRegex = '^Alias$'

            Write-Debug 'Creating new parameter''s attirubutes object'
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute

            Write-Debug 'Looping through the bound parameters, setting attirubutes...'
            switch -regex ($PSBoundParameters.Keys) {
                $AttributeRegex {
                    Try {
                        $ParameterAttribute.$_ = . $GetVar
                        Write-Debug "Added new parameter attribute: $_"
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }

            if ($DPDictionary.Keys -contains $Name) {
                Write-Verbose "Dynamic parameter '$Name' already exist, adding another parameter set to it"
                $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
            }
            else {
                Write-Verbose "Dynamic parameter '$Name' doesn't exist, creating"

                Write-Debug 'Creating new attribute collection object'
                $AttributeCollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]

                Write-Debug 'Looping through bound parameters, adding attributes'
                switch -regex ($PSBoundParameters.Keys) {
                    $ValidationRegex {
                        Try {
                            $ParameterOptions = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterOptions)
                            Write-Debug "Added attribute: $_"
                        }
                        Catch {
                            $_
                        }
                        continue
                    }

                    $AliasRegex {
                        Try {
                            $ParameterAlias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterAlias)
                            Write-Debug "Added alias: $_"
                            continue
                        }
                        Catch {
                            $_
                        }
                    }
                }

                Write-Debug 'Adding attributes to the attribute collection'
                $AttributeCollection.Add($ParameterAttribute)

                Write-Debug 'Finishing creation of the new dynamic parameter'
                $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)

                Write-Debug 'Adding dynamic parameter to the dynamic parameter dictionary'
                $DPDictionary.Add($Name, $Parameter)
            }
        }
    }

    End {
        if (!$CreateVariables -and !$Dictionary) {
            Write-Verbose 'Writing dynamic parameter dictionary to the pipeline'
            $DPDictionary
        }
    }
}