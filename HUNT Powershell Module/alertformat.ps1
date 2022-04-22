
# Add time window
function Get-ICAlert2 {
    [cmdletbinding(DefaultParameterSetName="Trailing")]
    param(
        [parameter(ValueFromPipeline)]
        [ValidateScript({ if ($_ -match $GUID_REGEX) { $true } else { throw "Incorrect input: $_.  Should be a guid."} })]
        [String]$Id,

        [parameter(
            ParameterSetName="Trailing",
            HelpMessage={"Trailing Days"})]
        [Int]$Trailing,

        [parameter(
            ParameterSetName="Time",
            HelpMessage={"Starting timestamp of items."})]
        [DateTime]$StartTime,

        [parameter(
            ParameterSetName="Time",
            HelpMessage={"Last timestamp of items. Default = Now"})]
        [DateTime]$EndTime,

        [Switch]$IncludeArchived,

        [parameter(HelpMessage="This will convert a hashtable into a JSON-encoded Loopback Where-filter: https://loopback.io/doc/en/lb2/Where-filter ")]
        [HashTable]$where=@{},

        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$fields,
        
        [Switch]$NoLimit,
        [Switch]$CountOnly
    )

    PROCESS {
        
        $Timefield = "createdOn"

        Write-Debug "ParameterSetName: $($PSCmdlet.ParameterSetName)"
        Write-Debug "Trailing: $Trailing, StartTime: $StartTime, EndTime: $EndTime, Timefield: $Timefield, Where:`n$($where|ConvertTo-Json -depth 10)"
    
        switch ( $PSCmdlet.ParameterSetName )
        {
            "Trailing" {
                if ($Trailing) {
                    $where = New-ICFilter -Where $where -Trailing $Trailing -timefield $Timefield
                }
            }
            "Time" { 
                $where = New-ICFilter -Where $where -StartTime $StartTime -EndTime $EndTime -timefield $Timefield
                Write-Verbose "$($where|ConvertTo-Json -depth 10)"
            }
        }
        
        $Endpoint = "Alerts"
        if ($Id) {
            $CountOnly = $false
            $Endpoint += "/$Id"
        } else {
            if ($Trailing -gt 30 -OR ($StartTime -AND $StartTime -lt (Get-Date).AddDays(-30))) {
                Write-Verbose "Querying Alert Archive Table for alerts older than 30 days..."
                Get-ICAPI -Endpoint "$($Endpoint)archive" -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
            }
            elseif (-NOT ($IncludeArchived -OR $Where['archived'] -OR $where['and'].Keys -contains 'archived')) {
                $Where['archived'] = $FALSE
            }
        }
        $Alerts = Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly

        $a = $global:HuntServerAddress | select-string "https://(.*)\.infocyte\.com"
        $tenant = $a.Matches.Groups[1].Value

        $Alerts | ForEach-Object {
            
            # Transform data payload
            $alert = $_
            $payload = $_.data
            if ($payload.name) {
                $payload | Add-Member -MemberType NoteProperty -Name fileName -Value $payload.name
                $payload.PSObject.Properties.Remove('name')

                $payload | Add-Member -MemberType NoteProperty -Name filePath -Value $payload.path
                $payload.PSObject.Properties.Remove('path')

                $payload | Add-Member -MemberType NoteProperty -Name fileSize -Value $payload.size
                $payload.PSObject.Properties.Remove('size')

                
                # Create Summary
                $summary = "todo"
                Switch ($payload.type) {
                    'process' {
                        $summary = "The $($payload.signature.type -eq "Catalog" ? 'trusted ' : '')$($payload.type) $($payload.fileName) (pid: $($payload.pid)) owned by '$($payload.owner)' performed a '$($alert.mitreTactic)' behavior that matched the following rule: '$($alert.sourceName)'. $($payload.realTime ? "Event occured at $($payload.eventTime)" : "Process was found running on $([DateTime]$payload.foundOn) and started on ]$([DateTime]$payload.processStarted)")'"
                    }
                    'autostart' {
                        $summary = "The $($payload.type) $($payload.fileName) is set to persist in autostart location: [$($payload.autostartType)]$($payload.place)) using $($alert.mitreTactic) technique '$($alert.mitreId)' that matched the following rule: '$($alert.sourceName)'."
                    }
                    'artifact' {
                        $summary = "The $($payload.type) $($payload.fileName) was found on disk with a $($payload.artifactType) reference. This matches a '$($alert.MitreTactic)' technique matching the following rule: '$($alert.sourceName)'"
                    
                    }
                    'connection' {
                        #$summary = "The $($payload.type) $($payload.fileName) (pid: $($payload.pid)) owned by '$($payload.owner)' performed a '$($alert.MitreTactic)' behavior that matched the following rule: '$($alert.sourceName)'"
                    
                    }
                    'account' {
                        #$summary = "The $($payload.type) $($payload.fileName) (pid: $($payload.pid)) owned by '$($payload.owner)' performed a '$($alert.MitreTactic)' behavior that matched the following rule: '$($alert.sourceName)'"
                    
                    }
                    default {

                    }
                }
                
                $payload | Add-Member -MemberType NoteProperty -Name summary -Value $summary
                                
                # add detectionName
                $fileDetails = Get-ICFileDetail -sha1 $payload.sha1
                $detectionName = $fileDetails.avResults.results.PSObject.Properties | ForEach-Object { [PSCustomObject] @{
                        av = $_.Value.av
                        name = $_.Value.name
                        source = $_.Value.source
                        detected = $_.Value.detected
                    }
                } | Where-Object { $_.detected } | Select-Object name -ExpandProperty name -First 1
                $payload | Add-Member -MemberType NoteProperty -Name detectionName -Value $detectionName
            }

            $NewAlert = [PSCustomObject]@{
                id = $_.id
                createdOn = [DateTime]$_.createdOn
                alertType = $_.sourceType
                tenant = $tenant
                hostname = $_.hostname
                rmmDeviceId = $_.agentId # placeholder
                agentId = $_.agentId
                ruleId = $_.sourceId
                ruleName = $_.sourceName
                message = $_.description
                description = $null
                severity = $_.severity
                signal = $_.signal
                payload = $_.data
            }
            $NewAlert
        }
    }
}