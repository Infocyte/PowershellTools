
function Update-ICCompromisedHosts {
    Param(
        [parameter(HelpMessage="The field or fields to return.")]
        [String[]]$flags=@("Verified Bad")
    )
        
    $FileTypes = @(
        "Process",
        "Module",
        "Driver",
        "MemScan",
        "Artifact",
        "Autostart",
        "Script"
    )

    #BoxId
    $Boxes = Get-ICBox -Global -Last 90
    $Boxes | ForEach-Object {
        $BoxId = $_.Id
        $where = @{
            boxId = $BoxId
            or = @(
                @{ threatName = "Bad" },
                @{ threatName = "Blacklist" }
            )
        }
        $flags | ForEach-Object {
            $where['or'] += @{ flagName = $_ }
        }
        $CompromisedFiles = Get-ICObject -Type File -BoxId $_.id -Where $where -AllInstances
        
        # Unique hostnames
        $CompromisedHosts = $CompromisedFiles | Sort-Object hostId -Unique | Select-Object boxId, hostId, hostname

        $CompromisedHosts.hostId | ForEach-Object {
            $SQLQuery = "Select id, hostid, boxid, scanid, compromised from boxhost where boxid='$BoxId' AND hostid='$_'"
            $results = saas sql -d cpxextext4572 --sql $query | convertfrom-csv
        }

    }
        
    $Endpoint = "BoxExtensionInstances"
    $fields = @("id", "extensionId", "extensionVersionId", "hostname", "ip", "sha256",
        "hostScanId", "success", "threatStatus", "name", "hostId", "scanId", "scannedOn", "startedOn", "endedOn", "output")
    $result = Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
    $fields = @("id","extensionId","extensionVersionId","boxId","hostScanId","success","threatStatus","name","hostId","scanId")
    Write-Verbose "Aggregating Extensions."
    $extensioninstances = Get-ICObject -Type "Extension" -BoxId $BoxId -where $where -fields $fields -AllInstances -NoLimit:$NoLimit

    Get-ICAPI -Endpoint $Endpoint -where $where -fields $fields -NoLimit:$NoLimit -CountOnly:$CountOnly
}

[String[]]$flags=@("Verified Bad")
$FileTypes = @(
    "Process",
    "Module",
    "Driver",
    "MemScan",
    "Artifact",
    "Autostart",
    "Script"
)

$Boxes = Get-ICBox -Global
$Boxes | ForEach-Object {
    $BoxId = $_.Id
    $where = @{
        boxId = $BoxId
        or = @(
            @{ threatName = "Bad" },
            @{ threatName = "Blacklist" }
        )
    }
    $flags | ForEach-Object {
        $where['or'] += @{ flagName = $_ }
    }
    $CompromisedFiles = Get-ICObject -Type File -BoxId $boxid -Where $where -AllInstances
    
    # Unique hostnames
    $CompromisedHosts = $CompromisedFiles | Sort-Object hostId -Unique | Select-Object hostname -ExpandProperty hostname

    $hostscans = @()
    $CompromisedHostIds | % {
    $hostscans += saas sql -d cpxextext4572 --sql "Select id, hostid, boxid, scanid, compromised from boxhost where boxid='$BoxId' AND hostid='$_'" | convertfrom-csv
    }
    $hostscans | % {
    $Query = "UPDATE hostscan SET compromised = true WHERE id='$_'"
    Write-Host $Query
    saas sql -d cpxextext4572 --sql $Query | convertfrom-csv
    }
}





#$Query = "SELECT hostname, hostscanid, filerepid, flagname, threatname, compromised, boxid, scanid, hostid FROM boxprocessinstance, boxmoduleinstance, boxdriverinstance, boxmemscaninstance, boxautostartinstance, boxartifactinstance, boxscriptinstance WHERE boxid = $BoxId AND (threatname = 'Bad' OR threatname = 'Blacklist' or flagname = 'Verified Bad'"
       