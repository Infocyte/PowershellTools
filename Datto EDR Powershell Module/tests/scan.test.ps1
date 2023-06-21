
Describe "ScanSetup" {

    It "Creates Default ScanOptions" {
        $r = New-ICScanOptions
        $r.process | Should -Be $true
        $r.installed | Should -Be $false
    }

    It "Creates Empty ScanOptions" {
        $r = New-ICScanOptions -Empty
        $r.process | Should -Be $false
        $r.installed | Should -Be $false
    }

    It "Creates Custom ScanOptions" {
        $r = New-ICScanOptions -Options process,account,driver
        $r.process | Should -Be $true
        $r.account | Should -Be $true
        $r.driver | Should -Be $true
        $r.application | Should -Be $false
        $r.artifact | Should -Be $false
        $r.installed | Should -Be $false

    }
}

Describe "ICFindHosts and ICScan" {
    BeforeAll {
        $Address = Get-ICAddress -where @{ hostname = $Testhost } | where { $_.queryId } | select -First 1 
        $TgId = $Address.targetId
        $TgId | Should -Match $GUID_REGEX
        $TG = Get-ICTargetGroup -Id $TgId
        $TG | Should -Not -Be $null
        $Opts = New-ICScanOptions -Options process, account
    }

    AfterEach {
        if ($r.userTaskId) {
            Start-Sleep 2
            Invoke-ICAPI -Method POST -endpoint "userTasks/$($r.userTaskId)/cancel"
        }
        $r = $null
    }
    AfterAll {
        $tasks = Get-ICTask -where @{ status = "Active" } 
        $tasks | ? { $_.id } | % {
            Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
        }
    }
    
    It "Invokes an enumeration on a target group" {
        $r = Invoke-ICFindHosts -TargetGroupId $TgId
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Invokes a scan on a target group" {
        $r = Invoke-ICSCan -TargetGroupId $TgId
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Invokes a scan on a target group with a filter" {
        $r = Invoke-ICSCan -TargetGroupId $TgId -where @{ id = $Address.id }
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Returns null on a scan on a target group with an unmatched filter" {
        $r = Invoke-ICSCan -TargetGroupId $TgId -where @{ hostname = "fake" }
        $r | Should -Be $null
    }

    It "Task errors on a scan on a target group with a illegal filter" {
        $r = Invoke-ICSCan -TargetGroupId $TgId -where @{ id = "fake" }
        $r2 = $r | Get-ICTask
        $r2.status | Should -Be "Error"
    }

    It "Invokes a scan on a target group with options" {
        $r = Invoke-ICSCan -TargetGroupId $TgId -ScanOptions $Opts
        $r.userTaskId | Should -Match $GUID_REGEX
    }

}

Describe "ICScanTarget and ICResponse" {
    BeforeAll {
        $Ext = Get-ICExtension -where @{ name = "Terminate Process" }
    }
    AfterEach {
        if ($r.userTaskId) {
            Start-Sleep 3
            Invoke-ICAPI -Method POST -endpoint "userTasks/$($r.userTaskId)/cancel"
            Start-Sleep 1
            $r = $null
        }
        $task = $null
    }
    AfterAll {
        $tasks = Get-ICTask -where @{ status = "Active" } 
        $tasks | ? { $_.id } | % {
            Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
        }
    }

    It "Invokes a scan on a single target" {
        $r = Invoke-ICScanTarget -target $testhost
        $r.userTaskId | Should -Match $GUID_REGEX
        Start-Sleep 2
        $task = Get-ICTask -id $r.userTaskId
        $task.status | Should -Be "Active"
    }

    It "Invokes a response on a target by extensionId" {
        $r = Invoke-ICResponse -target $testhost -ExtensionId $ext.id
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Invokes a response on a target by extensionName" {
        $r = Invoke-ICResponse -target $testhost -ExtensionName "Terminate Process"
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Returns null for a scan on a non-existant target" {
        $r = Invoke-ICScanTarget -target "fake"
        $r.userTaskId | Should -Be $null        
    }

    It "Throws on non-existant extensionId" {
        { $r = Invoke-ICResponse -target $testhost -ExtensionId "1ffd7a3a-ba60-4414-8991-52aa54615e73" } | Should -Throw
        $Error[0].Exception.Message | Should -Match "Extension with id 1ffd7a3a-ba60-4414-8991-52aa54615e73 does not exist!"
    }

    It "Throws error on non-existant 
    extensionName" {
        { $r = Invoke-ICResponse -target $testhost -ExtensionName "fake" } | Should -Throw
        $Error[0].Exception.Message | Should -Match "Extension with name fake does not exist!"
    }
}

Describe "ICScanTarget Results" {
    BeforeAll {
        $a = Get-ICAlert | select -Last 1
    }
    AfterEach {
        $results = $null
    }
    AfterAll {
        $tasks = Get-ICTask -where @{ status = "Active" } 
        $tasks | ? { $_.id } | % {
            Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
        }
    }

    It "Invokes a scan on a single target" {
        $scan = Invoke-ICScanTarget -target $testhost
        $scan.userTaskId | Should -Match $GUID_REGEX
        Start-Sleep 5
        $task = Get-ICTask -id $scan.userTaskId
        $task.status | Should -Be "Active"
        $task.data.scanId | Should -Match $GUID_REGEX
    }

    It "Gets scan status" {
        Start-Sleep 1
        $Task = Get-ICTask | select -Last 1
        $task.status | Should -Be "Active"
        $task.data.scanId | Should -Match $GUID_REGEX 
    }

    It "Gets scan results" {
        $results = Get-ICScan -id $a.scanId
        $results.completedOn | Should -Not -Be $null
        $results.hostCount | Should -Be 1
    }

    It "Gets hostScan results from Get-ICHostScanResults" {
        $results = Get-ICHostScanResult -scanId $a.scanId -Hostname PegasusActual
        $results.hostname | Should -Be $testhost
        $results.success | Should -Be $True
    }

}

Describe "ICResponse Results" {
    BeforeAll {
        $Ext = Get-ICExtension -where @{ name = "Terminate Process" }
        $r = Get-ICObject -Type Extension -AllInstances -where @{ name = "Terminate Process"; hostname = $testhost } | select -Last 1
        $r.threatStatus | Should -Match "Good|Unknown"
        $r.output | Should -Not -Be $Null
    }
    AfterEach {
        $results = $null
    }
    AfterAll {
        $tasks = Get-ICTask -where @{ status = "Active" } 
        $tasks | ? { $_.id } | % {
            Invoke-ICAPI -Method POST -endpoint "userTasks/$($_.id)/cancel"
        }
    }

    It "Invokes a response on a target by extensionName" {
        $r2 = Invoke-ICResponse -target $testhost -ExtensionName "Terminate Process"
        $r2.userTaskId | Should -Match $GUID_REGEX
        Start-Sleep 5
        $task = Get-ICTask -id $r.userTaskId
        $task.status | Should -Be "Active"
    }
        
    It "Gets scan metadata" {
        $results = Get-ICScan -id $r.scanId
        $results.hostCount | Should -Be 1 
    }

    It "Gets response results with Get-ICResponseResult" {
        $results = Get-ICResponseResult -ScanId $r.scanId -hostname $testhost
        $results.extensionId | Should -Be $ext.id
        $results.success | Should -Be $true
        $results.threatStatus | Should -Match "Good|Unknown"
    }

}



