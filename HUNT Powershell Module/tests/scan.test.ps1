
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
        $r = Invoke-ICSCan -TargetGroupId $TgId -where @{ hostname = "fake" } -ErrorVariable err
        $r | Should -Be $null
        #$err.count | Should -Not -Be 0
        $err.Exception[-1].Message | Should -Match ".*Could not find target with given filters.*"   
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
        $Extensions = Get-ICExtension
        $ext = $Extensions | Where-Object { $_.name -eq "Terminate Process" } | Select-Object -First 1
    }
    AfterEach {
        if ($r.userTaskId) {
            Start-Sleep 2
            Invoke-ICAPI -Method POST -endpoint "userTasks/$($r.userTaskId)/cancel"
        }
        $r = $null
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
        $r = Invoke-ICScanTarget -target "fake" -ErrorVariable err
        $r.userTaskId | Should -Be $null
        $err.count | Should -Not -Be 0
        $err.Exception[-1].Message | Should -Match "was not found with an active agent or accessible address entry within a Target Group"
        
    }

    It "Throws on non-existant extensionId" {
        { $r = Invoke-ICResponse -target $testhost -ExtensionId "1ffd7a3a-ba60-4414-8991-52aa54615e73" } | Should -Throw
        $Error[0].Exception.Message | Should -Match "Extension with id 1ffd7a3a-ba60-4414-8991-52aa54615e73 does not exist!"
    }

    It "Throws error on non-existant extensionName" {
        { $r = Invoke-ICResponse -target $testhost -ExtensionName "fake" } | Should -Throw
        $Error[0].Exception.Message | Should -Match "Extension with name fake does not exist!"
    }
}

Describe "ICScanTarget Results" {

    It "Invokes a scan on a single target" {
        $scan = Invoke-ICScanTarget -target $testhost
        $scan.userTaskId | Should -Match $GUID_REGEX
    }

    It "Gets scan status" {
        Start-Sleep 2
        $task = Get-ICTask -id $scan.userTaskId
        $task.status | Should -Be "Active"
        while ($task.status -eq "Active")
        {
            Start-Sleep 5
            $task = Get-ICTask -id $scan.userTaskId
        }
        $task.status | Should -Be "Completed"
    }

    It "Gets scan results" {
        $results = Get-ICScan -id $task.data.scanId
        $results.hostCount | Should -Be 1
    }
}

Describe "ICResponse Results" {
    BeforeAll {
        $Extensions = Get-ICExtension
        $ext = $Extensions | Where-Object { $_.name -eq "Terminate Process" } | Select-Object -First 1
    }

    It "Invokes a response on a target by extensionName" {
        $r = Invoke-ICResponse -target $testhost -ExtensionName "Terminate Process"
        $r.userTaskId | Should -Match $GUID_REGEX
    }
    
    It "Gets scan status" {
        Start-Sleep 2
        $task = Get-ICTask -id $r.userTaskId
        $task.status | Should -Be "Active"
        while ($task.status -eq "Active") {
            Start-Sleep 5
            $task = Get-ICTask -id $r.userTaskId
        }
        $task.status | Should -Be "Completed"
    }

    It "Gets response results" {
        $results = Get-ICObject -Type Extension -ScanId $task.data.scanId -AllInstances
        $results.extensionId | Should -Be $ext.id
        $results.success | Should -Be $true
        $results.threatStatus | Should -Be "Unknown"
    }

}



