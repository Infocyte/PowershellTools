
Describe "ScanSetup" {

    It "Creates ScanOptions" {
        $r = New-ICScanOptions
        $r.process | Should -Be $true
        $r.installed | Should -Be $false
    }
}

Describe "ICFindHosts and ICScan" {
    BeforeAll {
        $Address = Get-ICAddress -where @{ hostname = $Testhost } | select -First 1 
        $TgId = $Address.targetId
        $Opts = New-ICScanOptions
    }

    AfterEach {
        Start-Sleep 2
        Invoke-ICAPI -Method POST -endpoint "userTasks/$($r.userTaskId)/cancel"
    }
    
    It "Invokes an enumeration on a target group" {
        $r = Invoke-ICFindHosts -TargetGroupId $TgId
        $r.userTaskId | Should -Match $GUID_REGEX
        
    }

    It "Invokes a scan on a target group" {
        $r = Invoke-ICSCan -TargetGroupId $TgId
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Invokes a scan on a target group with options" {
        $r = Invoke-ICSCan -TargetGroupId $TgId -ScanOptions $Opts
        $r.userTaskId | Should -Match $GUID_REGEX
    }

}

Describe "ICScanTarget and ICResponse" {
    BeforeAll {
        $Extensions = Get-ICExtension
    }
    AfterEach {
        Start-Sleep 2
        Invoke-ICAPI -Method POST -endpoint "userTasks/$($r.userTaskId)/cancel"
    }

    It "Invokes a scan on a single target" {
        $r = Invoke-ICScanTarget -target $testhost
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Invokes a response on a target by id" {
        $ext = $Extensions | where { $_.name -eq "Terminate Process" } | Select -First 1
        $r = Invoke-ICResponse -target $testhost -ExtensionId $ext.id
        $r.userTaskId | Should -Match $GUID_REGEX
    }

    It "Invokes a response on a target by name" {
        $r = Invoke-ICResponse -target $testhost -ExtensionName "Terminate Process"
        $r.userTaskId | Should -Match $GUID_REGEX
    }
}



