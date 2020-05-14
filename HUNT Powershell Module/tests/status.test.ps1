

Describe "Get-ICJob" {
    
    It "It gets Jobs" {
        $r = Get-ICJob -All
        $r | Should -Not -Be $null
        $r[0].id | Should -Match $GUID_REGEX
    }

}

Describe "Get-ICAuditLog" {
    
    It "It gets audit logs" {
        $r = Get-ICAuditLog
        $r | Should -Not -Be $null
        $r[0].id | Should -Match $GUID_REGEX
    }

}

Describe "Get-ICTask" {
    
    It "It gets Tasks" {
        $r = Get-ICTask
        $r | Should -Not -Be $null
        $r[0].id | Should -Match $GUID_REGEX

        $r2 = $r[0] | Get-ICTask
        $r2 | Should -Not -Be $null
        $r2[0].id | Should -Match $GUID_REGEX    
    }

}

Describe "Get-ICLastScanTask" {
    BeforeAll {
        $task = Get-ICTask -where @{ type = "Scan" } | Select -Last 1
    }

    It "It gets the last enumerate task" {
        $r = Get-ICLastScanTask -type "Enumerate"
        $r.type | Should -Be "Enumerate"
        $r[0].userTaskId | Should -Match $GUID_REGEX  
        ([array]$r).count | Should -BeExactly 1
    }

    It "It gets the last scan task" {
        $r = Get-ICLastScanTask -type "Scan"
        $r.type | Should -Be "Scan"
        $r[0].userTaskId | Should -Match $GUID_REGEX  
        ([array]$r).count | Should -BeExactly 1

        $r = Get-ICTargetGroup -targetGroupId $task.relatedId
        $r.controllerGroupId | Should -Match $GUID_REGEX  
    }

}

Describe "Get-ICTaskItems" {
    BeforeAll {
        $task = Get-ICTask -where @{ type = "Scan"} | Select -Last 1
    }

    It "It gets TaskItems" {
        $r = Get-ICTaskItems -taskId $task.Id
        $r[0].userTaskId | Should -Match $GUID_REGEX  

        $r2 = $task.Id | Get-ICTaskItems
        $r2[0].userTaskId | Should -Match $GUID_REGEX    
    }

}