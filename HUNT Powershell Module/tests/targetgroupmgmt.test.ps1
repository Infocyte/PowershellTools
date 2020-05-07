

Describe "ICTargetGroup" {

    BeforeAll {
        Get-ICTargetGroup -where @{ name = $testname } | Remove-ICTargetGroup | Out-Null
        Get-ICControllerGroup -where @{ name = $testname } | Remove-ICControllerGroup | Out-Null
        Get-ICCredential -where @{ name = $testname } | Remove-ICCredential | Out-Null
        Get-ICQuery -where @{ name = $testname } | Remove-ICQuery | Out-Null
    }
    AfterAll {
        Get-ICTargetGroup -where @{ name = $testname } | Remove-ICTargetGroup
        Get-ICControllerGroup -where @{ name = $testname } | Remove-ICControllerGroup
        Get-ICCredential -where @{ name = $testname } | Remove-ICCredential
        Get-ICQuery -where @{ name = $testname } | Remove-ICQuery
    }

    It "Create and Get Target Groups" {
        $r = Get-ICTargetGroup -where @{ name = $testname }
        $r | Should -Be $null

        $tg = New-ICTargetGroup -Name $testname
        $tg.name | Should -BeExactly $testname
        $tg.id | Should -Match $GUID_REGEX

        $r = Get-ICTargetGroup -where @{ name = $testname }
        $r.id | Should -BeExactly $tg.id
    }

    It "Create and Get Controller Group" {
        $r = Get-ICControllerGroup -where @{ name = "Controller Group 1" }
        $r.id | Should -Match $GUID_REGEX

        $r = Get-ICControllerGroup -where @{ name = $testname }
        $r | Should -Be $null

        $r = New-ICControllerGroup -name $testname
        $r.name | Should -BeExactly $testname

        $r = Get-ICControllerGroup -where @{ name = $testname }
        $r.name | Should -BeExactly $testname
    }

    It "Removes a Target Group" {
        $r = Get-ICTargetGroup -where @{ name = $testname } | Remove-ICTargetGroup
        $r | Should -Be $true

        $r = Get-ICTargetGroup -where @{ name = $testname } | Remove-ICTargetGroup
        $r | Should -Be $null
    }

    It "Create Target Group with Controller Group" {   
        $cg = Get-ICControllerGroup -where @{ name = $testname }     
        $a = New-ICTargetGroup -Name $testname -ControllerGroupId $cg.id
        $b = Get-ICTargetGroup -where @{ name = $testname }
        $a.id | Should -Be $b.id
    }
    
    It "Create and Get Credentials" {
        $r = Get-ICCredential -where @{ name = $testname }
        $r | Should -Be $null

        $ssPass = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential ("TestUser", $ssPass)
        $rnew = New-ICCredential -Name $testname -Cred $Cred -AccountType windowsDomain
        $rnew.name | Should -BeExactly $testname
        $rnew.id | Should -Match $GUID_REGEX

        $r = Get-ICCredential -where @{ name = $testname }
        $r.id | Should -BeExactly $rnew.id
    }

    It "Create and Get Queries" {
        $r = Get-ICQuery -where @{ name = $testname }
        $r | Should -Be $null

        $tg = Get-ICTargetGroup -where @{ name = $testname }
        $c = Get-ICCredential -where @{ name = $testname }
        $q = New-ICQuery -Name $testname -TargetGroupId $tg.id -credentialId $c.id -Query "127.0.0.1"
        $q.name | Should -BeExactly $testname
        $q.id | Should -Match $GUID_REGEX

        $r = Get-ICQuery -where @{ name = $testname }
        $r.id | Should -BeExactly $q.id
    }

}


Describe "Addresses and Agents" {

    It "Gets Address Entries" {
        $tg = Get-ICTargetGroup -where @{ totalAddressCount = @{ gte = 1 } } | Select-Object -First 1
        $r = Get-ICAddress -TargetGroupId $tg.id
        $r.id | Should -Match $GUID_REGEX

        $address = Get-ICAddress -where @{ hostname = $testhost; queryId = @{ neq = $null } } | Select-Object -Last 1
        $r = Get-ICTargetGroup -id $address.targetId
        $r.id | Should -Match $GUID_REGEX 
        $r = Get-ICQuery -id $address.queryId
        $r.id | Should -Match $GUID_REGEX 
    }

    It "Gets Agents" {
        $r = Get-ICAgent -where @{ name = $testhost }
        $r.id | Should -Match $GUID_REGEX
        $r.hostname = $testhost
    }
}