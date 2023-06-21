

Describe "ICFlag" {

    BeforeAll {
        Get-ICFlag -where @{ name = $Testname } | Remove-ICFlag | Out-Null
    }
    AfterAll {
        Get-ICFlag -where @{ name = $Testname } | Remove-ICFlag | Out-Null
    }

    It "Gets a flag named 'Verified Good" {
        $r = Get-ICFlag -where @{ name = "Verified Good" }
        $r.color | Should -BeExactly "green"
    }

    It "Returns empty when it can't find a flag" {
        $r = Get-ICFlag -where @{ name = "fake" }
        $r | Should -Be $null
    }

    It "Creates a flag" {
        $r = New-ICFlag -Name $Testname -Color "blue" -Weight 5 
        $r.id | Should -Not -Be $null
    }

    It "Throws if it tries to create an existing flag name" {
        { $r = New-ICFlag -Name $Testname -Color "blue" -Weight 5 } | Should -Throw
        $r.id | Should -Be $null
    }

    It "Updates a flag" {
        $r = Get-ICFlag -where @{ name = $Testname }
        $r.color | Should -BeExactly "blue"

        $r = Update-ICFlag -id $r.id -Color "green"
        $r.color | Should -BeExactly "green"
    }

}
