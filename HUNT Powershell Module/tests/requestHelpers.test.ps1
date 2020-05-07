

Describe "Get-ICAPI" {
    
    It "Gets the Version" {
        $ver = Get-ICAPI -Endpoint "Version" -Fields serverVersion
        $ver.serverVersion.Split('.')[3] | Should -BeGreaterOrEqual "2400"
    }

    It "Gets a specific flag named 'Verified Good'" {
        $r = Get-ICAPI -Endpoint "flags" -where @{ name = "Verified Good" }
        $r.color | Should -BeExactly "green"
    }

    It "Returns null on no results" {
        $r = Get-ICAPI -Endpoint "flags" -where @{ name = "fake" }
        $r | Should -Be $null
    }

    It "Gets flags weight using -fields filter" {
        $r = Get-ICAPI -endpoint "flags" -fields weight
        $r[0].name | Should -Be $null
        { [int]$r[0].weight } | Should -Not -Throw
        [int]$r[0].weight | Should -BeOfType [int]
    }

    It "Throws on fake endpoint" {
        $err = { Get-ICAPI -Endpoint "fake" } | Should -Throw -Passthru
        $err.Exception.GetType().Name | Should -BeIn @("WebException","HttpResponseException")
    }
    
    It "Gets the count of an API" {
        $b = Get-ICAPI -endpoint "Users"
        $c = Get-ICAPI -endpoint "Users" -CountOnly 
        $c | Should -BeExactly $b.Count
    }

    It "Only gets first 1000 entries" {
        $r = Get-ICAPI -Endpoint "jobs"
        $r.Count | Should -BeExactly 1000
    }

    It "Gets all entries on -NoLimit" -Skip {
        $date = Get-Date -format "u"
        Mock Get-Host { 
            [pscustomobject] @{ 
                ui = Add-Member -PassThru -Name PromptForChoice -InputObject ([pscustomobject] @{}) -Type ScriptMethod -Value { return 1 }
            }   
        }
        $cnt = Get-ICAPI -Endpoint "jobs" -where @{ createdOn = @{ lt = $date } } -CountOnly
        if ($cnt -gt 1000000) { $cnt = 1000000 }
        $r = Get-ICAPI -Endpoint "jobs" -where @{ createdOn = @{ lt = $date } } -NoLimit
        $r.Count | Should -BeExactly $cnt
    }
}

Describe "Invoke-ICAPI" {
    AfterAll {
        Get-ICFlag -where @{ or = @( @{ name = $Testname }, @{ name = $null }) } | Remove-ICFlag
    }
            
    It "Creates a flag via POST method" {
        $Endpoint = "flags"
        $body = @{
            name = $Testname
            color = "blue"
            weight = 5
        }
        $r = Invoke-ICAPI -method POST -Endpoint $Endpoint -body $body 
        $r.id | Should -Not -Be $null
    }

    It "Throws while using an illegal endpoint method" {
        $err = {                 
            $Endpoint = "fake"
            $body = @{
                name = $Testname
                color = "blue"
                weight = 5
            }
            Invoke-ICAPI -method POST -Endpoint $Endpoint -body $body  
        } | Should -Throw -Passthru
        $err.Exception.GetType().Name | Should -BeIn @("WebException","HttpResponseException")
    }

}

