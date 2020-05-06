
InModuleScope InfocyteHUNTAPI {

    BeforeAll {
        Remove-Module -Name InfocyteHUNTAPI -Force -ErrorAction Ignore
        Import-Module $PSScriptRoot\..\infocyteHUNTAPI.psd1 -Force -ErrorAction Stop
        Set-ICToken -Instance TestChris2644
        $PesterPreference = [PesterConfiguration]::Default
        $PesterPreference.Output.Verbosity.Value = "Normal"

    }

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

        It "Gets flags in order" {
            $r = Get-ICAPI -endpoint "flags" -fields name, weight -order 'weight desc'
            $r[0].weight | Should -BeExactly 10
        }

        It "Throws on fake endpoint" {
            { Get-ICAPI -Endpoint "fake" } | Should -Throw -ExceptionType ([system.net.webexception])
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

        It "Gets all entries on -NoLimit" {
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
            Get-ICFlag -where @{ or = @( @{ name = "TestFlag" }, @{ name = $null }) } | Remove-ICFlag
        }
                
        It "Creates a flag via POST method" {
            $Endpoint = "flags"
            $body = @{
                name = "TestFlag"
                color = "blue"
                weight = 5
            }
            $r = Invoke-ICAPI -method POST -Endpoint $Endpoint -body $body 
            $r.id | Should -Not -Be $null
        }

        It "Throws while using an illegal endpoint method" {
            {
                $Endpoint = "fake"
                $body = @{
                    name = "TestFlag"
                    color = "blue"
                    weight = 5
                }
                Invoke-ICAPI -method POST -Endpoint $Endpoint -body $body 
            } | Should -Throw -ExceptionType ([system.net.webexception])
        }
   
    }


}