
Describe "ICExtensions" {
    AfterAll {
        Get-ICExtension -where @{ name = $testname } | Remove-ICExtension
    }

    Describe "New-ICExtension" {
        BeforeAll {
            Remove-Item .\testextension.lua -Force -ErrorAction Ignore | Out-Null
        }

        AfterAll {
            Remove-Item .\testextension.lua -Force -ErrorAction Stop     
        }

        It "Creates an extension" {
            $r = New-ICExtension -Name $testname -Type Collection
            $r | Should -Not -Be $null

            $r = New-ICExtension -Name $testname -Type Collection -SavePath ".\testextension.lua"
            $r | Should -Be $true
            Resolve-Path ".\testextension.lua" | Should -Exist

        }

        It "Imports an extension" {
            $r = Import-ICExtension -Path .\testextension.lua -Active:$false
            $r | Should -Not -Be $null

        }

    }

    Describe "Get-Extension" {
    
        It "Gets an extension" {
            $r = Get-ICExtension -where @{ name = $testname }
            $r | Should -Not -Be $null
        }

    }

    Describe "Update-ICExtension" {
        BeforeAll {
            $ext = Get-ICExtension -where @{ name = $testname } -IncludeBody | select -first 1
        }
        AfterAll {
            Remove-Item .\testextension.lua -Force -ErrorAction Ignore
            Get-ICExtension -where @{ name = $testname } | Remove-ICExtension
        }

        It "Updates an extension" {
            $r = Update-ICExtension -id $ext.id -body $ext.body
            $r.updatedBy | Should -Not -Be $null
        }
    }

    Describe "Import-ICOfficialExtensions" {
        BeforeAll {
            $ProgressPreference = 'SilentlyContinue'
        }
    
        It "Imports all the official extensions" {
            $r = Import-ICOfficialExtensions
            $r | Should -Be $true

            $r = Get-ICExtension
            $r.count | Should -GE 12
        }


    }

}

