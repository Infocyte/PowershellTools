InModuleScope InfocyteHUNTAPI {

    BeforeAll {
        Remove-Module -Name InfocyteHUNTAPI -Force -ErrorAction Ignore
        Import-Module $PSScriptRoot\..\infocyteHUNTAPI.psd1 -Force -ErrorAction Stop
        Set-ICToken -Instance TestChris2644
        $PesterPreference = [PesterConfiguration]::Default
        $PesterPreference.Output.Verbosity.Value = "Normal"

    }
    
    Describe "Command" {
        
        It "does something useful" {
            $true | Should Be $false
        }

    }

    
}