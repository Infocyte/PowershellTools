InModuleScope InfocyteHUNTAPI {

    BeforeAll {
        Remove-Module -Name InfocyteHUNTAPI -Force -ErrorAction Ignore
        Import-Module $PSScriptRoot\..\infocyteHUNTAPI.psd1 -Force -ErrorAction Stop
        Set-ICToken -Instance TestChris2644
        $PesterPreference = [PesterConfiguration]::Default
        $PesterPreference.Output.Verbosity.Value = "Normal"

    }
    
    Describe "Create Controller Group" {
        
    }

    Describe "Create Target Group" {
        $tg = New-ICTargetGroup -Name "PSTest"
        $tg | Should Exist

        if (-NOT $tg) {
            $cg = Get-ICControllerGroup -where @{ name = "ChrisTest" }
            $tg = New-ICTargetGroup -Name "PSTest" -ControllerGroupId $cg.id
        }
        $b = Get-ICTargetGroup -where @{ name = "PSTest" }
        if ($a.id -ne $b.id) { throw "Error" }
    }

    AfterAll {
        Remove-ICTargetGroup -Id
        Remove-ICControllerGroup -Id
    }

    
}