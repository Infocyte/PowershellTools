

Describe "Set-ICToken" {
    BeforeAll {
        move-item "C:\Users\cgerr\AppData\Roaming\infocyte\credentials.json" -Destination "C:\Users\cgerr\AppData\Roaming\infocyte\credentials.json.bck"
    }
    AfterAll {
        move-item "C:\Users\cgerr\AppData\Roaming\infocyte\credentials.json.bck" -Destination "C:\Users\cgerr\AppData\Roaming\infocyte\credentials.json" -Force
    }

    It "Connects to instance" {
        $result = Set-ICToken -Instance testchris2644 -Token "5VNDcdevqEz6GHYpUOfyDpLdHajT56nPdcmwhBlHyD5IcCZo2ydedMuUiFp32R00"
        $result | Should -Be $true
    }

    It "Defines a single BoxId" {
        $Global:ICCurrentBox | Should -Match $GUID_REGEX
        $Global:ICCurrentBox.Count | Should -BeExactly 1
    }

    It "Throws error on failure to connect to non-existant instance" {
        $err = { Set-ICToken -Instance "fakechris2644" -Token "5VNDcdevqEz6GHYpUOfyDpLdHajT56nPdcmwhBlHyD5IcCZo2ydedMuUiFp32R00" } | Should -Throw -PassThru
        $err.Exception.GetType().Name | Should -BeIn @("WebException","HttpResponseException")    # HttpResponseException = PSCore   
    }

    It "Saves token to credentials.json" {
        $result = Set-ICToken -Instance "testchris2644" -Token "5VNDcdevqEz6GHYpUOfyDpLdHajT56nPdcmwhBlHyD5IcCZo2ydedMuUiFp32R00" -Save
        $result | Should -Be $true
        "C:\Users\cgerr\AppData\Roaming\infocyte\credentials.json" | Should -Exist
        $result = select-string -Path C:\Users\cgerr\AppData\Roaming\infocyte\credentials.json -Pattern "testchris2644"
        $result | Should -BeLike "*testchris2644*"            
    }

    It "Pulls token from credentials.json" {
        $result = Set-ICToken -Instance "testchris2644"
        $result | Should -Be $true
    }
}

