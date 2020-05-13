
Describe "Get-ICObject" {

    It "Gets a Powershell.exe object from processes" {
        $r = Get-ICObject -Type "Process" -where @{ name = "powershell.exe" }
        $r = Get-ICObject -Type "Process" -where @{ name = "powershell.exe" }
        $r.Count | Should -GE 1
    }

    It "Gets a Powershell.exe object from artifacts" {
        $r = Get-ICObject -Type "Artifact" -where @{ name = "powershell.exe" }
        $r.Count | Should -GE 1
    }

    It "Gets extension objects" {
        $r = Get-ICObject -Type "Extension"
        $r.Count | Should -GE 1
    }
    
    It "Gets account objects" {
        $r = Get-ICObject -Type "Account"
        $r.Count | Should -GE 1
    }

    It "Gets host objects" {
        $r = Get-ICObject -Type "Host"
        $r.Count | Should -GE 1
    }  

    It "Gets any File objects" {
        $file = Get-ICObject -Type "Process" -where @{ name = "powershell.exe" } | Select -First 1
        $r = Get-ICObject -Type "File" -where @{ sha1 = $($file.sha1) }
        $r.Count | Should -GE 1
    }  

    It "Gets instances of powershell.exe with CLI args" {
        $r = Get-ICObject -Type "Process" -where @{ name = "powershell.exe" } -AllInstances
        $r.Count | Should -GE 1
        $r | where { $_.commandline -match "-" } | Should -Not -Be $null

    }    
}

Describe "Get-ICVulnerability" {

    It "Gets vulnerabilities" {
        $r = Get-ICVulnerability
        $r.Count | Should -GE 1
    }
}

Describe "Get-ICAlert" {

    It "Gets alerts" {
        $r = Get-ICAlert
        $r.Count | Should -GE 1
    }
}
    
Describe "Get-ICReport" {

    It "Gets reports" {
        $r = Get-ICReport
        $r.Count | Should -GE 1
    }
}

Describe "Get-ICActivityTrace" {

    It "Gets Activity Trace" {
        $r = Get-ICActivityTrace
        $r.Count | Should -GE 1
    }
}

Describe "Get-ICDwellTime" {

    It "Gets Dwell Time stats" {
        $r = Get-ICDwellTime
        $r.Count | Should -GE 1
    }
}

Describe "Get-ICFileDetail and ICNotes" {
    BeforeAll {
        $file = Get-ICObject -Type "Process" -where @{ commentCount = @{ gte = 1}} | select -First 1
    }

    It "Gets file details" {
        $r = Get-ICFileDetail -sha1 $file.fileRepId
        $r | Should -Not -Be $null
        $r.commentCount | Should -BeOfType int
    }

    It "Gets file notes" {
        $r = Get-ICNotes -sha1 $file.fileRepId
        $r | Should -Not -Be $null
        $r.createdBy | Should -Not -Be $null
    }
}
