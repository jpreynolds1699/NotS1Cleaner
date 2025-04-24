$Path = "$Env:systemdrive\Users\swilson\AppData\Local\Google\Chrome\User Data\Default\History"
if (-not (Test-Path -Path $Path)) {
    Write-Verbose "[!] Could not find Chrome History for username: swilson"
    }
    $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $Value = Get-Content -Path "$Env:systemdrive\Users\swilson\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
    $Value | ForEach-Object {
        $Key = $_
        if ($Key -match $Search){
            New-Object -TypeName PSObject -Property @{
                User = $UserName
                Browser = 'Chrome'
                DataType = 'History'
                Data = $_
            }
        }
    }