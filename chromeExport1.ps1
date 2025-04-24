$Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
$Value = Get-Content -Path "$Env:systemdrive\Users\dholter\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique

$Results = @()
$Value | ForEach-Object {
    $Key = $_
    if ($Key -match $Search){
        $Results += New-Object -TypeName PSObject -Property @{
            User = $UserName
            Browser = 'Chrome'
            DataType = 'History'
            Data = $_
        }
    }
}

$Results | Export-Csv -Path "C:\temp\BrightFlow\ChromeHistory.csv" -NoTypeInformation
