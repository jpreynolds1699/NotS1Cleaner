$outputFile = "C:\Temp\BrightFlow\Edge_History_PublicDataCheck.csv"
 
$userProfile = $env:USERPROFILE
$historyPath = "$userProfile\AppData\Local\Microsoft\Edge\User Data\Default\History"
$tempHistory = "$env:TEMP\EdgeHistory_temp.db"
 
Copy-Item -Path $historyPath -Destination $tempHistory -Force
 
Add-Type -AssemblyName System.Data
 
$connectionString = "Data Source=$tempHistory;Version=3;"
$connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
$connection.Open()
 
function Get-ChromeTimestamp {
    param([datetime]$date)
    $epoch = Get-Date "1601-01-01T00:00:00Z"
    return [int64](($date.ToUniversalTime() - $epoch).TotalMilliseconds * 1000)
}
 
$startTime = Get-ChromeTimestamp -date "2025-04-06 00:00:00"
$endTime   = Get-ChromeTimestamp -date "2025-04-08 23:59:59"
 
$sql = @"
SELECT urls.url, urls.title, datetime((visits.visit_time/1000000)-11644473600, 'unixepoch') as visit_date
FROM urls
JOIN visits ON urls.id = visits.url
WHERE urls.url LIKE '%publicdatacheck.com%' AND visits.visit_time BETWEEN $startTime AND $endTime
ORDER BY visits.visit_time DESC
"@
 
$command = $connection.CreateCommand()
$command.CommandText = $sql
$reader = $command.ExecuteReader()
 
$results = @()
while ($reader.Read()) {
    $results += [PSCustomObject]@{
        VisitDate = $reader["visit_date"]
        Title     = $reader["title"]
        URL       = $reader["url"]
    }
}
 
$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
 
$reader.Close()
$connection.Close()
Remove-Item -Path $tempHistory -Force
 
Write-Host "Edge history saved to: $outputFile"