try {
    Remove-ItemProperty -Path "Registry::HKU\S-1-12-1-4288098288-1209587296-83036081-1222742042\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PCAppStore" -ErrorAction Stop
    Remove-ItemProperty -Path "Registry::HKU\S-1-12-1-4288098288-1209587296-83036081-1222742042\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PCAppStoreUpdater" -ErrorAction Stop

    $fileNames = @(
        "pcappstore\pcappstore.exe",
        "pcappstore\autoupdater.exe",
        "pcappstore\autoupdater.ini",
        "pcappstore\pcappstore.ini"
    )

    $userDirs = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $exclude -notcontains $_.Name }

    foreach ($user in $userDirs) {
        foreach ($file in $fileNames) {
            $fullPath = Join-Path $user.FullName $file
            if (Test-Path $fullPath) {
                try {
                    Remove-Item $fullPath -Force
                    Write-Host "Deleted: $fullPath"
                } catch {
                    Write-Warning "Failed to delete $fullPath": $_""
                }
            } else {
                Write-Host "$fullPath not found"
            }
        }
    }

    Write-Host "Finished checking all user directories."
}
catch {
    Write-Host "Error: $_"
}