param ([Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $collectAgentLogs="true",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $collectAgentCrashDumps="false",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $collectLiveAgentDump="false",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $collectWpr="false",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $collectWfpCapture="false",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $deleteZip="true",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $uploadZip="true",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $collectOnlyOnError="false",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $fast="false",
       [Parameter(Mandatory=$false)][ValidateSet("true", "false")][string] $encrypt="true",
       [Parameter(Mandatory=$false)][int] $agentLogCount=3,
       [Parameter(Mandatory=$false)][int] $agentCrashdumpsCount=1,
       [Parameter(Mandatory=$false)][int] $wprTimeout=5,
       [Parameter(Mandatory=$false)][int] $wfpTimeout=10,
       [Parameter(Mandatory=$false)][string] $diagnosticOutputDir="$env:SystemRoot\temp",
       [Parameter(Mandatory=$false)][string] $diagnosticTempDir="$env:SystemRoot\temp",
       [Parameter(Mandatory=$false)][string] $diagnosticZipOut=$null,
       [Parameter(Mandatory=$false)][string] $zipPk=$null,
       [Parameter(Mandatory=$false)][string] $sentinelCleanerLogPath=$null,
       [Parameter(Mandatory=$false)][string] $sentinelAgentUUID=$null,
       [Parameter(Mandatory=$false)][string] $sentinelSiteId=$null,
       [Parameter(Mandatory=$false)][string] $sentinelMgmtUrl=$null,
       [Parameter(Mandatory=$false)][string] $cleanerExitCode=$null)

if ("true" -ieq $collectAgentLogs)       {$collectAgentLogs = $true}       else {$collectAgentLogs = $false}
if ("true" -ieq $collectAgentCrashDumps) {$collectAgentCrashDumps = $true} else {$collectAgentCrashDumps = $false}
if ("true" -ieq $collectLiveAgentDump)   {$collectLiveAgentDump = $true}   else {$collectLiveAgentDump = $false}
if ("true" -ieq $collectWpr)             {$collectWpr = $true}             else {$collectWpr = $false}
if ("true" -ieq $collectWfpCapture)      {$collectWfpCapture = $true}      else {$collectWfpCapture = $false}
if ("true" -ieq $deleteZip)              {$deleteZip = $true}              else {$deleteZip = $false}
if ("true" -ieq $uploadZip)              {$uploadZip = $true}              else {$uploadZip = $false}
if ("true" -ieq $collectOnlyOnError)     {$collectOnlyOnError = $true}     else {$collectOnlyOnError = $false}
if ("true" -ieq $fast)                   {$fast = $true}                   else {$fast = $false}
if ("true" -ieq $encrypt)                {$encrypt = $true}                else {$encrypt = $false}

$troubleshooterMachineUniqueIdPathLegacy = "$env:SystemRoot\temp\SentinelTroubleshooterMachineUiqueId"
$troubleshooterMachineUniqueIdPath = "$env:SystemRoot\temp\SentinelTroubleshooterMachineUiqueIdNew"

function EncodeBase64 {
    param(
        [string] $InString
    )

    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($InString))
}

function EncodeHex {
    param(
        [string] $InString
    )

    [System.BitConverter]::ToString([system.Text.Encoding]::UTF8.GetBytes($InString)).Replace("-", "")
}

function Get-RandomKey {
    $rand = $(Get-Random)
    $str = [convert]::ToString($rand)
    $str
}

function GetMachineUniqueId {
    if (Test-Path $troubleshooterMachineUniqueIdPathLegacy) {
        Remove-Item -Path $troubleshooterMachineUniqueIdPathLegacy
    }

    $path = $troubleshooterMachineUniqueIdPath
    if (Test-Path $path) {
        Get-Content -Path $path
    } else {
        $id = $(Get-RandomKey)
        Set-Content -Path $path -Value $id
        $id
    }
}

function IsWowConsole {
    Test-Path "$env:SystemRoot\sysnative"
}

function Is64BitMachine {
    Test-Path "$env:SystemRoot\SysWOW64"
}

function GetProgramFilesPath {
    if (Is64BitMachine) {
        $env:ProgramW6432
    } else {
        $env:ProgramFiles
    }
}

function GetSentinelProgramFilesDirectory {
    $programFiles = GetProgramFilesPath

    if (Test-Path $programFiles\SentinelOne) {
        $programFiles + "\SentinelOne\" + (Get-ChildItem $programFiles\SentinelOne | Sort-Object -Descending -Property CreationTime | select -First 1).Name
    }
}

$SentinelTroubleshooterVersion = "1.10"
$startTime = $((Get-Date -UFormat %s).Split('.')[0])
$hostname = $env:computername
$machineUniqueId = GetMachineUniqueId
$diagnosticOutputUniqueName = $hostname + '.' + $machineUniqueId + '.' + $startTime + '.' + $(Get-RandomKey)
$diagnosticWorkDir = $diagnosticTempDir + '\SentinelTroubleshooterTemp.' + $diagnosticOutputUniqueName
$diagnosticOutputPathTmpPrefix = $diagnosticWorkDir + '\Output'
$diagnosticTranscriptPath = $diagnosticOutputPathTmpPrefix + "__transcript.txt"

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$sentinelAgentProgramDataDir = "$env:ProgramData\Sentinel"
$sentinelAgentProgramFilesDir = GetSentinelProgramFilesDirectory
$sentinelCtl = $sentinelAgentProgramFilesDir + '\SentinelCtl.exe'
$programFiles = GetProgramFilesPath

New-Item $diagnosticWorkDir -ItemType Directory | Out-Null

function log {
    param(
        [string] $Msg,
        [switch] $Hide
    )

    $path = $diagnosticOutputPathTmpPrefix + "__Log.txt"
    Add-Content -Path $path -Value "[$(Get-Date)] $Msg"

    if (-not $Hide) {
        Write-Output "[$(Get-Date)] $Msg"
    }
}

function logException {
    param(
        [string] $Msg,
        [string] $Ex
    )

    log "$Msg" -Hide
    log "$Ex" -Hide
}

log "SentinelTroubleshooter Version $SentinelTroubleshooterVersion"
log -Hide "Command line argument collectAgentLogs= $collectAgentLogs"
log -Hide "Command line argument collectAgentCrashDumps= $collectAgentCrashDumps"
log -Hide "Command line argument collectLiveAgentDump= $collectLiveAgentDump"
log -Hide "Command line argument collectWpr= $collectWpr"
log -Hide "Command line argument collectWfpCapture= $collectWfpCapture"
log -Hide "Command line argument deleteZip= $deleteZip"
log -Hide "Command line argument uploadZip= $uploadZip"
log -Hide "Command line argument collectOnlyOnError= $collectOnlyOnError"
log -Hide "Command line argument fast= $fast"
log -Hide "Command line argument encrypt= $encrypt"
log -Hide "Command line argument agentLogCount= $agentLogCount"
log -Hide "Command line argument agentCrashdumpsCount= $agentCrashdumpsCount"
log -Hide "Command line argument wprTimeout= $wprTimeout"
log -Hide "Command line argument wfpTimeout= $wfpTimeout"
log -Hide "Command line argument diagnosticOutputDir= $diagnosticOutputDir"
log -Hide "Command line argument diagnosticTempDir= $diagnosticTempDir"
log -Hide "Command line argument diagnosticZipOut= $diagnosticZipOut"
log -Hide "Command line argument zipPk= $zipPk"
log -Hide "Command line argument sentinelCleanerLogPath= $sentinelCleanerLogPath"
log -Hide "Command line argument sentinelAgentUUID= $sentinelAgentUUID"
log -Hide "Command line argument sentinelSiteId= $sentinelSiteId"
log -Hide "Command line argument sentinelMgmtUrl= $sentinelMgmtUrl"
log -Hide "Command line argument cleanerExitCode= $cleanerExitCode"

function SentinelCtl {
    param (
        $ArgumentList
    )

    try {
        if (-not (Test-Path $sentinelCtl)) {
            log "Error: SentinelCtl.exe not found" | Out-Null
            return;
        }

        cmd /c "`"$sentinelCtl`" $ArgumentList 2> nul"
    } catch {
        logException -Msg "Error SentinelCtl '$sentinelCtl' with arguments '$ArgumentList'" -Ex $_
        $null
    }
}

function GetSentinelAgentUUID {
    SentinelCtl("agent_id")
}

function GetSentinelSiteId {
    SentinelCtl("config server.site").Replace("`"","")
}

function GetSentinelMgmtUrl {
    SentinelCtl("config server.mgmtServer").Replace("`"","")
}

function GetNewestWildcardPath {
    param (
        $Wildcard,
        $Count
    )
    try {
        (Get-ChildItem $Wildcard | Sort-Object -Descending -Property CreationTime | select -First $Count).FullName
    } catch {
        logException -Msg "Error getting path" -Ex $_
        $null
    }
}

function GetNewestAgentCrashdumpsPath {
    GetNewestWildcradPath -Wildcard $sentinelAgentCrashDumpsWildcard -Count $agentCrashdumpsCount
}

function GetNewestAgentLogPath {
    GetNewestWildcradPath -Wildcard $sentinelAgentLogsWildcard -Count $agentLogCount
}

function GetNewestAgentTextLogPath {
    GetNewestWildcradPath -Wildcard $sentinelAgentTextLogsWildcard -Count $agentLogCount
}

if ([String]::IsNullOrEmpty($sentinelAgentUUID)) {
    $sentinelAgentUUID = GetSentinelAgentUUID
}

if ([String]::IsNullOrEmpty($sentinelSiteId)) {
    $sentinelSiteId = GetSentinelSiteId
}

if ([String]::IsNullOrEmpty($sentinelMgmtUrl)) {
    $sentinelMgmtUrl = GetSentinelMgmtUrl
}

if ([String]::IsNullOrEmpty($diagnosticZipOut)) {
    $diagnosticZipOut = $diagnosticOutputDir + '\SentinelTroubleshooter.' + $diagnosticOutputUniqueName + ".zip"
}

if ([String]::IsNullOrEmpty($zipPk)) {
    $zipPk = "-----BEGIN CERTIFICATE-----MIIDOzCCAiOgAwIBAgIJAPpmF4os62KNMA0GCSqGSIb3DQEBCwUAMDQxCzAJBgNVBAYTAklMMQ8wDQYDVQQIDAZJc3JhZWwxFDASBgNVBAoMC1NlbnRpbmVsT25lMB4XDTIxMDMyOTIwNDQwNloXDTI2MDMyODIwNDQwNlowNDELMAkGA1UEBhMCSUwxDzANBgNVBAgMBklzcmFlbDEUMBIGA1UECgwLU2VudGluZWxPbmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3POXDRaijLReMtQt6+WwOyWNkcoCUZwmeLeUH1cRNa+1oth6AXDGvxsNI2qSrjFyKlUmIuhHsY8iOeNOsKUkt8A+S4jiUbgQVZ82N9+jZh+S/l9lLQj1Jwr54rzZpsxScYgJzifmtt2+zO1HlfCtmJzPyWZgso6Ix0A55zLAGYvhWiuWFVJk3oeHssxViY0aax7m8v2v9xD4ju2rOD6M5yVHtwvl31ncFL3Mf5K0/E+Yk87EHyYY99h8UwHM1GRAIVteLeZYymCyNfuBATxmb8dy8dpDz/Z8RrCejP/17yIpCUS64vGrrZ0FDA7906Lm5SzYK9rNaWTNZN7/wugP/AgMBAAGjUDBOMB0GA1UdDgQWBBQASWIRx9PPvPT3B0W4ZYZE/0H8wjAfBgNVHSMEGDAWgBQASWIRx9PPvPT3B0W4ZYZE/0H8wjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAXfPOl15TCkBj8E4S9WjHTLo2UKOt3mNVbscLyS2daULmClgRn4jIWIPzfdbzt5KVhCdbtKiAbZBQdrf1Zs2Tvkt5MNnXp9ndTMJRDdBFTPhSA7z0ZAcWccRlQ1KmGwB9jkuvfQ3aiyzcCuhdEeAD/AZ8fbmJmAOW0d6U3kTm/ivIrcBw13mtSDwACekRctdegfvc6V80r9bfIiR8uSEBpfbUdv24fFQH8Tk9fR2SeFZHigqK/s9RwaXF2++Za6bj3biJLDEdWE+uRyJliR4AuC7XfcybuL04+y7fqXRtpUSPMgPutVOLUVOmdIgSOOB1VoiOTwLN32qdqjkBHz7y9-----END CERTIFICATE-----"
}

function Invoke-CLR4PowerShellCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(ValueFromRemainingArguments=$true)]
        [Alias('Args')]
        [object[]]
        $ArgumentList
    )

    if ($PSVersionTable.CLRVersion.Major -eq 4) {
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        return
    }

    $RunActivationConfigPath = $Env:TEMP | Join-Path -ChildPath ([Guid]::NewGuid())
    New-Item -Path $RunActivationConfigPath -ItemType Container | Out-Null
@"
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <startup useLegacyV2RuntimeActivationPolicy="true">
    <supportedRuntime version="v4.0"/>
  </startup>
</configuration>
"@ | Set-Content -Path $RunActivationConfigPath\powershell.exe.activation_config -Encoding UTF8

    $EnvVarName = 'COMPLUS_ApplicationMigrationRuntimeActivationConfigPath'
    $EnvVarOld = [Environment]::GetEnvironmentVariable($EnvVarName)
    [Environment]::SetEnvironmentVariable($EnvVarName, $RunActivationConfigPath)

    try {
        & powershell.exe -inputformat text -command $ScriptBlock -args $ArgumentList
    } finally {
        [Environment]::SetEnvironmentVariable($EnvVarName, $EnvVarOld)
        $RunActivationConfigPath | Remove-Item -Recurse
    }
}

function ZipDirectory {
    param(
        [string] $InputDir,
        [string] $ZipPath
    )

    $7z = "$scriptPath\7za.exe"

    try {
        if (Test-Path $7z) {
            log "7za.exe found."
            & $7z a -bd -tzip -m0=LZMA $ZipPath $InputDir 2>&1 > $7zOut

            # If 7z succedded, we will not see this log line because the log was aleady collected
            log -Hide $7zOut
        } else {
            log -Hide "7za.exe not found at '$7z'."
        }

    } finally {
        if (-not (Test-Path $ZipPath)) {
            log "7zip artifact not found, falling back to built-in compression."
            Invoke-CLR4PowerShellCommand -ArgumentList @{'InputDir'=$InputDir; 'ZipPath'=$ZipPath} -ScriptBlock {
                [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.ZipFile") | Out-Null
                [System.IO.Compression.ZipFile]::CreateFromDirectory($args[0].InputDir, $args[0].ZipPath)
            }
        }
    }
}

function Encrypt-File {
    param(
        [string] $SrcPath,
        [string] $DstPath
    )

    Invoke-CLR4PowerShellCommand -ArgumentList @{'SrcPath'=$SrcPath; 'DstPath'=$DstPath} -ScriptBlock {
        param(
            $ArgumentList
        )

        $SrcPath = $ArgumentList['SrcPath']
        $DstPath = $ArgumentList['DstPath']

        function Create-AesManagedObject($key, $IV) {
            $aes = New-Object "System.Security.Cryptography.AesManaged"
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            $aes.BlockSize = 128
            $aes.KeySize = 256

            if ($key) {
                $aes.Key = $key
                $aes.IV = $IV

            } else {
                $aes.GenerateKey() | Out-Null
            }

            $aes
        }

        function WriteEncryptedHeader($dst, $aes) {
            $pk = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2

            $pkbytes = [system.Text.Encoding]::UTF8.GetBytes($zipPk)
            $pk.Import($pkbytes)

            $header = New-Object byte[] ($aes.Key.Length + $aes.IV.Length)
            [System.Array]::Copy($aes.Key, 0, $header, 0, $aes.Key.Length) | Out-Null
            [System.Array]::Copy($aes.IV, 0, $header, $aes.Key.Length, $aes.IV.Length) | Out-Null

            $encryptedHeader = Encrypt-Envelope $pk $header
            $encryptedHeaderLengthBytes = [System.BitConverter]::GetBytes($encryptedHeader.Length)

            $dst.Write($encryptedHeaderLengthBytes, 0, $encryptedHeaderLengthBytes.Length) | Out-Null
            $dst.Write($encryptedHeader, 0, $encryptedHeader.Length) | Out-Null
        }

        function Encrypt-File-Impl($SrcPath, $DstPath) {
            $src = [System.IO.File]::OpenRead($SrcPath)
            $dst = [System.IO.File]::OpenWrite($DstPath)
            $aes = Create-AesManagedObject
            try {
                WriteEncryptedHeader $dst $aes

                $enc = $aes.CreateEncryptor()
                $streamMode = [System.Security.Cryptography.CryptoStreamMode]::Write
                $crypto = New-Object System.Security.Cryptography.CryptoStream $dst, $enc, $streamMode
                try {
                    $src.CopyTo($crypto)

                } finally {
                    $crypto.Close()
                    $crypto.Dispose()
                }

            } finally {
                $dst.Close()
                $src.Close()
            }
        }

        Function Encrypt-Envelope($pk, $plain) {
            [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null
            $content = New-Object Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$plain)
            $env = New-Object Security.Cryptography.Pkcs.EnvelopedCms $content
            $recpient = (New-Object System.Security.Cryptography.Pkcs.CmsRecipient($pk))
            $env.Encrypt($recpient)
            $env.Encode()
        }

        Encrypt-File-Impl $SrcPath $DstPath
    }
}

function UploadZip {
    param(
        [string] $Uri,
        [string] $InFile,
        [string] $HeaderId,
        [string] $HeaderSite,
        [string] $HeaderUUID
    )

    $http = New-Object System.Net.WebClient
    $http.Headers['ContentType'] = 'application/zip'
    $http.Headers['id'] = $HeaderId
    $http.Headers['x-site'] = $HeaderSite
    $http.Headers['x-uuid'] = $HeaderUUID
    $http.UploadFile($Uri, $InFile)
}

function Get-HelperComObject {
    $code = @"
         using System;
         using System.Runtime.InteropServices;

         public class ImpTest
         {
             [DllImport("Ole32.dll", CharSet = CharSet.Auto)]
             public static extern int CoSetProxyBlanket(
                IntPtr pProxy,
                uint dwAuthnSvc,
                uint dwAuthzSvc,
                uint pServerPrincName,
                uint dwAuthLevel,
                uint dwImpLevel,
                IntPtr pAuthInfo,
                uint dwCapabilities
             );

             public static int SetSecurity(object objDCOM)
             {
                 IntPtr dispatchInterface = Marshal.GetIDispatchForObject(objDCOM);
                 int hr = CoSetProxyBlanket(
                    dispatchInterface,
                    0xffffffff,
                    0xffffffff,
                    0xffffffff,
                    0, // Authentication Level
                    3, // Impersonation Level
                    IntPtr.Zero,
                    64
                 );
                 return hr;
             }
         }
"@
    try {
        Add-Type -TypeDefinition $code | Out-Null

        log "Initializing SentinelHelper COM object..." | Out-Null
        $SentinelHelper = New-Object -com "SentinelHelper.1"

        log "SentinelHelper COM object initialized successfully" | Out-Null
        [ImpTest]::SetSecurity($SentinelHelper)  | Out-Null
        $SentinelHelper

    } catch {
        logException -Msg "Error getting helper com object" -Ex $_ | Out-Null
    }
}

function ExecHelperCommands {

    try {
        $SentinelHelper = Get-HelperComObject

        function TakeDump {
            param(
                [int] $ProcessId,
                [string] $User,
                [string] $Kernel
            )

            $SentinelHelper.dump($ProcessId, $User, $Kernel)
        }

        function ExecHelperCommandsImpl {
            $agentStatusJson = $SentinelHelper.GetAgentStatusJSON()
            log $agentStatusJson
            Set-Content -Path $($diagnosticOutputPathTmpPrefix + "__AgentStatusJSON.txt") -Value $agentStatusJson

            if ($collectLiveAgentDump -eq $true) {
                log "Fetching SentinelAgent ProcessId..."
                $sentinelAgentProcessId = (Get-Process -Name SentinelAgent).Id

                log "SentinelAgent Found: $sentinelAgentProcessId"

                TakeDump -SentinelHelper $SentinelHelper `
                         -ProcessId $sentinelAgentProcessId `
                         -User $($diagnosticOutputPathTmpPrefix + "__SentinelAgentUser.dmp") `
                         -Kernel $($diagnosticOutputPathTmpPrefix + "__SentinelAgentKernel.dmp")
            }
        }

        ExecHelperCommandsImpl

    } catch {
        logException -Msg "Error running helper commands" -Ex $_
    }
}

function GetMgmtLastSeen {
    param(
        [string] $json
    )

    # using regex for json parsing to support windows 7
    $json -match 'last-seen[^:]+:([^,]+)' | Out-Null

    if ($null -eq $Matches[1]) {
        $null
        return
    }

    $lastSeen = $Matches[1].Replace('"', '')

    log "Mgmt last seen at $lastSeen" | Out-Null

    if ($lastSeen -eq "null") {
        log "Got mgmt last seen 'null' from helper" | Out-Null
        $null
    } else {
        try {
            [datetime]::ParseExact($lastSeen, "yyyy-MM-ddTHH:mm:ss.fffzzz", $null)
        } catch {
            logException -Msg "Error parsing mgmt last seen" -Ex $_
            $null
        }
    }
}

function IsConnectedToMgmt() {
    $helper = Get-HelperComObject

    if ($null -eq $helper) {
        $false
        return
    }

    try {
        $json = $helper.GetAgentStatusJSON()
        $lastSeen = GetMgmtLastSeen -json $json

        if ($null -eq $lastSeen) {
            $false
            return
        }

        $now = Get-Date

        $hoursSinceLastSeen = (New-TimeSpan -Start $lastSeen -End $now).TotalHours
        log "Hours passed since last seen mgmt: $hoursSinceLastSeen" | Out-Null

        return ($hoursSinceLastSeen -le 1);

    } catch {
        logException -Msg "Error checking mgmt connectivity" -Ex $_
        $false
    }
}

function IsAgentProcessRunning {
    try {
        $proc = Get-Process -Name SentinelAgent -ErrorAction SilentlyContinue

        if ($null -eq $proc) {
            $null
        } else {
            ($proc).Length -ne 0
        }
    } catch {
        logException -Msg "Error checking if sentinel process is running" -Ex $_
        $false
    }
}

function IsMonitorLoaded {
    try {
        (Get-WmiObject -Class win32_SystemDriver -filter "name='SentinelMonitor'").State -eq "Running"
    } catch {
        logException -Msg "Error checking if monitor is loaded" -Ex $_
        $false
    }
}

function ShouldCollectDiagnosticData {
    $isConnectedToMgmt = IsConnectedToMgmt
    $isAgentProcessRunning = IsAgentProcessRunning
    $isMonitorLoaded = IsMonitorLoaded

    log "Sanity check- isConnectedToMgmt: $isConnectedToMgmt ; isAgentProcessRunning: $isAgentProcessRunning ; isMonitorLoaded : $isMonitorLoaded" | Out-Null

    if (-not $isConnectedToMgmt) {
        return $true;
    }

    if (-not $isAgentProcessRunning) {
        return $true;
    }

    if (-not $isMonitorLoaded) {
        return $true;
    }

    if ($collectOnlyOnError -eq $true) {
        return $false
    }

    return $true
}

function RecordWpr {
    param(
        [int] $Timeout
    )

    try {
        try {
            wpr.exe -cancel
        } catch {}

        log "Starting new WPR session..."
        wpr.exe -start CPU -start Heap -start FileIO -start DiskIO

        log "Sleeping for $Timeout..."
        Start-Sleep $Timeout

        log "Stopping WPR"
        wpr.exe -stop $($diagnosticOutputPathTmpPrefix + "__wpr.etl")

        log "Done taking WPR"
    } catch {
        logException -Msg "Error taking WPR" -Ex $_
    }
}

function RecordWfpCapture {
    param(
        [int] $Timeout
    )

    try {
        try {
            netsh.exe wfp capture stop
        } catch {}

        log "Starting new WFP capture session..."
        netsh.exe wfp capture start $($diagnosticOutputPathTmpPrefix + "__wfpcapture.cab")

        log "Sleeping for $Timeout..."
        Start-Sleep $Timeout

        log "Stopping WFP capture"
        netsh.exe wfp capture stop

        log "Done taking WFP capture"
    } catch {
        logException -Msg "Error taking WFP capture" -Ex $_
    }
}

function CollectWfpData {
    try {
        netsh wfp show filters $($diagnosticOutputPathTmpPrefix + "__wfpfilters.xml")
        netsh wfp show state $($diagnosticOutputPathTmpPrefix + "__wfpstate.xml")
        netsh wfp show netevents $($diagnosticOutputPathTmpPrefix + "__wfpnetevents.xml")
    } catch {
        logException -Msg "Error collecting wfp data" -Ex $_
    }
}

function main {
    $ErrorActionPreference = 'Continue'
    $VerbosePreference = 'Continue'
    $InformationPreference = 'Continue'

    $senitnelInstallerLogsProgramDataWildcard = $sentinelAgentProgramDataDir + "\UserCrashDumps\*.log"
    $sentinelInstallerLogsWinTempWildcard = $env:SystemRoot + "\temp\SentinelInstaller*.log"
    $sentinelInstallerLogsUserTempWildcard = $env:temp + "\SentinelInstaller*.log"
    $sentinelUninstallerLogsWinTempWildcard = $env:SystemRoot + "\temp\SentinelUninstaller*.log"
    $sentinelUninstallerLogsUserTempWildcard = $env:temp + "\SentinelUninstaller*.log"
    $senitnelInstallerLogsEtlProgramDataWildcard = $sentinelAgentProgramDataDir + "\UserCrashDumps\*.etl"
    $sentinelInstallerLogsEtlWinTempWildcard = $env:SystemRoot + "\temp\SentinelInstaller*.etl"
    $sentinelInstallerLogsEtlUserTempWildcard = $env:temp + "\SentinelInstaller*.etl"
    $sentinelUninstallerLogsEtlWinTempWildcard = $env:SystemRoot + "\temp\SentinelUninstaller*.etl"
    $sentinelUninstallerLogsEtlUserTempWildcard = $env:temp + "\SentinelUninstaller*.etl"
    $sentinelMSIInstallerLogsWinTempWildcard = $env:SystemRoot + "\temp\MSI*.log"
    $sentinelMSIInstallerLogsUserTempWildcard = $env:temp + "\MSI*.log"
    $sentinelAgentLogsWildcard = $sentinelAgentProgramDataDir + "\logs\*.binlog"
    $sentinelAgentTextLogsWildcard = $sentinelAgentProgramDataDir + "\logs\*.log"
    $sentinelAgentCrashDumpsWildcard = $sentinelAgentProgramDataDir + "\CrashDumps\*.dmp"
    $sentinelAgentPerfLog = $sentinelAgentProgramDataDir + "\data\perf_logger_db\perf_logger_db.sqlite3"
    $sentinelAgentParamsWildcard = $sentinelAgentProgramFilesDir + "\config\*.json"

    function ExecCmd {
        param(
            [string] $Label,
            [string] $Command,
            [string] $ArgumentList=""
        )

        try {
            $txtOut = $diagnosticOutputPathTmpPrefix + "__cmd_" + $Label + "__" + $(Get-RandomKey) + ".txt"
            log "'$txtOut'"

            & $Command $ArgumentList 2>&1 > $txtOut
        } catch {
            logException -Msg "Error running '$txtOut'" -Ex $_
        }
    }

    function ExecPsCommand {
        param(
            [string] $Command,
            [string] $Label="",
            [hashtable] $ArgumentList=$null
        )

        try {
            $csvOut = $diagnosticOutputPathTmpPrefix + "__ps_" + $Command + "_" + $Label + "__" + $(Get-RandomKey) + ".csv"
            log "'$csvOut'"

            if ($null -eq $ArgumentList) {
                $out = & $Command 2>&1
            } else {
                $out = & $Command @ArgumentList 2>&1
            }

            $out | Select-Object -Property * | Export-Csv -Path $csvOut
        } catch {
            logException -Msg "Error running '$csvOut'" -Ex $_
        }
    }

    function ExecWmi {
        param(
            [string] $Class,
            [string] $Namespace="Root\CIMV2"
        )

        ExecPsCommand -Command Get-WmiObject @{Class=$Class; Namespace=$Namespace} -Label $Class
    }

    function ExportReg {
        param(
            [string] $Path,
            [string] $OutputFilename
        )

        try {
            $regExe = "reg.exe"

            if (IsWowConsole) {
                log -Hide "We are in WOW64 process"
                $regExe = "$env:SystemRoot\sysnative\reg.exe"
            }

            $regOut = $diagnosticOutputPathTmpPrefix + "__reg_" + $OutputFilename + "__" + $(Get-RandomKey) + ".reg.txt"
            log "'$regOut'"

            $out = & $regExe export $Path $regOut 2>&1
            $out_str = $out.tostring()

            if ($out_str.IndexOf("unable to find the specified registry key") -ne -1) {
                echo "Registry does not exist" > $regOut
            }

            log $out

        } catch {
            logException -Msg "Error running '$regOut'" -Ex $_
        }
    }

    function Expand-Object {
        param(
            $InputObject
        )

        (Out-String -InputObject $InputObject -Width 9999).Replace("`n", ";").Replace("`r", "")
    }

    function Get-ChildItemAclRecursive {
        param (
            [string] $Path,
            [string] $Exclude
        )

        Get-ChildItemRecursive -Path $Path -Exclude $Exclude | Get-Acl | Select-Object -Property *, { Expand-Object -InputObject $_.Access }
    }

    function Get-ChildItemRecursive {
        param (
            [string] $Path,
            [string] $Exclude
        )

        if ($null -eq $Exclude) {
            Get-ChildItem -Path $Path | Get-ChildItem -Recurse
        } else {
            Get-ChildItem -Path $Path -Exclude $Exclude | Get-ChildItem -Recurse
        }
    }

    function ExecRecursiveDirAndAcl {
        param (
            [string] $Path,
            [string] $Label=$null,
            [string] $Exclude=$null
        )

        ExecPsCommand -Command Get-ChildItemRecursive -ArgumentList @{Path=$Path; Exclude=$Exclude} -Label $Label
        ExecPsCommand -Command Get-ChildItemAclRecursive -ArgumentList @{Path=$Path; Exclude=$Exclude} -Label $Label
    }

    function Transcript {
        param(
            [string] $Command,
            [string] $Path
        )

        try {
            Start-Transcript -Path $Path
            & $Command
        } finally {
            Stop-Transcript
        }
    }

    function MyCopy {
        param (
            $Path,
            $Destination
        )

        Copy-Item -Path $Path -Destination $Destination -ErrorVariable badoutput -ErrorAction SilentlyContinue

        if (-not [String]::IsNullOrEmpty($badoutput)) {
            log $badoutput
        }
    }

    function ExecCopyFiles {
        try {
            log "Copying installer logs"
            MyCopy -Path $troubleshooterMachineUniqueIdPath -Destination $diagnosticWorkDir
            MyCopy -Path $senitnelInstallerLogsProgramDataWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelInstallerLogsWinTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelInstallerLogsUserTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelUninstallerLogsWinTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelUninstallerLogsUserTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $senitnelInstallerLogsEtlProgramDataWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelInstallerLogsEtlWinTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelInstallerLogsEtlUserTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelUninstallerLogsEtlWinTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelUninstallerLogsEtlUserTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelMSIInstallerLogsUserTempWildcard -Destination $diagnosticWorkDir
            MyCopy -Path $sentinelMSIInstallerLogsWinTempWildcard -Destination $diagnosticWorkDir

            if ($collectAgentLogs -eq $true) {
                $newestAgentLogPath = GetNewestAgentLogPath
                if (-not [String]::IsNullOrEmpty($newestAgentLogPath)) {
                    log "Copying agent logs from '$newestAgentLogPath'"
                    MyCopy -Path $newestAgentLogPath -Destination $diagnosticWorkDir
                }

                $newestAgentTextLogPath = GetNewestAgentTextLogPath
                if (-not [String]::IsNullOrEmpty($newestAgentTextLogPath)) {
                    log "Copying agent text logs"
                    MyCopy -Path $newestAgentTextLogPath -Destination $diagnosticWorkDir
                }
            }

            log "Copying agent params"
            MyCopy -Path $sentinelAgentParamsWildcard $diagnosticWorkDir

            if (-not [String]::IsNullOrEmpty($sentinelCleanerLogPath)) {
                log "Copying cleaner log"
                MyCopy -Path $sentinelCleanerLogPath -Destination $diagnosticWorkDir
            }

            if ($collectAgentCrashDumps -eq $true) {
                $newestAgentCrashdumpsPath = GetNewestAgentCrashdumpsPath
                if (-not [String]::IsNullOrEmpty($newestAgentCrashdumpsPath)) {
                    log "Copying agent crash dumps"
                    MyCopy -Path $newestAgentCrashdumpsPath -Destination $diagnosticWorkDir
                }
            }

            log "Copying perf log"
            MyCopy -Path $sentinelAgentPerfLog -Destination $($diagnosticOutputPathTmpPrefix + "__perflog.sqlite3")

        } catch {
            logException -Msg "Error copying files to zip" -Ex $_
        }
    }

    function CreateCleanerExitCodeFile {
        if (-not [String]::IsNullOrEmpty($cleanerExitCode)) {
            try {
                $CleanerExitCodeFilePath = $diagnosticOutputPathTmpPrefix + "__CleanerExitCode.txt"
                echo "$cleanerExitCode" > $CleanerExitCodeFilePath
            } catch {
                logException -Msg "Error running CreateCleanerExitCodeFile()" -Ex $_
            }
        }
    }

    function ExecAllCommands {
        ExecCopyFiles

        CreateCleanerExitCodeFile

        ExecCmd -Command $sentinelCtl -ArgumentList "status" -Label "SentinelCtlStatus"
        ExecCmd -Command $sentinelCtl -ArgumentList "agent_id" -Label "SentinelCtlAgentId"
        ExecCmd -Command $sentinelCtl -ArgumentList "config" -Label "SentinelCtlConfig"
        ExecCmd -Command "systeminfo.exe" -Label "systeminfo"
        ExecCmd -Command "tasklist.exe" -Label "tasklist"
        ExecCmd -Command "ipconfig.exe" -Label "ipconfig"
        ExecCmd -Command "netstat.exe" -Label "netstat"
        ExecCmd -Command "cmd" -ArgumentList "/c sc query type= all" -Label "sc_query" # hack for windows 7
        ExecCmd -Command "cmd" -ArgumentList "/c schtasks /query /v" -Label "schtasks"
        ExecCmd -Command "fltmc.exe" -Label "fltmc"

        ExecWmi -Class "Win32_ComputerSystem"
        ExecWmi -Class "Win32_OperatingSystem"
        ExecWmi -Class "Win32_TimeZone"
        #ExecWmi -Class "Win32_UserAccount"

        ExecWmi -Class "Win32_DiskDrive"
        ExecWmi -Class "Win32_LogicalDisk"
        ExecWmi -Class "Win32_DiskPartition"

        ExecWmi -Class "Win32_Process"
        ExecWmi -Class "Win32_Service"
        ExecWmi -Class "Win32_SystemDriver"
        ExecWmi -Class "Win32_Session"
        ExecWmi -Class "Win32_LogonSession"

        ExecWmi -Class "Win32_Processor"
        ExecWmi -Class "Win32_PhysicalMemory"
        ExecWmi -Class "Win32_NetworkAdapter"
        ExecWmi -Class "Win32_NetworkAdapterConfiguration"
        ExecWmi -Class "Win32_PageFileUsage"

        ExecWmi -Class "Win32_Printer"
        ExecWmi -Class "Win32_USBController"
        ExecWmi -Class "Win32_USBControllerDevice"

        ExecWmi -Class "AntiVirusProduct" -Namespace "Root\SecurityCenter2"
        ExecWmi -Class "AntiSpywareProduct" -Namespace "Root\SecurityCenter2"
        ExecWmi -Class "FirewallProduct" -Namespace "Root\SecurityCenter2"

        ExecWmi -Class "MSFT_ScheduledTask" -Namespace "ROOT\Microsoft\Windows\TaskScheduler"

        ExecPsCommand -Command Get-Date

        if ($fast -eq $true) {
            return
        }

        ExecWmi -Class "Win32_Product"
        ExecWmi -Class "Win32_OptionalFeature"
        ExecWmi -Class "Win32_QuickFixEngineering"

        ExecPsCommand -Command Get-EventLog -ArgumentList @{LogName="System"; Newest=1000; EntryType="Error"} -Label "SystemError"
        ExecPsCommand -Command Get-EventLog -ArgumentList @{LogName="System"; Newest=1000; EntryType="Warning"} -Label "SystemWarning"
        ExecPsCommand -Command Get-EventLog -ArgumentList @{LogName="System"; Newest=1000} -Label "SystemAll"
        ExecPsCommand -Command Get-WinEvent -ArgumentList @{LogName="Microsoft-Windows-WindowsUpdateClient/Operational"; MaxEvents=1000} -Label "WindowsUpdateClient"
        ExecPsCommand -Command Get-WinEvent -ArgumentList @{LogName="Microsoft-Windows-AppModel-Runtime/Operational"; MaxEvents=1000} -Label "AppModelRuntime"
        ExecPsCommand -Command Get-WinEvent -ArgumentList @{LogName="SentinelOne/Operational"; MaxEvents=1000} -Label "SentinelOperational"
        ExecPsCommand -Command Get-WinEvent -ArgumentList @{LogName="SentinelOne/Firewall"; MaxEvents=1000} -Label "SentinelFirewall"

        ExportReg -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" -OutputFilename services
        #ExportReg -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" -OutputFilename control
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\sentinel labs" -OutputFilename SentinelLabs
        ExportReg -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger" -OutputFilename Autologger
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -OutputFilename Uninstall
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -OutputFilename ProfileList
        ExportReg -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" -OutputFilename SessionManager
        ExportReg -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class" -OutputFilename ControlClass
        ExportReg -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Security" -OutputFilename WmiSecurity
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -OutputFilename WindowsErrorReporting

        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\SentinelAgent" -OutputFilename AppIDSentinelAgentExecutable
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\SentinelHelperService" -OutputFilename AppIDSentinelHelperServiceExecutable
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{1ECB7470-7BA4-4F64-A41D-BDF1B38DEED8}" -OutputFilename AppIDSentinelAgent
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{4F58E51B-3F2B-4807-AB8C-2A7F143E9C3F}" -OutputFilename AppIDSentinelHelper
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{DFE127B0-F72C-40FB-BEF8-9F29CB996B9C}" -OutputFilename CLSIDSentinelAgent
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{AE31BE8D-9641-4F45-B1DA-9AAFF3B6E971}" -OutputFilename CLSIDSentinelAgentCore
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{D8292311-6F2E-4A02-9881-F69620A2A85F}" -OutputFilename CLSIDSentinelAgentDisableMode
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{FC862BC1-C866-4B81-B15A-EB4D487445CE}" -OutputFilename CLSIDSentinelAMSIProvider
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{28B58EFD-EED3-49D0-9AC3-A7A9E39A6303}" -OutputFilename CLSIDSentinelHelper
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{0420773B-38C3-4300-AD2B-23652FEEE26C}" -OutputFilename InterfaceISentinelHelper
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8E470FB5-6800-4FF6-8E0A-620F676C912E}" -OutputFilename InterfaceISentinelAgent
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{BFAC1BA7-19C8-4FF3-B3AB-85966226D198}" -OutputFilename InterfaceISentinelAgentCore
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{36025835-87A1-4385-A9A3-F333373E12A9}" -OutputFilename InterfaceISentinelAgentDisableMode
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{BD9B4591-8E6A-49BF-BBDB-1C8E08C20D5D}" -OutputFilename InterfaceISentinelAgentModuleLoader
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{ebacbec2-899e-44a5-b653-652a099b1a3c}" -OutputFilename InterfaceIDeployer
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TypeLib\{667D5A92-7C14-4687-B20E-A5CF06FEF1AF}" -OutputFilename TypeLibSentinelAgent
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TypeLib\{BED0DAEE-A8DC-40E6-AAD6-DCA5532B746C}" -OutputFilename TypeLibSentinelHelper
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TypeLib\{7e87ffec-3b0d-4b1c-b882-f91e0cae131b}" -OutputFilename TypeLibDeployer
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelHelper.1" -OutputFilename ClassesSentinelHelper1
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelHelper" -OutputFilename ClassesSentinelHelper
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelAgent.1" -OutputFilename ClassesSentinelAgent1
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelAgent" -OutputFilename ClassesSentinelAgent
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelAgentCore.1" -OutputFilename ClassesSentinelAgentCore1
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelAgentCore" -OutputFilename ClassesSentinelAgentCore
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelAgentDisableMode.1" -OutputFilename ClassesSentinelAgentDisableMode1
        ExportReg -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\SentinelAgentDisableMode" -OutputFilename ClassesSentinelAgentDisableMode

        ExecPsCommand -Command Get-ComputerInfo

        ExecPsCommand -Command Get-ChildItem -ArgumentList @{Path="env:"} -Label "EnvVars"
        ExecPsCommand -Command Get-ChildItem -ArgumentList @{Path="$programFiles"} -Label "ProgramFiles"
        ExecPsCommand -Command Get-ChildItem -ArgumentList @{Path="$env:SystemRoot\Prefetch"} -Label "Prefetch"
        ExecPsCommand -Command Get-ChildItem -ArgumentList @{Path="$env:SystemRoot\sysnative\drivers"} -Label "drivers"
        ExecRecursiveDirAndAcl -Path "$programFiles\SentinelOne" -Label "SentinelProgramFiles"
        ExecRecursiveDirAndAcl -Path $sentinelAgentProgramDataDir -Exclude "rshTranscripts" -Label "SentinelProgramData"

        ExecPsCommand -Command Get-AutologgerConfig -ArgumentList @{Name="*"}
        ExecPsCommand -Command Get-EtwTraceSession -ArgumentList @{Name="*"}

        ExecHelperCommands

        CollectWfpData
        if ($collectWpr -eq $true) {
            RecordWpr -Timeout $wprTimeout
        }
        if ($collectWfpCapture -eq $true){
            RecordWfpCapture -Timeout $wfpTimeout
        }
    }

    try {
        log -Hide "Processed command line argument collectAgentLogs= $collectAgentLogs"
        log -Hide "Processed command line argument collectAgentCrashDumps= $collectAgentCrashDumps"
        log -Hide "Processed command line argument collectLiveAgentDump= $collectLiveAgentDump"
        log -Hide "Processed command line argument collectWpr= $collectWpr"
        log -Hide "Processed command line argument collectWfpCapture= $collectWfpCapture"
        log -Hide "Processed command line argument deleteZip= $deleteZip"
        log -Hide "Processed command line argument uploadZip= $uploadZip"
        log -Hide "Processed command line argument collectOnlyOnError= $collectOnlyOnError"
        log -Hide "Processed command line argument fast= $fast"
        log -Hide "Processed command line argument encrypt= $encrypt"
        log -Hide "Processed command line argument agentLogCount= $agentLogCount"
        log -Hide "Processed command line argument wprTimeout= $wprTimeout"
        log -Hide "Processed command line argument wfpTimeout= $wfpTimeout"
        log -Hide "Processed command line argument diagnosticOutputDir= $diagnosticOutputDir"
        log -Hide "Processed command line argument diagnosticTempDir= $diagnosticTempDir"
        log -Hide "Processed command line argument diagnosticZipOut= $diagnosticZipOut"
        log -Hide "Processed command line argument zipPk= $zipPk"
        log -Hide "Processed command line argument sentinelCleanerLogPath= $sentinelCleanerLogPath"
        log -Hide "Processed command line argument sentinelAgentUUID= $sentinelAgentUUID"
        log -Hide "Processed command line argument sentinelSiteId= $sentinelSiteId"
        log -Hide "Processed command line argument sentinelMgmtUrl= $sentinelMgmtUrl"
        log -Hide "Processed command line argument cleanerExitCode= $cleanerExitCode"


        if (ShouldCollectDiagnosticData) {
            Transcript -Command ExecAllCommands -Path $diagnosticTranscriptPath

            $tempZipPath = "$diagnosticTempDir\SentinelTroubleshooterTempZip.$diagnosticOutputUniqueName.temp"

            log "Saving temporary zip of '$diagnosticWorkDir' to '$tempZipPath'"
            ZipDirectory -InputDir $diagnosticWorkDir -ZipPath $tempZipPath

            if ($encrypt -eq $true) {
                log "Encrypting zip file at '$tempZipPath' to '$diagnosticZipOut'"
                Encrypt-File -SrcPath $tempZipPath -DstPath $diagnosticZipOut
            } else {
                log "Not encrypting output file due to argmunet selection"
                MyCopy -Path $tempZipPath -Destination $diagnosticZipOut
            }

            if ($uploadZip -eq $true) {
                UploadZip -Uri "$sentinelMgmtUrl/api/v1.6/upload/state-diagnostic" `
                          -InFile $diagnosticZipOut `
                          -HeaderId $machineUniqueId `
                          -HeaderSite $sentinelSiteId `
                          -HeaderUUID $sentinelAgentUUID
            }
        } else {
            log "Not collecting diagnostic data"
        }

        log "SentinelTroubleshooter finished successfully."
        $global:exitcode = 0

    } finally {
        if ($deleteZip -eq $true) {
            if (Test-Path $diagnosticZipOut) {
                log "Deleting zip file"
                Remove-Item -Path $diagnosticZipOut
            }
        }

        if ($null -ne $tempZipPath) {
            if (Test-Path $tempZipPath) {
                log "Deleting temporary zip file"
                Remove-Item -Path $tempZipPath
            }
        }

        log "Deleting temporary files"
        Remove-Item -Recurse -Path $diagnosticWorkDir

        # log is deleted and can't be writen to anymore
    }
}

$global:exitcode = 1

main
[Environment]::Exit($global:exitcode)
