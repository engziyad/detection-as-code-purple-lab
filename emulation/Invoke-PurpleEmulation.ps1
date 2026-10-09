<#
.SYNOPSIS
    Safe, self-cleaning adversary emulation for the Purple Lab detections.

.DESCRIPTION
    Generates the exact telemetry each detection in /detections is built for,
    then cleans up after itself. Every run is logged to a JSON file with
    UTC timestamps so you can line emulation up with SIEM alerts and measure
    detection latency.

    *** LAB USE ONLY. Run on an isolated, disposable VM that you own. ***

.PARAMETER Technique
    One or more ATT&CK IDs, or 'All'.

.PARAMETER LabConfirmed
    Mandatory acknowledgement that this host is an isolated lab machine.

.PARAMETER IncludeCredentialAccess
    Required in addition for T1003.001 (dumps LSASS memory to %TEMP% and deletes it).

.PARAMETER Spn
    Service Principal Name to request for T1558.003 (domain-joined lab only).

.EXAMPLE
    .\Invoke-PurpleEmulation.ps1 -Technique T1059.001,T1547.001 -LabConfirmed

.EXAMPLE
    .\Invoke-PurpleEmulation.ps1 -Technique All -LabConfirmed -IncludeCredentialAccess -Spn MSSQLSvc/sql01.lab.local:1433
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('All','T1003.001','T1059.001','T1218.011','T1053.005','T1547.001','T1569.002','T1070.001','T1558.003')]
    [string[]] $Technique,

    [Parameter(Mandatory)]
    [switch] $LabConfirmed,

    [switch] $IncludeCredentialAccess,

    [string] $Spn,

    [string] $LogPath = (Join-Path $PSScriptRoot 'emulation-results.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Results = [System.Collections.Generic.List[object]]::new()

function Invoke-Step {
    param([string]$Id, [string]$Name, [scriptblock]$Action, [scriptblock]$Cleanup, [switch]$NeedsAdmin)

    if ($NeedsAdmin -and -not $IsAdmin) {
        Write-Warning "[$Id] skipped - requires an elevated session"
        $Results.Add([pscustomobject]@{ technique=$Id; name=$Name; status='skipped'; reason='not admin'; utc=(Get-Date).ToUniversalTime().ToString('o') })
        return
    }
    $start = (Get-Date).ToUniversalTime()
    Write-Host "[$Id] $Name" -ForegroundColor Cyan
    $status = 'executed'; $err = $null
    try   { & $Action }
    catch { $status = 'error'; $err = $_.Exception.Message; Write-Warning "[$Id] $err" }
    finally {
        if ($Cleanup) { try { & $Cleanup } catch { Write-Warning "[$Id] cleanup: $($_.Exception.Message)" } }
    }
    $Results.Add([pscustomobject]@{
        technique = $Id; name = $Name; status = $status; error = $err
        host = $env:COMPUTERNAME; user = "$env:USERDOMAIN\$env:USERNAME"
        utc_start = $start.ToString('o'); utc_end = (Get-Date).ToUniversalTime().ToString('o')
    })
    Start-Sleep -Seconds 2   # spacing makes events easy to separate in the SIEM
}

$Marker = "purplelab_$([guid]::NewGuid().ToString('N').Substring(0,8))"
$All    = $Technique -contains 'All'
function Want([string]$id) { $All -or ($Technique -contains $id) }

# ---------------------------------------------------------------- T1059.001
if (Want 'T1059.001') {
    Invoke-Step 'T1059.001' 'PowerShell -EncodedCommand (benign payload)' {
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '$Marker'"))
        & powershell.exe -NoProfile -enc $enc | Out-Null
    }
}

# ---------------------------------------------------------------- T1218.011
if (Want 'T1218.011') {
    Invoke-Step 'T1218.011' 'rundll32 javascript: proxy execution (closes immediately)' {
        Start-Process rundll32.exe -ArgumentList 'javascript:"\..\mshtml,RunHTMLApplication ";close();' -Wait
    }
}

# ---------------------------------------------------------------- T1053.005
if (Want 'T1053.005') {
    Invoke-Step 'T1053.005' 'schtasks /create with cmd /c action in %TEMP%' {
        & schtasks.exe /create /tn $Marker /sc once /st 23:59 /f /tr "cmd /c echo $Marker > %TEMP%\$Marker.txt" | Out-Null
    } {
        & schtasks.exe /delete /tn $Marker /f 2>$null | Out-Null
    }
}

# ---------------------------------------------------------------- T1547.001
if (Want 'T1547.001') {
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    Invoke-Step 'T1547.001' 'HKCU Run value pointing to %TEMP% (file does not exist)' {
        New-ItemProperty -Path $runKey -Name $Marker -Value "$env:LOCALAPPDATA\Temp\$Marker.exe" -PropertyType String -Force | Out-Null
    } {
        Remove-ItemProperty -Path $runKey -Name $Marker -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- T1569.002
if (Want 'T1569.002') {
    Invoke-Step 'T1569.002' 'Service install with cmd.exe /c binPath (never started)' -NeedsAdmin {
        & sc.exe create $Marker binPath= "cmd.exe /c echo $Marker" start= demand | Out-Null
    } {
        & sc.exe delete $Marker 2>$null | Out-Null
    }
}

# ---------------------------------------------------------------- T1070.001
if (Want 'T1070.001') {
    Invoke-Step 'T1070.001' 'wevtutil cl on a dedicated test log (never Security/System)' -NeedsAdmin {
        New-EventLog -LogName $Marker -Source $Marker
        Write-EventLog -LogName $Marker -Source $Marker -EventId 1 -Message 'purple lab test entry'
        & wevtutil.exe cl $Marker
    } {
        Remove-EventLog -LogName $Marker -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- T1003.001
if (Want 'T1003.001') {
    if (-not $IncludeCredentialAccess) {
        Write-Warning '[T1003.001] skipped - add -IncludeCredentialAccess to dump LSASS (lab only)'
    } else {
        $dump = Join-Path $env:TEMP "$Marker.dmp"
        Invoke-Step 'T1003.001' 'LSASS MiniDump via comsvcs.dll (dump deleted immediately)' -NeedsAdmin {
            $pid_ = (Get-Process lsass).Id
            Start-Process rundll32.exe -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $pid_ $dump full" -Wait
        } {
            Remove-Item $dump -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------- T1558.003
if (Want 'T1558.003') {
    if (-not $Spn) {
        Write-Warning '[T1558.003] skipped - provide -Spn <service/host> from your lab domain'
    } else {
        Invoke-Step 'T1558.003' "Request a TGS for $Spn (no export, no cracking)" {
            Add-Type -AssemblyName System.IdentityModel
            $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $Spn
        }
    }
}

$Results | ConvertTo-Json -Depth 3 | Set-Content -Path $LogPath -Encoding UTF8
Write-Host "`n[+] $($Results.Count) step(s) logged to $LogPath (marker: $Marker)" -ForegroundColor Green
Write-Host '    Search your SIEM for the marker string to find the generated events.'
