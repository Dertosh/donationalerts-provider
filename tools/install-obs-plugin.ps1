[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [string]$ObsInstallRoot = "C:\Program Files\obs-studio",
    [string]$DllPath
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$moduleName = "donationalerts-obs-provider"
$obsExecutable = Join-Path $ObsInstallRoot "bin\64bit\obs64.exe"
$sourceDll = if ([string]::IsNullOrWhiteSpace($DllPath)) {
    Join-Path $projectRoot "obs-plugin\build\$Configuration\donationalerts-obs-provider.dll"
} else {
    $DllPath
}
$sourceLocale = Join-Path $projectRoot "obs-plugin\data\locale"
$sourceDemoRoot = Join-Path $projectRoot "obs-plugin\demo"
$sourceDemoFiles = @(Get-ChildItem -LiteralPath $sourceDemoRoot -File)
$sourceDemoPages = @($sourceDemoFiles | Where-Object { $_.Extension -eq ".html" })
$sourceTlsBackend = Join-Path $projectRoot "obs-plugin\build\$Configuration\qt-plugins\tls\qschannelbackend.dll"
$pluginRoot = Join-Path $env:ProgramData "obs-studio\plugins\$moduleName"
$binaryRoot = Join-Path $pluginRoot "bin\64bit"
$tlsRoot = Join-Path $binaryRoot "qt-plugins\tls"
$localeRoot = Join-Path $pluginRoot "data\locale"
$demoRoot = Join-Path $pluginRoot "data\demo"

if (Get-Process -Name "obs64" -ErrorAction SilentlyContinue) {
    throw "OBS is running. Close OBS completely before installing the plugin, then run this script again."
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $quotePowerShellString = {
        param([string]$Value)
        "'" + $Value.Replace("'", "''") + "'"
    }

    $childCommand = "& $(& $quotePowerShellString $PSCommandPath) -Configuration $(& $quotePowerShellString $Configuration) -ObsInstallRoot $(& $quotePowerShellString $ObsInstallRoot)"
    if (-not [string]::IsNullOrWhiteSpace($DllPath)) {
        $childCommand += " -DllPath $(& $quotePowerShellString $DllPath)"
    }
    if ($WhatIfPreference) {
        $childCommand += " -WhatIf"
    }
    if ($PSBoundParameters.ContainsKey("Confirm")) {
        $childCommand += " -Confirm"
    }

    $elevatedPowerShell = Join-Path $PSHOME "powershell.exe"
    if (-not (Test-Path -LiteralPath $elevatedPowerShell -PathType Leaf)) {
        throw "Could not locate Windows PowerShell to request administrator permission."
    }
    $diagnosticId = [Guid]::NewGuid().ToString("N")
    $logPath = Join-Path $env:TEMP "donationalerts-obs-install-$diagnosticId.log"
    $childCommand = "`$ErrorActionPreference = 'Stop'; try { $childCommand *>&1 | Out-File -LiteralPath $(& $quotePowerShellString $logPath) -Encoding utf8; exit 0 } catch { `$_ | Out-File -LiteralPath $(& $quotePowerShellString $logPath) -Append -Encoding utf8; exit 1 }"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCommand))
    try {
        $process = Start-Process -FilePath $elevatedPowerShell `
            -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encodedCommand) `
            -Verb RunAs `
            -Wait `
            -PassThru
    } catch {
        Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
        throw "Administrator permission was not granted; installation was cancelled. $($_.Exception.Message)"
    }
    if ($process.ExitCode -ne 0) {
        $diagnostics = if (Test-Path -LiteralPath $logPath -PathType Leaf) {
            Get-Content -LiteralPath $logPath -ErrorAction SilentlyContinue
        } else {
            @()
        }
        Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
        $details = ($diagnostics -join [Environment]::NewLine).Trim()
        if ([string]::IsNullOrWhiteSpace($details)) {
            $details = "The elevated process did not provide additional error details."
        }
        throw "Elevated installer failed with exit code $($process.ExitCode): $details"
    }
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
    return
}

if (-not (Test-Path -LiteralPath $obsExecutable -PathType Leaf)) {
    throw "OBS Studio x64 was not found at '$obsExecutable'. Install OBS 32.2.2 or pass -ObsInstallRoot."
}

$installedVersion = (Get-Item -LiteralPath $obsExecutable).VersionInfo.ProductVersion
if ($installedVersion -ne "32.2.2") {
    throw "This plugin build targets OBS 32.2.2, but '$obsExecutable' reports version '$installedVersion'."
}

if (-not (Test-Path -LiteralPath $sourceDll -PathType Leaf)) {
    throw "Plugin DLL was not found at '$sourceDll'. Build the plugin first or pass -DllPath."
}

$localeFiles = @(Get-ChildItem -LiteralPath $sourceLocale -Filter "*.ini" -File)
if ($localeFiles.Count -eq 0) {
    throw "No locale files were found in '$sourceLocale'."
}

if ($sourceDemoPages.Count -eq 0) {
    throw "No demo widget pages were found in '$sourceDemoRoot'."
}

if (-not (Test-Path -LiteralPath $sourceTlsBackend -PathType Leaf)) {
    throw "Qt Schannel TLS backend was not found at '$sourceTlsBackend'. Rebuild the plugin before installing."
}

if ($PSCmdlet.ShouldProcess($pluginRoot, "Install DonationAlerts OBS Provider")) {
    New-Item -ItemType Directory -Force -Path $binaryRoot, $localeRoot, $tlsRoot, $demoRoot | Out-Null
    Copy-Item -LiteralPath $sourceDll -Destination $binaryRoot -Force
    Copy-Item -Path (Join-Path $sourceLocale "*.ini") -Destination $localeRoot -Force
    Copy-Item -LiteralPath $sourceTlsBackend -Destination $tlsRoot -Force
    foreach ($demoFile in $sourceDemoFiles) {
        Copy-Item -LiteralPath $demoFile.FullName -Destination $demoRoot -Force
    }

    $installedDll = Join-Path $binaryRoot "donationalerts-obs-provider.dll"
    if (-not (Test-Path -LiteralPath $installedDll -PathType Leaf)) {
        throw "Installation did not produce '$installedDll'."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $tlsRoot "qschannelbackend.dll") -PathType Leaf)) {
        throw "Installation did not produce the Qt Schannel TLS backend."
    }
    foreach ($demoFile in $sourceDemoFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $demoRoot $demoFile.Name) -PathType Leaf)) {
            throw "Installation did not produce the demo asset '$($demoFile.Name)'."
        }
    }

    Write-Host "DonationAlerts OBS Provider and demo widget installed successfully."
    Write-Host "Restart OBS and open Tools -> DonationAlerts Provider."
    foreach ($demoFile in $sourceDemoPages) {
        Write-Host "Demo widget: $(Join-Path $demoRoot $demoFile.Name)"
    }
}
