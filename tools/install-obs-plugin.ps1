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
$pluginRoot = Join-Path $env:ProgramData "obs-studio\plugins\$moduleName"
$binaryRoot = Join-Path $pluginRoot "bin\64bit"
$localeRoot = Join-Path $pluginRoot "data\locale"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from PowerShell opened with 'Run as administrator'."
}

if (Get-Process -Name "obs64" -ErrorAction SilentlyContinue) {
    throw "OBS is running. Close OBS completely before installing the plugin."
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

if ($PSCmdlet.ShouldProcess($pluginRoot, "Install DonationAlerts OBS Provider")) {
    New-Item -ItemType Directory -Force -Path $binaryRoot, $localeRoot | Out-Null
    Copy-Item -LiteralPath $sourceDll -Destination $binaryRoot -Force
    Copy-Item -Path (Join-Path $sourceLocale "*.ini") -Destination $localeRoot -Force

    $installedDll = Join-Path $binaryRoot "donationalerts-obs-provider.dll"
    if (-not (Test-Path -LiteralPath $installedDll -PathType Leaf)) {
        throw "Installation did not produce '$installedDll'."
    }

    Write-Host "DonationAlerts OBS Provider installed successfully."
    Write-Host "Restart OBS and open Tools -> DonationAlerts Provider."
}
