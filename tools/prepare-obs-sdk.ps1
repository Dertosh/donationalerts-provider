param(
    [string]$ObsInstallRoot = "C:\Program Files\obs-studio",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$sdkRoot = Join-Path $projectRoot ".obs-sdk"
$sourceRoot = Join-Path $sdkRoot "source"
$obsSource = Join-Path $sourceRoot "obs-studio-32.2.2-sources"
$archivePath = Join-Path $sdkRoot "OBS-Studio-32.2.2-Sources.tar.gz"
$buildRoot = Join-Path $sdkRoot "build"
$expectedHash = "ec81fb66b03e75ddb3076b576f62679c39262e0e9960cef3e17a40dc5d68e6b4"
$archiveUrl = "https://github.com/obsproject/obs-studio/releases/download/32.2.2/OBS-Studio-32.2.2-Sources.tar.gz"

$obsExecutable = Join-Path $ObsInstallRoot "bin\64bit\obs64.exe"
if (-not (Test-Path -LiteralPath $obsExecutable)) {
    throw "OBS Studio x64 was not found at '$obsExecutable'. Install OBS Studio 32.2.2 or pass -ObsInstallRoot."
}

$installedVersion = (Get-Item -LiteralPath $obsExecutable).VersionInfo.ProductVersion
if ($installedVersion -ne "32.2.2") {
    throw "This SDK setup is pinned to OBS 32.2.2, but '$obsExecutable' reports version '$installedVersion'."
}

if (-not (Get-Command cmake.exe -ErrorAction SilentlyContinue)) {
    throw "CMake is required. Install CMake 3.28 or newer and run this script again."
}

$compiler = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path -LiteralPath $compiler)) {
    $compiler = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path -LiteralPath $compiler)) {
    throw "Visual Studio 2022 C++ Build Tools are required."
}

New-Item -ItemType Directory -Force -Path $sdkRoot, $sourceRoot | Out-Null

if (-not (Test-Path -LiteralPath (Join-Path $obsSource "CMakeLists.txt"))) {
    if (-not (Test-Path -LiteralPath $archivePath)) {
        Write-Host "Downloading official OBS Studio 32.2.2 source archive..."
        & curl.exe --fail --location --retry 3 --output $archivePath $archiveUrl
        if ($LASTEXITCODE -ne 0) {
            throw "OBS source download failed with exit code $LASTEXITCODE."
        }
    }

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "OBS source SHA-256 mismatch. Expected $expectedHash, got $actualHash."
    }

    Write-Host "Extracting verified OBS source archive..."
    Push-Location -LiteralPath $sdkRoot
    try {
        & cmake.exe -E tar xzf $archivePath
        $extractExitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($extractExitCode -ne 0) {
        throw "OBS source archive extraction failed with exit code $extractExitCode."
    }
    Move-Item -LiteralPath (Join-Path $sdkRoot "obs-studio-32.2.2-sources") -Destination $obsSource
}

Write-Host "Configuring the OBS 32.2.2 x64 SDK..."
& cmake.exe `
    -S $obsSource `
    -B $buildRoot `
    -G "Visual Studio 17 2022" `
    -A "x64,version=10.0.26100.0" `
    "-DCMAKE_INSTALL_PREFIX=$(Join-Path $sdkRoot 'install')" `
    "-DENABLE_FRONTEND=ON" `
    "-DENABLE_BROWSER=OFF" `
    "-DENABLE_SCRIPTING=OFF" `
    "-DENABLE_HEVC=OFF"
if ($LASTEXITCODE -ne 0) {
    throw "OBS SDK CMake configuration failed with exit code $LASTEXITCODE."
}

Write-Host "Building libobs and OBS Frontend API ($Configuration)..."
& cmake.exe --build $buildRoot --config $Configuration --target libobs obs-frontend-api --parallel
if ($LASTEXITCODE -ne 0) {
    throw "OBS SDK build failed with exit code $LASTEXITCODE."
}

Write-Host "OBS SDK is ready at '$sdkRoot'."
