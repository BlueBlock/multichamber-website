[CmdletBinding()]
param(
    # Tools to install from tools.json; all when omitted.
    [string[]]$Name
)

# Downloads the pinned build tools listed in tools.json into .tools/<name>-<version>/ and checks
# each archive's SHA-256 before extracting it. Nothing is installed globally. Prints the path of
# each tool's executable. Works on Windows x64 and Linux x64 (GitHub-hosted runners).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$pins = Get-Content -LiteralPath (Join-Path $root 'tools.json') -Raw | ConvertFrom-Json
$platform = if ($IsWindows) { 'windows-x64' } elseif ($IsLinux) { 'linux-x64' } else { throw 'Only Windows x64 and Linux x64 are supported.' }
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') { throw 'Only x64 is supported.' }

$toolsDir = Join-Path $root '.tools'
$names = if ($Name) { $Name } else { $pins.PSObject.Properties.Name | Where-Object { $_ -notlike '_*' } }

foreach ($tool in $names) {
    $pin = $pins.$tool
    if (-not $pin) { throw "Unknown tool '$tool'." }
    $asset = $pin.$platform
    $dir = Join-Path $toolsDir "$tool-$($pin.version)"
    $exe = Join-Path $dir $asset.exe
    $receipt = Join-Path $dir '.sha256'

    if ((Test-Path -LiteralPath $exe) -and (Test-Path -LiteralPath $receipt) -and
        ((Get-Content -LiteralPath $receipt -Raw).Trim() -eq $asset.sha256)) {
        Write-Output $exe
        continue
    }

    $download = Join-Path $toolsDir ".download-$tool"
    if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $download | Out-Null
    $archive = Join-Path $download ([System.IO.Path]::GetFileName(([uri]$asset.url).AbsolutePath))

    Write-Host "Downloading $tool $($pin.version) ..."
    Invoke-WebRequest -Uri $asset.url -OutFile $archive -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $asset.sha256) {
        Remove-Item -LiteralPath $download -Recurse -Force
        throw "$tool archive failed verification: expected $($asset.sha256), got $actual."
    }

    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    if ($archive.EndsWith('.zip')) {
        Expand-Archive -LiteralPath $archive -DestinationPath $dir
    } else {
        tar -xzf $archive -C $dir
        if ($LASTEXITCODE -ne 0) { throw "Could not extract $archive." }
    }
    if (-not (Test-Path -LiteralPath $exe)) { throw "$tool archive did not contain $($asset.exe)." }
    Set-Content -LiteralPath $receipt -Value $asset.sha256 -NoNewline
    Remove-Item -LiteralPath $download -Recurse -Force
    Write-Output $exe
}
