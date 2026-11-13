[CmdletBinding()]
param(
    # Also request every external link (HEAD/GET). Off by default so the check works offline.
    [switch]$CheckExternalLinks,
    # Skip the Gitleaks scans (for a quick content-only run). Never skip before a push.
    [switch]$SkipGitleaks
)

# Builds the site and runs the checks that must pass before any push:
#   1. Hugo build with warnings treated as errors.
#   2. Output checks: no scripts, no third-party resources, every image has alt text,
#      internal links and #anchors resolve, external links only to allowed hosts.
#   3. Content scan of the repository's files, the built site and commit metadata for personal
#      or internal details: email addresses other than the public contact, IP addresses,
#      user-profile paths, plus any patterns in the untracked .content-scan.local.txt.
#   4. Gitleaks over the git history and the working tree.
# Exits non-zero when anything fails. Works on Windows and Linux (CI).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
$failures = [System.Collections.Generic.List[string]]::new()
function Fail([string]$message) { $failures.Add($message); Write-Host "  FAIL $message" -ForegroundColor Red }

try {
    $tools = @(& (Join-Path $PSScriptRoot 'Install-Tools.ps1'))
    $hugo = $tools | Where-Object { $_ -match 'hugo' } | Select-Object -First 1
    $gitleaks = $tools | Where-Object { $_ -match 'gitleaks' } | Select-Object -First 1

    # 1. Build ---------------------------------------------------------------------------
    Write-Host '== Build'
    & $hugo --minify --gc --cleanDestinationDir --panicOnWarning
    if ($LASTEXITCODE -ne 0) { throw 'Hugo build failed.' }
    $public = Join-Path $root 'public'

    # 2. Output checks -------------------------------------------------------------------
    Write-Host '== Output'
    $allowedHosts = @('github.com', 'docs.github.com')
    $allowedSchemes = @('mailto:blueblock@multichamber.dev')
    $htmlFiles = Get-ChildItem -LiteralPath $public -Recurse -Filter '*.html' -File
    $idsByFile = @{}
    foreach ($f in $htmlFiles) {
        # Attributes are read only from start tags, so text that looks like markup is ignored.
        $tags = ([regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), '<[a-zA-Z][^>]*>') | ForEach-Object Value) -join "`n"
        $idsByFile[$f.FullName] = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@([regex]::Matches($tags, '\sid="?([^"\s>]+)') | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) }))
    }
    $external = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($f in $htmlFiles) {
        $rel = [System.IO.Path]::GetRelativePath($public, $f.FullName)
        $html = ([regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), '<[a-zA-Z][^>]*>') | ForEach-Object Value) -join "`n"
        if ($html -match '<script\b') { Fail "${rel}: contains a <script> element" }
        if ($html -match '\son[a-z]+\s*=') { Fail "${rel}: contains an inline event handler" }
        if ($html -match '\sstyle\s*=') { Fail "${rel}: contains an inline style attribute (blocked by the CSP)" }
        foreach ($m in [regex]::Matches($html, '<img\b[^>]*>')) {
            # alt must be present; an empty alt is right for decorative images such as the header logo.
            if ($m.Value -notmatch '\salt(?=[\s=>/])') { Fail "${rel}: <img> without an alt attribute: $($m.Value)" }
        }
        foreach ($m in [regex]::Matches($html, '<(?:link|img|source|iframe|embed|object)\b[^>]*\s(?:href|src)="?(https?:)?//[^"\s>]+')) {
            if ($m.Value -notmatch 'rel="?canonical') { Fail "${rel}: loads a resource from another site: $($m.Value)" }
        }
        foreach ($m in [regex]::Matches($html, '\s(?:href|src)="?([^"\s>]+)')) {
            $url = [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
            if ($url -match '^https?://') {
                $uri = [uri]$url
                if ($uri.Host -eq 'www.multichamber.dev') { $url = $uri.PathAndQuery + $uri.Fragment }
                else {
                    if ($uri.Scheme -ne 'https') { Fail "${rel}: insecure link $url" }
                    if ($allowedHosts -notcontains $uri.Host) { Fail "${rel}: link to a host that isn't allowed: $url" }
                    [void]$external.Add($url)
                    continue
                }
            }
            if ($url -match '^[a-z]+:') {
                if ($allowedSchemes -notcontains $url) { Fail "${rel}: unexpected link $url" }
                continue
            }
            $path, $fragment = $url -split '#', 2
            $path = ($path -split '\?', 2)[0]
            if ($fragment) { $fragment = [uri]::UnescapeDataString($fragment) }
            if ($path -eq '') { $target = $f.FullName }
            else {
                $base = if ($path.StartsWith('/')) { $public } else { $f.DirectoryName }
                $target = Join-Path $base ([uri]::UnescapeDataString($path.TrimStart('/')))
                if (Test-Path -LiteralPath $target -PathType Container) { $target = Join-Path $target 'index.html' }
                $target = [System.IO.Path]::GetFullPath($target)
            }
            if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { Fail "${rel}: broken link $url"; continue }
            if ($fragment) {
                if (-not $idsByFile.ContainsKey($target)) { Fail "${rel}: anchor on a link to a non-HTML file $url" }
                elseif (-not $idsByFile[$target].Contains($fragment)) { Fail "${rel}: missing anchor $url" }
            }
        }
    }
    if ($CheckExternalLinks) {
        foreach ($url in $external) {
            try { Invoke-WebRequest -Uri $url -Method Get -MaximumRedirection 5 -UseBasicParsing -TimeoutSec 20 | Out-Null }
            catch { Fail "external link failed: $url ($($_.Exception.Message))" }
        }
    } else {
        Write-Host "  $($external.Count) external link(s) not requested (use -CheckExternalLinks)."
    }

    # 3. Content scan --------------------------------------------------------------------
    Write-Host '== Content scan'
    $patterns = [ordered]@{
        'email address'     = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
        'IPv4 address'      = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
        'Windows user path' = '(?i)\b[a-z]:[\\/]+users[\\/]+[^\\/\s"''<>]+'
        'Unix home path'    = '(?<![\w.])/(?:home|Users)/[A-Za-z0-9._-]+'
    }
    $allowed = @(
        'blueblock@multichamber.dev',   # the public contact
        '127.0.0.1'                     # loopback, used in generic examples
    )
    $local = Join-Path $root '.content-scan.local.txt'
    if (Test-Path -LiteralPath $local) {
        $i = 0
        foreach ($line in Get-Content -LiteralPath $local) {
            if ($line.Trim() -and -not $line.TrimStart().StartsWith('#')) { $patterns["local pattern $((++$i))"] = $line.Trim() }
        }
        Write-Host "  + $i local pattern(s) from .content-scan.local.txt"
    } else {
        Write-Host '  No .content-scan.local.txt; generic patterns only.'
    }

    $textExt = '.md', '.html', '.htm', '.css', '.toml', '.yml', '.yaml', '.json', '.ps1', '.txt', '.xml', '.svg', '.gitignore', ''
    $listed = (git -c core.quotePath=false ls-files -z --cached --others --exclude-standard) -split "`0" | Where-Object { $_ }
    $repoFiles = foreach ($p in $listed) {
        $full = Join-Path $root $p
        # A tracked file deleted in the working tree is fine; anything else unreadable is a failure.
        if (-not (Test-Path -LiteralPath $full -PathType Leaf) -and @(git ls-files --deleted -- $p).Count -eq 0) { Fail "cannot read listed file $p" }
        $full
    }
    $builtFiles = Get-ChildItem -LiteralPath $public -Recurse -File | ForEach-Object FullName
    $scanFiles = @($repoFiles + $builtFiles) | Where-Object {
        (Test-Path -LiteralPath $_ -PathType Leaf) -and ($textExt -contains [System.IO.Path]::GetExtension($_).ToLowerInvariant())
    }
    # This script's own pattern text must not trip the scan.
    $self = (Resolve-Path -LiteralPath $PSCommandPath).Path
    foreach ($file in $scanFiles) {
        if ((Resolve-Path -LiteralPath $file).Path -eq $self) { continue }
        $rel = [System.IO.Path]::GetRelativePath($root, $file)
        $n = 0
        foreach ($line in Get-Content -LiteralPath $file) {
            $n++
            foreach ($kind in $patterns.Keys) {
                foreach ($m in [regex]::Matches($line, $patterns[$kind])) {
                    if ($allowed -contains $m.Value) { continue }
                    if ($kind -eq 'IPv4 address' -and $file -match '[\\/]tools\.json$') { continue }
                    Fail "${rel}:${n}: $kind '$($m.Value)'"
                }
            }
        }
    }
    # Commit metadata for what would be pushed (local branches, tags and HEAD): authors and
    # committers must be the public identity, and no message may carry a co-author or
    # "generated with" attribution line.
    $refs = @('--branches', '--tags', 'HEAD')
    foreach ($id in @(git log @refs --format='%an <%ae>%n%cn <%ce>' | Sort-Object -Unique)) {
        if ($id -and $id -ne 'BlueBlock <blueblock@multichamber.dev>' -and $id -notmatch '^GitHub <noreply@github\.com>$') {
            Fail "commit identity '$id' is not the public identity"
        }
    }
    foreach ($line in @(git log @refs --format='%B')) {
        if ($line -match '(?i)^\s*co-authored-by:|generated (with|by) \[?(claude|copilot|chatgpt|ai\b)') {
            Fail "commit message: attribution line '$($line.Trim())'"
        }
        foreach ($kind in $patterns.Keys) {
            foreach ($m in [regex]::Matches($line, $patterns[$kind])) {
                if ($allowed -notcontains $m.Value) { Fail "commit message: $kind '$($m.Value)'" }
            }
        }
    }

    # 4. Gitleaks ------------------------------------------------------------------------
    if (-not $SkipGitleaks) {
        Write-Host '== Gitleaks'
        & $gitleaks git --no-banner --redact --exit-code 1 $root
        if ($LASTEXITCODE -ne 0) { Fail 'gitleaks found secrets in the git history' }
        & $gitleaks dir --no-banner --redact --exit-code 1 --config (Join-Path $root '.gitleaks.toml') $root
        if ($LASTEXITCODE -ne 0) { Fail 'gitleaks found secrets in the working tree' }
    }
}
finally {
    Pop-Location
}

if ($failures.Count) {
    Write-Host "`n$($failures.Count) check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "`nAll checks passed." -ForegroundColor Green
