# App-owned adapter: upstream files remain unchanged across updates.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$env:PYTHONIOENCODING = 'utf-8'
$ProgressPreference = 'SilentlyContinue'
$PSDefaultParameterValues['Invoke-WebRequest:UseBasicParsing'] = $true
$PSDefaultParameterValues['Invoke-WebRequest:TimeoutSec'] = 120
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tokens = $null; $parseErrors = $null
$source = Get-Content -LiteralPath $env:MEMFORENSICS_UPDATER -Raw
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Cannot parse Analyzer updater' }
$declarations = [regex]::Match($source, '(?s)#region Declarations.*?#endregion Declarations')
if (!$declarations.Success) { throw 'Unsupported Analyzer updater: declarations missing' }
. ([scriptblock]::Create($declarations.Value.Replace('$PSScriptRoot', '$env:MEMFORENSICS_ANALYZER_ROOT')))

# Bootstrap packages before *every new requirements version* is used, including
# the first --update-rules call immediately following a fresh source download.
$script:preparedRequirements = ''
function python {
    if ($args -contains '--update-rules') {
        Write-Output '[Setup] Sigma download deferred to the verified update stage.'
        return
    }
    $requirements = Join-Path $env:MEMFORENSICS_ANALYZER_ROOT 'Tools\Zircolite\requirements.txt'
    $project = Join-Path $env:MEMFORENSICS_ANALYZER_ROOT 'Tools\Zircolite\pyproject.toml'
    $packageArgs = @('-r', $requirements)
    if (Test-Path -LiteralPath $project -PathType Leaf) {
        $requirements = $project
        $packageArgs = @((Split-Path $project))
    } elseif (!(Test-Path -LiteralPath $requirements -PathType Leaf)) {
        throw 'Zircolite dependency metadata missing (pyproject.toml or requirements.txt)'
    }
    $fingerprint = (Get-FileHash -LiteralPath $requirements -Algorithm SHA256).Hash
    if ($script:preparedRequirements -ne $fingerprint) {
        if (!(Test-Path -LiteralPath $env:MEMFORENSICS_ZIRCOLITE_PYTHON)) {
            & $env:MEMFORENSICS_BASE_PYTHON -m venv (Split-Path (Split-Path $env:MEMFORENSICS_ZIRCOLITE_PYTHON))
            if ($LASTEXITCODE -ne 0) { throw 'Cannot create Zircolite environment' }
        }
        Write-Host '[Setup] Installing Zircolite Python dependencies...'
        & $env:MEMFORENSICS_ZIRCOLITE_PYTHON -m pip install --disable-pip-version-check --timeout 120 --retries 5 @packageArgs | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Zircolite dependency installation failed' }
        $script:preparedRequirements = $fingerprint
    }
    & $env:MEMFORENSICS_ZIRCOLITE_PYTHON @args
    if ($LASTEXITCODE -ne 0) { throw "Zircolite failed with exit code $LASTEXITCODE" }
}

function Select-YaraWindowsAsset($releases) {
    foreach ($release in $releases) {
        if ($release.draft -or $release.prerelease) { continue }
        $assets = @($release.assets | Where-Object { $_.name -match '^yara-.*-win64\.zip$' })
        if ($assets.Count -eq 0) { continue }
        if ($assets.Count -ne 1) { throw "Ambiguous Windows YARA archives in $($release.tag_name)" }
        $uri = $null
        if (![uri]::TryCreate([string]$assets[0].browser_download_url, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com') {
            throw "Invalid Windows YARA download URL in $($release.tag_name)"
        }
        return @{ Tag = $release.tag_name; Url = $uri.AbsoluteUri }
    }
    return $null
}

function Install-YaraWindows {
    # Recent source releases may have no binaries. Walk stable releases in
    # GitHub's newest-first order and select exactly one Windows archive.
    $selected = $null
    for ($page = 1; $page -le 5 -and !$selected; $page++) {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/VirusTotal/yara/releases?per_page=30&page=$page" -TimeoutSec 120
        $selected = Select-YaraWindowsAsset $releases
        if ($releases.Count -lt 30) { break }
    }
    if (!$selected) { throw 'No official Windows 64-bit YARA archive found in recent releases' }
    Write-Output "[Setup] YARA $($selected.Tag): newest available official Windows 64-bit binary"
    $destination = Join-Path $env:MEMFORENSICS_ANALYZER_ROOT 'Tools\YARA'
    $zip = Join-Path ([IO.Path]::GetTempPath()) ("memfusion-yara-" + [guid]::NewGuid() + '.zip')
    try {
        Invoke-WebRequest -Uri $selected.Url -OutFile $zip -UseBasicParsing -TimeoutSec 120
        Expand-Archive -LiteralPath $zip -DestinationPath $destination -Force
        $exe = Join-Path $destination 'yara64.exe'
        if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'YARA archive did not contain yara64.exe' }
        & $exe --version
        if ($LASTEXITCODE -ne 0) { throw 'YARA executable verification failed' }
    } finally {
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    }
}

# The app installs MemProcFS and drivers separately. The mounted adapter does
# not run the upstream ClamAV or Elasticsearch/Kibana workflows.
$steps = @('Get-YaraCustomRules','Get-AmcacheParser','Get-AppCompatCacheParser','Get-Entropy',
    'Get-EvtxECmd','Get-IPinfo','Get-jq','Get-lnk_parser','Get-RECmd',
    'Get-SBECmd','Get-XSV','Get-Yara','Get-Zircolite')
$failures = @()
foreach ($step in $steps) {
    try {
        Write-Output "[Setup] Starting $step"
        if ($step -eq 'Get-Yara') {
            Install-YaraWindows
            Write-Output "[Setup] Finished $step"
            continue
        }
        $definition = @($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $step}, $true))
        if ($definition.Count -ne 1) { throw "Unsupported updater: $step missing or ambiguous" }
        . ([scriptblock]::Create($definition[0].Extent.Text))
        & $step
        # Upstream downloads lnk_parser.exe but its analysis script expects
        # lnk_parser_x86_64.exe. Keep this compatibility fix in our adapter.
        if ($step -eq 'Get-lnk_parser') {
            $downloaded = Join-Path $env:MEMFORENSICS_ANALYZER_ROOT 'Tools\lnk_parser\lnk_parser.exe'
            $expected = Join-Path $env:MEMFORENSICS_ANALYZER_ROOT 'Tools\lnk_parser\lnk_parser_x86_64.exe'
            if (Test-Path -LiteralPath $downloaded -PathType Leaf) {
                Copy-Item -LiteralPath $downloaded -Destination $expected -Force
            }
            if (!(Test-Path -LiteralPath $expected -PathType Leaf)) { throw 'LNK parser download is missing' }
        }
        Write-Output "[Setup] Finished $step"
    } catch {
        $failures += "${step}: $($_.Exception.Message)"
        Write-Output "[Setup] Failed: $($failures[-1])"
    }
}
try {
    Write-Output '[Setup] Installing/updating ImportExcel for the current user'
    if (!(Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }
    Install-Module -Name ImportExcel -Scope CurrentUser -Repository PSGallery -Force -Confirm:$false
    Import-Module ImportExcel -ErrorAction Stop
} catch { $failures += "ImportExcel: $($_.Exception.Message)" }
if ($failures.Count) { throw ($failures -join '; ') }
Write-Output 'MEMFORENSICS_UPDATER_COMPLETE'
