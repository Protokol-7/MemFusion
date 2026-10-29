param([string]$AnalyzerScript, [string]$MemProcFSPath, [string]$ImagePath, [string]$MountRoot, [string]$OutputRoot, [switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath $AnalyzerScript -Raw
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Analyzer source could not be parsed.' }
$functions = $ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)
$header = $functions | Where-Object Name -eq 'Header' | Select-Object -First 1
$mem = $functions | Where-Object Name -eq 'MemProcFS' | Select-Object -First 1
if (!$header -or !$mem) { throw 'Unsupported Analyzer layout: required functions missing.' }
$body = $mem.Extent.Text
$start = $body.IndexOf('# Remove existing MemProcFS Logfile')
$end = $body.IndexOf('# Check if Mount Point exists')
if ($start -lt 0 -or $end -le $start) { throw 'Unsupported Analyzer layout: mount adapter needs updating.' }
$body = $body.Substring(0,$start) + "if (Test-Path -LiteralPath `$MemProcFS) {`n" + $body.Substring($end)
# Forensic mode 1 uses an in-memory database. The vendor assumes mode 4
# and attempts Copy-Item even when database.txt supplies no disk path.
$databaseCopy = 'Copy-Item -Path "$DatabasePath" -Destination "$OUTPUT_FOLDER\database\vmm.sqlite3"'
if ([regex]::Matches($body, [regex]::Escape($databaseCopy)).Count -ne 1) {
 throw 'Unsupported Analyzer layout: SQLite export adapter needs updating.'
}
$safeDatabaseCopy = @'
if ([string]::IsNullOrWhiteSpace($DatabasePath)) {
    Write-Output '[Info] SQLite export skipped: MemProcFS supplied no disk database path (forensic mode 1 uses memory). Other exported results are retained.'
} else {
    Copy-Item -LiteralPath $DatabasePath -Destination "$OUTPUT_FOLDER\database\vmm.sqlite3"
}
'@
$body = $body.Replace($databaseCopy, $safeDatabaseCopy)
# Current MemProcFS omits obj; the vendor reads it but excludes it from
# the exported process table. Remove the unused access, not other errors.
$body = $body.Replace('$obj = $_ | Select-Object -ExpandProperty obj', '$obj = $null # Optional unused legacy field')
$adapted = [scriptblock]::Create($body)
if ($ValidateOnly) { Write-Output 'Analyzer mounted adapter parses successfully.'; exit 0 }
# Preserve the vendor declarations and analysis functions, without its GUI,
# independent mount lifecycle, archive deletion, or system-setting helpers.
$declarations = $source.Substring(0, $header.Extent.StartOffset)
$declarations = $declarations.Replace('$PSScriptRoot', '$env:MEMFORENSICS_ANALYZER_ROOT')
$env:MEMFORENSICS_ANALYZER_ROOT = Split-Path -Parent $AnalyzerScript
. ([scriptblock]::Create($declarations))
foreach ($fn in $functions) {
 if ($fn.Name -in @('Header','Show-UserInterface','Footer','MemProcFS')) { continue }
 . ([scriptblock]::Create($fn.Extent.Text))
}
. $adapted
function python {
    & $env:MEMFORENSICS_ANALYZER_PYTHON @args
    if ($LASTEXITCODE -ne 0) { throw "Analyzer Python command failed (exit $LASTEXITCODE). See Zircolite/Screenlog.txt; zero detections must not be inferred from this failure." }
}
$script:MemProcFS = $MemProcFSPath
$script:MemoryDump = $ImagePath
$script:DriveLetter = $MountRoot.TrimEnd('\')
$script:OUTPUT_FOLDER = $OutputRoot
$script:FileName = [IO.Path]::GetFileNameWithoutExtension($ImagePath)
$script:OfflineMode = 'Enabled'
$script:StartTime_Processing = Get-Date
$script:StartTime_Analysis = Get-Date
if (!(Test-Path -LiteralPath $MemProcFS) -or !(Test-Path -LiteralPath "$DriveLetter\forensic")) { throw 'Configured MemProcFS executable or live forensic mount is unavailable.' }
New-Item -ItemType Directory -Path $OUTPUT_FOLDER -Force | Out-Null
Import-Module ImportExcel -ErrorAction Stop
Start-Transcript -Path (Join-Path $OUTPUT_FOLDER 'Analyzer-transcript.txt') -Force
try {
 if (!(Test-Path -LiteralPath $env:MEMFORENSICS_ANALYZER_PYTHON)) { throw 'Zircolite Python environment is missing. Run Install / update tools.' }
 python "$SCRIPT_DIR\Tools\Zircolite\zircolite.py" --help | Out-Null
 if (!(Test-Path -LiteralPath "$SCRIPT_DIR\Tools\Zircolite\rules\rules_windows_generic.json")) { throw 'Zircolite Windows Sigma ruleset is missing.' }
 Write-Output '[Info] Sigma engine verified. Scanning uses installed rules; only automatic rule downloads are disabled during analysis.'
 $Error.Clear()
 # Vendor functions handle optional-tool availability themselves.
 $ErrorActionPreference = 'Continue'
 MemProcFS
 Documents
 DFIRBatch
 ImageMount
 Modules
 if ($Error.Count) {
     $recordedErrors = @($Error)
     $errorPath = Join-Path $OUTPUT_FOLDER 'Analyzer-errors.txt'
     $recordedErrors | ForEach-Object { $_ | Format-List * -Force | Out-String } | Set-Content -LiteralPath $errorPath
     $recordedErrors | Group-Object FullyQualifiedErrorId | Select-Object -First 8 | ForEach-Object {
         Write-Output "[Error] $($_.Name): $($_.Group[0].Exception.Message)"
     }
     throw "Analyzer recorded $($recordedErrors.Count) recent errors. Details: $errorPath"
 }
 Write-Output 'MEMFORENSICS_ANALYZER_COMPLETE'
} finally { Stop-Transcript }
