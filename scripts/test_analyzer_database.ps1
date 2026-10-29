$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../internal/analyzer/mounted.ps1') -Raw
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
$assignment = $ast.Find({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$safeDatabaseCopy'}, $true)
. ([scriptblock]::Create($assignment.Extent.Text))
$copy = [scriptblock]::Create($safeDatabaseCopy)
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('memforensics-db-test-' + [guid]::NewGuid())
$OUTPUT_FOLDER = Join-Path $testRoot 'output'
New-Item -ItemType Directory -Path "$OUTPUT_FOLDER/database" -Force | Out-Null
$DatabasePath = ''
$message = & $copy
if ($message -notmatch 'SQLite export skipped') { throw 'Empty database path was not reported as skipped' }
if (Test-Path "$OUTPUT_FOLDER/database/vmm.sqlite3") { throw 'Empty source created an output file' }
$DatabasePath = Join-Path $testRoot 'database [sample].sqlite3'
[IO.File]::WriteAllText($DatabasePath, 'test database content')
& $copy
if ([IO.File]::ReadAllText("$OUTPUT_FOLDER/database/vmm.sqlite3") -ne 'test database content') { throw 'Disk database copy failed' }
Write-Output "PASS: empty path skipped; literal disk path copied. Test artifacts: $testRoot"
