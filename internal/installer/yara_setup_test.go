package installer

import (
	"os/exec"
	"testing"
)

func TestYaraWindowsReleaseSelection(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	// Exercise the actual adapter function without executing installation.
	script := `$ErrorActionPreference = 'Stop'
$source = Get-Content analyzer_setup.ps1 -Raw
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Adapter syntax error' }
$fn=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Select-YaraWindowsAsset'},$true)
. ([scriptblock]::Create($fn[0].Extent.Text))
$asset=@{name='yara-4.5.5-2368-win64.zip'; browser_download_url='https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'}
$releases=@(@{tag_name='v4.5.8'; assets=@()}, @{tag_name='v5-rc'; prerelease=$true; assets=@($asset)}, @{tag_name='v4.5.5'; assets=@(@{name='yara-win32.zip'},$asset)})
$got=Select-YaraWindowsAsset $releases
if ($got.Tag -ne 'v4.5.5' -or $got.Url -ne $asset.browser_download_url) { throw 'Wrong archive selected' }
if ($null -ne (Select-YaraWindowsAsset @(@{assets=@()}))) { throw 'Empty release accepted' }
$failed=$false
try { Select-YaraWindowsAsset @(@{assets=@($asset,$asset)}) } catch { $failed=$true }
if (!$failed) { throw 'Ambiguous archive accepted' }
$asset.browser_download_url='invalid URL'
$failed=$false
try { Select-YaraWindowsAsset @(@{assets=@($asset)}) } catch { $failed=$true }
if (!$failed) { throw 'Invalid URL accepted' }
`
	if out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("YARA selection: %v\n%s", err, out)
	}
}
