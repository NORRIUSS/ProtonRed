# ProtonRed wrapper around Invoke-AtomicTest. Runs ON THE TARGET.
#
# ProtonRed prepends one line before this script:
#   $ParamsB64 = '<base64 of a UTF-8 JSON object>'
# JSON keys: modules_dir, logger_path, atomics_dir, technique, test_guid,
#            test_number, input_args, timeout, check_prereqs, get_prereqs,
#            run_test, run_cleanup
#
# The last output line is always:
#   PROTONRED_RESULT:<base64 of a UTF-8 JSON object>
# { prereq: {met, reasons[], output} | null,
#   test:   <one ProtonRed-ExecutionLogger entry> | null,
#   cleanup:{ran, output} | null,
#   output: <Invoke-AtomicTest console text for the test run>,
#   error:  <exception message> | null }

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue } catch { }

$result = [ordered]@{ prereq = $null; test = $null; cleanup = $null; output = ''; error = $null }

function ConvertTo-PRText($records) {
    # Write-Host lands in the information stream; *>&1 merges every stream.
    (@($records) | ForEach-Object { "$_" }) -join "`n"
}

try {
    $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ParamsB64)) | ConvertFrom-Json

    # powershell-yaml (RequiredModules of Invoke-AtomicRedTeam) is resolved via PSModulePath.
    $env:PSModulePath = $p.modules_dir + [IO.Path]::PathSeparator + $env:PSModulePath
    Import-Module (Join-Path (Join-Path $p.modules_dir 'Invoke-AtomicRedTeam') 'Invoke-AtomicRedTeam.psd1') -Force -ErrorAction Stop
    Import-Module $p.logger_path -Force -ErrorAction Stop

    $common = @{
        AtomicTechnique            = [string]$p.technique
        PathToAtomicsFolder        = [string]$p.atomics_dir
        TimeoutSeconds             = [int]$p.timeout
        SupressPathToAtomicsFolder = $true
    }
    if ($p.test_guid) { $common.TestGuids = @([string]$p.test_guid) }
    else { $common.TestNumbers = @([string]$p.test_number) }

    if ($null -ne $p.input_args) {
        $ia = @{}
        foreach ($prop in $p.input_args.PSObject.Properties) { $ia[$prop.Name] = [string]$prop.Value }
        if ($ia.Count -gt 0) { $common.InputArgs = $ia }
    }

    $prereqOk = $true
    if ($p.check_prereqs) {
        $txt = ConvertTo-PRText (Invoke-AtomicTest @common -CheckPrereqs -NoExecutionLog *>&1)
        if ($p.get_prereqs -and $txt -match 'Prerequisites not met') {
            $null = Invoke-AtomicTest @common -GetPrereqs -NoExecutionLog *>&1
            $txt = ConvertTo-PRText (Invoke-AtomicTest @common -CheckPrereqs -NoExecutionLog *>&1)
        }
        $prereqOk = $txt -notmatch 'Prerequisites not met'
        $reasons = @([regex]::Matches($txt, '\[\*\]\s*([^\r\n\t]+)') | ForEach-Object { $_.Groups[1].Value.Trim() } | Where-Object { $_ })
        $result.prereq = [ordered]@{ met = $prereqOk; reasons = $reasons; output = $txt }
    }

    if ($p.run_test -and $prereqOk) {
        $log = Join-Path ([IO.Path]::GetTempPath()) ('protonred-' + [guid]::NewGuid().ToString('N') + '.jsonl')
        $result.output = ConvertTo-PRText (Invoke-AtomicTest @common -ExecutionLogPath $log -LoggingModule 'ProtonRed-ExecutionLogger' *>&1)
        if (Test-Path -LiteralPath $log) {
            $lines = @(Get-Content -LiteralPath $log -Encoding UTF8 | Where-Object { $_.Trim() })
            if ($lines.Count -gt 0) { $result.test = $lines[-1] | ConvertFrom-Json }
            Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
        }
    }

    # Cleanup also runs after a failed test (it may have half-applied changes),
    # but not when prerequisites stopped the test from running at all.
    if ($p.run_cleanup -and $prereqOk) {
        $txt = ConvertTo-PRText (Invoke-AtomicTest @common -Cleanup -NoExecutionLog *>&1)
        $result.cleanup = [ordered]@{ ran = $true; output = $txt }
    }
}
catch {
    $result.error = $_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 6 -Compress
'PROTONRED_RESULT:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
