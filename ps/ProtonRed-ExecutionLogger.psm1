# ProtonRed execution logger for Invoke-AtomicRedTeam.
#
# Invoke-AtomicTest loads loggers by module name:
#   Invoke-AtomicTest T1082 -LoggingModule ProtonRed-ExecutionLogger -ExecutionLogPath <file>
# and calls Start-/Write-/Stop-ExecutionLog. Write-ExecutionLog runs once per
# executed test and receives the raw process result ($res: StandardOutput,
# ErrorOutput, ExitCode, IsTimeOut). We append one JSON object per line so
# ProtonRed gets exactly what ran, unparsed and untruncated.
#
# Note: Invoke-AtomicTest only calls loggers for test execution, not for
# -CheckPrereqs / -GetPrereqs / -Cleanup.

function Start-ExecutionLog($startTime, $logPath, $targetHostname, $targetUser, $commandLine, $isWindows) {
    if (Test-Path -LiteralPath $logPath) {
        Remove-Item -LiteralPath $logPath -Force
    }
}

function Write-ExecutionLog($startTime, $stopTime, $technique, $testNum, $testName, $testGuid, $testExecutor, $testDescription, $command, $logPath, $targetHostname, $targetUser, $res, $isWindows) {
    $exitCode = $null
    $stdout = ''
    $stderr = ''
    $isTimeout = $false
    if ($res -is [int]) {
        # Invoke-ExecuteCommand returns a bare 0 when the test has no command.
        $exitCode = $res
    }
    elseif ($null -ne $res) {
        $exitCode = $res.ExitCode
        $stdout = [string]$res.StandardOutput
        $stderr = [string]$res.ErrorOutput
        $isTimeout = [bool]$res.IsTimeOut
    }

    $entry = [ordered]@{
        technique   = [string]$technique
        test_number = $testNum
        test_name   = [string]$testName
        test_guid   = [string]$testGuid
        executor    = [string]$testExecutor
        command     = [string]$command
        exit_code   = $exitCode
        is_timeout  = $isTimeout
        stdout      = $stdout
        stderr      = $stderr
        start_time  = $startTime.ToUniversalTime().ToString('o')
        stop_time   = $stopTime.ToUniversalTime().ToString('o')
        hostname    = [string]$targetHostname
        user        = [string]$targetUser
    }
    Add-Content -LiteralPath $logPath -Value ($entry | ConvertTo-Json -Depth 4 -Compress) -Encoding UTF8
}

function Stop-ExecutionLog($startTime, $logPath, $targetHostname, $targetUser, $isWindows) {
}

Export-ModuleMember -Function Start-ExecutionLog, Write-ExecutionLog, Stop-ExecutionLog
