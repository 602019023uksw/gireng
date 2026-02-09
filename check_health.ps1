try {
    $h = Invoke-RestMethod -Uri http://localhost:8080/health -TimeoutSec 5
    Write-Host "HEALTH_OK: $($h | ConvertTo-Json -Compress)"
} catch {
    Write-Host "HEALTH_FAIL: $($_.Exception.Message)"
}

try {
    $s = Invoke-RestMethod -Uri http://localhost:8080/status/bb1641c0-9fa2-43c0-a8d0-cf25f00a6ad6 -TimeoutSec 5
    Write-Host "SESSION_STATUS: $($s.status)"
    Write-Host "SESSION_HASH: $($s.state.program_hash)"
} catch {
    Write-Host "SESSION_NOT_FOUND: $($_.Exception.Message)"
}
