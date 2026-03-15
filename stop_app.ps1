$process = Get-NetTCPConnection -LocalPort 8000 -ErrorAction Ignore | Select-Object -ExpandProperty OwningProcess -First 1
if ($process) {
    Write-Host "Stopping process $process on port 8000..."
    Stop-Process -Id $process -Force
    Write-Host "Application stopped."
} else {
    Write-Host "No application found running on port 8000."
}
