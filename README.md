# badusb

Start-Process "msedge.exe" "--kiosk https://c.tenor.com/x8v1oNUOmg4AAAAd/tenor.gif --edge-kiosk-type=fullscreen"

1..2 | ForEach-Object { $done = New-Object -ComObject Wscript.Shell; $msg = if ($_ -eq 1) {"First Message"} else {"Second Message"}; $done.Popup($msg, 0, "Status", 0x1) }



$bufferSize = $Host.UI.RawUI.BufferSize
$bufferSize.Width = 125
$bufferSize.Height = 20
$Host.UI.RawUI.BufferSize = $bufferSize

$windowSize = $Host.UI.RawUI.WindowSize
$windowSize.Width = 125
$windowSize.Height = 20
$Host.UI.RawUI.WindowSize = $windowSize

$filePath = "ruta\al\archivo.txt"
$lines = Get-Content $filePath

foreach ($line in $lines) {
    Write-Host $line
    Start-Sleep -Milliseconds 500 # Ajusta este valor para controlar la velocidad del "scroll"
}

# Esperar a que el usuario presione una tecla antes de cerrar la consola
Write-Host "Presiona cualquier tecla para continuar ..." -ForegroundColor Yellow
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
