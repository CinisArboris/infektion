# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta de destino
$destinationDir = $config.apk_destination_path

# Obtener ID del dispositivo
$device_id = $config.device_id

# Verifica si el dispositivo está conectado
try {
    $deviceList = adb devices
    if (-not ($deviceList -like "*$device_id*")) {
        Write-Host "Dispositivo $device_id no encontrado. Asegúrate de que esté conectado y en modo depuración."
        exit
    }
} catch {
    Write-Host "Error al intentar comunicarse con adb. Asegúrate de que adb esté instalado y configurado correctamente."
    exit
}

# Obtener las rutas de los archivos APK en el dispositivo
$apkBasePath = $config.apk_base_path

# Construir comandos adb para extraer los archivos APK
$adbCommands = $config.apk_files | ForEach-Object {
    $remotePath = $apkBasePath + $_
    $localPath = Join-Path $destinationDir $_
    "adb -s $device_id pull $remotePath `"$localPath`""
}

# Ejecutar cada comando adb con manejo de errores
foreach ($command in $adbCommands) {
    try {
        Invoke-Expression $command
        Write-Host "Comando ejecutado con éxito: $command"
    } catch {
        Write-Host "Error al ejecutar el comando: $command"
    }
}

# Verificar si los archivos se extrajeron correctamente
$apkFiles = Get-ChildItem $destinationDir -Filter *.apk
if ($apkFiles.Count -eq $config.apk_files.Count) {
    Write-Host "Archivos APK extraídos exitosamente."
} else {
    Write-Host "Hubo un problema al extraer algunos archivos APK."
}
