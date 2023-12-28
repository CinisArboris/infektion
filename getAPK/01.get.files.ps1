# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta de destino
$destinationDir = $config.apk_destination_path

# Obtener las rutas de los archivos APK en el dispositivo
$device_id = $config.device_id
$package_name = $config.package_name
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
