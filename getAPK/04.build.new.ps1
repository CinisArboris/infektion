# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta del directorio del código fuente a recompilar
$sourceCodeDir = $config.edited_apk_dir

# Define la ruta completa del archivo APK de salida, incluyendo el nombre del archivo
$rebuiltApkFullPath = Join-Path $config.rebuilt_apk_dir $config.rebuilt_apk_name

# Elimina el archivo APK existente en la ruta de destino si existe
if (Test-Path $rebuiltApkFullPath) {
    Remove-Item $rebuiltApkFullPath
}

# Verifica si el directorio del código fuente existe
if (-not (Test-Path $sourceCodeDir)) {
    Write-Host "El directorio del código fuente a recompilar no existe: $sourceCodeDir"
    return "Error"
}

# Construye el comando para apktool.jar
$apkToolCommand = "apktool.jar b `"$sourceCodeDir`" -o `"$rebuiltApkFullPath`""

# Ejecuta el comando con manejo de errores
try {
    Invoke-Expression $apkToolCommand
} catch {
    Write-Host "Error al construir el APK. Asegúrate de que apktool está instalado y accesible desde tu PATH."
    return "Error"
}

# Espera a que se cree el archivo APK y que su tamaño sea mayor a 5 MB
$waitTime = 0
while (-not (Test-Path $rebuiltApkFullPath) -or ((Get-Item $rebuiltApkFullPath).Length -lt 5MB)) {
    Start-Sleep -Seconds 5
    $waitTime += 5
    if ($waitTime -ge 120) {  # Puedes ajustar el tiempo máximo de espera según sea necesario
        Write-Host "Tiempo de espera excedido para la creación del APK o el archivo es demasiado pequeño."
        return "Error"
    }
}

Write-Host "APK construido exitosamente y disponible en: $rebuiltApkFullPath"
return "Success"
