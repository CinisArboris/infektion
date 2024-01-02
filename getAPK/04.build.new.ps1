# 04.build.new.ps1

# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta del directorio del código fuente a recompilar
$sourceCodeDir = $config.edited_apk_dir

# Define la ruta completa del archivo APK de salida, incluyendo el nombre del archivo
$rebuiltApkFullPath = Join-Path $config.rebuilt_apk_dir $config.rebuilt_apk_name

# Verifica si el directorio del código fuente existe
if (-not (Test-Path $sourceCodeDir)) {
    Write-Host "El directorio del código fuente a recompilar no existe: $sourceCodeDir"
    exit
}

# Construye el comando para apktool.jar
$apkToolCommand = "apktool.jar b `"$sourceCodeDir`" -o `"$rebuiltApkFullPath`""

# Ejecuta el comando con manejo de errores
try {
    Invoke-Expression $apkToolCommand
    if (Test-Path $rebuiltApkFullPath) {
        Write-Host "APK construido exitosamente y disponible en: $rebuiltApkFullPath"
    } else {
        Write-Host "El APK reconstruido no se encuentra en la ruta esperada."
        exit
    }
} catch {
    Write-Host "Error al construir el APK. Asegúrate de que apktool está instalado y accesible desde tu PATH."
    exit
}
