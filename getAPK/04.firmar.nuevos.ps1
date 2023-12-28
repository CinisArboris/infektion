# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta del directorio de APKs editados
$editedApkDir = $config.edited_apk_dir

# Información del keystore
$keystorePath = "#"
$keystoreAlias = "#"
$keystorePass = "#"

# Firma cada APK en el directorio de APKs editados
foreach ($apkFile in $config.apk_files) {
    $apkPath = Join-Path $editedApkDir $apkFile

    # Comando para firmar el APK con apksigner
    $apksignerCommand = "apksigner sign --ks `"$keystorePath`" --ks-pass pass:$keystorePass --key-pass pass:$keystorePass --out `"$apkPath`" `"$apkPath`""

    # Ejecutar el comando de firma
    try {
        Invoke-Expression $apksignerCommand
        Write-Host "APK firmado con éxito: $apkFile"
    } catch {
        Write-Host "Error al firmar el APK: $apkFile"
    }
}

# Verificar la firma de un APK como ejemplo
$verifyCommand = "apksigner verify --verbose `"$editedApkDir\base.apk`""
try {
    Invoke-Expression $verifyCommand
    Write-Host "La firma del APK base ha sido verificada."
} catch {
    Write-Host "Error al verificar la firma del APK base."
}
