# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta del directorio de APKs reconstruidos
$rebuiltApkDir = $config.rebuilt_apk_dir

# Información del keystore desde la configuración
$keystorePath = Join-Path $config.keystore_dir $config.keystore_name
$keystoreAlias = $config.keystore_alias
$keystorePass = $config.keystore_pass

$allSignedSuccessfully = $true

# Firma y alinea cada APK en el directorio de APKs reconstruidos
foreach ($apkFile in $config.apk_files) {
    $apkPath = Join-Path $rebuiltApkDir $apkFile
    $tempAlignedApkPath = Join-Path $rebuiltApkDir ("temp_aligned_" + $apkFile)

    # Alinea el APK y guarda en un archivo temporal
    $zipAlignCommand = "zipalign -f -p 4 `"$apkPath`" `"$tempAlignedApkPath`""
    Invoke-Expression $zipAlignCommand

    # Reemplaza el archivo original con el archivo alineado
    Move-Item -Path $tempAlignedApkPath -Destination $apkPath -Force

    # Comando para firmar el APK con apksigner
    $apksignerCommand = "apksigner sign --ks `"$keystorePath`" --ks-key-alias `"$keystoreAlias`" --ks-pass pass:$keystorePass --key-pass pass:$keystorePass `"$apkPath`""

    # Ejecutar el comando de firma
    try {
        Invoke-Expression $apksignerCommand
        Write-Host "APK firmado y alineado con éxito: $apkFile"
    } catch {
        Write-Host "Error al firmar o alinear el APK: $apkFile"
        $allSignedSuccessfully = $false
    }
}

# Verificar la firma de un APK como ejemplo
if ($allSignedSuccessfully) {
    $verifyCommand = "apksigner verify --verbose `"$rebuiltApkDir\base.apk`""
    try {
        Invoke-Expression $verifyCommand
        Write-Host "La firma del APK base ha sido verificada."
        return "Success"
    } catch {
        Write-Host "Error al verificar la firma del APK base."
        return "Error"
    }
} else {
    return "Error"
}
