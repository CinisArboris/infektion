# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta de destino
$destinationDir = $config.apk_destination_path

# Obtener ID del dispositivo
$device_id = $config.device_id

# Construir el comando adb para instalar múltiples APKs
$apkFiles = $config.apk_files | ForEach-Object { Join-Path $destinationDir $_ }
$installCommand = "adb -s $device_id install-multiple " + ($apkFiles -join " ")

# Ejecutar el comando de instalación
try {
    Invoke-Expression $installCommand
    Write-Host "Comando de instalación ejecutado con éxito."
} catch {
    Write-Host "Error al ejecutar el comando de instalación."
}

# Verifica si los archivos APK se instalaron correctamente
# Esta parte puede ser desafiante ya que 'adb install-multiple' no ofrece una manera directa de verificar la instalación.
# Podrías listar las aplicaciones instaladas y verificar si tu aplicación está allí, pero eso depende de tus necesidades específicas.
