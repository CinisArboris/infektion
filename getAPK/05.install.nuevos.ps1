# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta de los APKs modificados
$editedApkDir = "#"

# Obtener ID del dispositivo
$device_id = $config.device_id

# Construir el comando adb para instalar múltiples APKs
$apkFiles = Get-ChildItem $editedApkDir -Filter *.apk | ForEach-Object { $_.FullName }
$installCommand = "adb -s $device_id install-multiple " + ($apkFiles -join " ")

# Ejecutar el comando de instalación
try {
    Invoke-Expression $installCommand
    Write-Host "Comando de instalación ejecutado con éxito."
} catch {
    Write-Host "Error al ejecutar el comando de instalación: $_"
}

# Opcional: Verificación de la instalación
# Aquí puedes añadir código para verificar si la instalación fue exitosa.
