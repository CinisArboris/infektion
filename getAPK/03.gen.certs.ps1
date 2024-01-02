# Limpia la consola
Clear-Host

# Carga la configuración desde configMe.json
$configFilePath = Join-Path $PSScriptRoot "..\configMe.json"
$config = Get-Content $configFilePath | ConvertFrom-Json

# Define la ruta y el nombre del keystore
$keystoreDir = $config.keystore_dir
$keystorePath = Join-Path $keystoreDir $config.keystore_name

# Información del keystore desde la configuración
$keystoreAlias = $config.keystore_alias
$keystorePass = $config.keystore_pass
$keyAlg = $config.key_alg
$keySize = $config.key_size
$validity = $config.validity

# Crear el directorio si no existe
if (-not (Test-Path -Path $keystoreDir)) {
    New-Item -ItemType Directory -Path $keystoreDir
}

# Comando para generar el keystore
$keytoolCommand = "keytool -genkey -v -keystore `"$keystorePath`" -alias `"$keystoreAlias`" -keyalg `"$keyAlg`" -keysize $keySize -validity $validity -storepass `"$keystorePass`" -keypass `"$keystorePass`" -dname `"CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, S=Unknown, C=Unknown`""

# Ejecutar el comando
try {
    Invoke-Expression $keytoolCommand
    Write-Host "Keystore creado con éxito en: $keystorePath"
} catch {
    Write-Host "Error al crear el keystore."
}
