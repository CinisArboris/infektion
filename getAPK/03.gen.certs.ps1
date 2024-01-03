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

# Comando para verificar si el alias ya existe en el keystore
$checkAliasCommand = "keytool -list -keystore `"$keystorePath`" -alias `"$keystoreAlias`" -storepass `"$keystorePass`""

# Comando para eliminar el alias si ya existe
$deleteAliasCommand = "keytool -delete -alias `"$keystoreAlias`" -keystore `"$keystorePath`" -storepass `"$keystorePass`""

# Comando para generar el keystore
$keytoolCommand = "keytool -genkey -v -keystore `"$keystorePath`" -alias `"$keystoreAlias`" -keyalg `"$keyAlg`" -keysize $keySize -validity $validity -storepass `"$keystorePass`" -keypass `"$keystorePass`" -dname `"CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, S=Unknown, C=Unknown`""

try {
    # Suprimir salida detallada de los comandos keytool
    $null = Invoke-Expression $checkAliasCommand 2>&1
    $null = Invoke-Expression $deleteAliasCommand 2>&1
    $null = Invoke-Expression $keytoolCommand 2>&1

    Write-Host "Keystore creado con éxito en: $keystorePath"
    return "Success"
} catch {
    Write-Host "Error durante la creación del keystore."
    return "Error"
}
