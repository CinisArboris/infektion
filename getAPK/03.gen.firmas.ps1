# Limpia la consola
Clear-Host

# Define la ruta donde se creará el keystore
$keystoreDir = "#"
$keystorePath = Join-Path $keystoreDir "#"

# Información del keystore
$keystoreAlias = "#"
$keystorePass = "#"
$keyAlg = "RSA"
$keySize = 2048
$validity = 10000 # Número de días de validez

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
