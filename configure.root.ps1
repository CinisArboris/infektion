# Definición de variables
$fridaServerPath = "../frida-server"
$devicePath = "/data/local/tmp/frida-server"
$deviceID = "emulator-5554"

# Reinicia adb como root
Write-Host "Reiniciando adb con privilegios de root..."
adb -s $deviceID root

# Detiene cualquier instancia existente del servidor de Frida
Write-Host "Deteniendo cualquier instancia existente de Frida Server..."
$fridaPids = adb -s $deviceID shell "ps | grep frida-server | awk '{print `$2}'" | Out-String -Stream | Where-Object { $_ -match '\d+' }
foreach ($fridaPid in $fridaPids) {
    if ($fridaPid -ne $null) {
        Write-Host "Matando proceso con PID: $fridaPid"
        adb -s $deviceID shell "kill $fridaPid"
    }
}

# Sube el servidor de Frida al dispositivo
Write-Host "Subiendo Frida Server al dispositivo..."
adb -s $deviceID push $fridaServerPath $devicePath

# Cambia los permisos para hacerlo ejecutable
Write-Host "Configurando permisos de Frida Server..."
adb -s $deviceID shell "chmod 755 $devicePath"

# Ejecuta el servidor de Frida en el dispositivo
Write-Host "Iniciando Frida Server..."
adb -s $deviceID shell "nohup $devicePath > /dev/null 2>&1 &"

Write-Host "Frida Server reiniciado y en ejecución."
