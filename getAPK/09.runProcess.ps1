# Limpia la consola
Clear-Host

function Execute-Script {
    param (
        [string]$scriptPath
    )
    
    # Ejecuta el script y captura la salida
    $result = Invoke-Command -ScriptBlock {
        . $scriptPath
    }

    # Verifica el resultado
    if ($result -eq "Success") {
        Write-Host "Proceso exitoso para: $(Split-Path $scriptPath -Leaf)"
        return $true
    } else {
        Write-Host "Hubo un error en: $(Split-Path $scriptPath -Leaf)"
        return $false
    }
}

# Lista de scripts a ejecutar
$scriptList = @(
    "$PSScriptRoot\03.gen.certs.ps1"
    ,"$PSScriptRoot\04.build.new.ps1"
    ,"$PSScriptRoot\05.firmar.nuevos.ps1"
    ,"$PSScriptRoot\06.install.nuevos.ps1"
)

# Ejecuta cada script y detente si alguno falla
foreach ($script in $scriptList) {
    $success = Execute-Script -scriptPath $script
    if (-not $success) {
        break
    }
}
