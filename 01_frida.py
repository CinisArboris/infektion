import frida

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

try:
    session = frida.attach("notepad++.exe")

    script_code = """
        rpc.exports.enumerateModules = function () {
            return Process.enumerateModules();
        };
    """
    script = session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    modules = script.exports_sync.enumerate_modules()
    
    # Imprimiendo cada módulo en una nueva línea
    for module in modules:
        print(module["name"])

except frida.ProcessNotFoundError:
    print("Error: No se pudo encontrar el proceso 'notepad++.exe'. Asegúrate de que el proceso esté en ejecución.")
except frida.PermissionDeniedError:
    print("Error: Permiso denegado. Es posible que necesites privilegios de administrador para adjuntarte a este proceso.")
except Exception as e:
    print(f"Error inesperado: {e}")
