import frida
import sys
import os
import json

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

def load_config(config_file):
    with open(config_file, 'r', encoding='utf-8') as file:
        return json.load(file)

def generate_string_search_script(package_name, main_activity):
    full_activity_name = package_name + '.' + main_activity
    return f"""
        Java.perform(function () {{
            var MainActivity = Java.use('{full_activity_name}');
            var methods = MainActivity.class.getDeclaredMethods();
            methods.forEach(function (method) {{
                var methodName = method.getName();
                send('Método encontrado: ' + methodName);
                interceptStringManipulation(methodName);
            }});
        }});

        function interceptStringManipulation(methodName) {{
            var MainActivity = Java.use('{full_activity_name}');
            var method = MainActivity[methodName];
            if (method) {{
                var overloads = method.overloads;
                overloads.forEach(function(overload) {{
                    overload.implementation = function() {{
                        var args = Array.prototype.slice.call(arguments);
                        send('Método ' + methodName + ' llamado. Argumentos: ' + JSON.stringify(args));
                        var returnValue = this[methodName].apply(this, arguments);
                        if (typeof returnValue === 'string' && returnValue.includes('Bienvenido(a)')) {{
                            returnValue = returnValue.replace('Bienvenido(a)', 'hola hola hola');
                            send('Cadena modificada en valor de retorno: ' + returnValue);
                        }}
                        return returnValue;
                    }};
                }});
            }}
        }}
    """

def analyze_string_usage(device_id, process_name, package_name, main_activity):
    jscode = generate_string_search_script(package_name, main_activity)

    try:
        print("> Conectando al dispositivo...")
        device = frida.get_device(device_id, timeout=2)

        print("> Adjuntando a la aplicación en ejecución...")
        session = device.attach(process_name)

        print("> Cargando el script de análisis...")
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()

        print("> Script cargado. Buscando uso de la cadena específica...")
        input("[*] Presiona enter para detener el script...")
    except Exception as e:
        print(f"> Error: {e}")
        print(f"> Tipo de error: {type(e).__name__}")
        print(f"> Detalles del error: {e.args}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    config = load_config('../configMe.json')
    device_id = config['device_id']
    process_name = config['process_name']
    package_name = config['package_name']
    main_activity = config['main_activity']

    print("Asegúrate de que la aplicación está en ejecución antes de continuar.")
    input("Presiona Enter después de que la aplicación esté en ejecución para iniciar el análisis.")

    analyze_string_usage(device_id, process_name, package_name, main_activity)

if __name__ == "__main__":
    main()
