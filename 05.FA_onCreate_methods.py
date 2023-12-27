import frida
import sys
import os
import json
import time

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

def load_config(config_file):
    with open(config_file, 'r', encoding='utf-8') as file:
        return json.load(file)

def generate_analysis_scripts(method_names):
    analysis_scripts = ""
    for name in method_names:
        analysis_script = """
            var method = MainActivity['%s'];
            if (method) {
                var overloads = method.overloads;
                overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var args = Array.prototype.slice.call(arguments);
                        send('Método %s llamado. Argumentos: ' + JSON.stringify(args));
                        var returnValue = this['%s'].apply(this, arguments);
                        send('Valor de retorno de %s: ' + returnValue);
                        return returnValue;
                    };
                });
            }
        """ % (name, name, name, name)
        analysis_scripts += analysis_script
    return analysis_scripts

def analyze_specific_methods(device_id, process_name, package_name, main_activity, method_names):
    full_activity_name = package_name + "." + main_activity
    analysis_scripts = generate_analysis_scripts(method_names)

    jscode = """
        Java.perform(function () {
            var MainActivity = Java.use('%s');
            %s
        });
    """ % (full_activity_name, analysis_scripts)

    try:
        print("> Conectando al dispositivo...")
        device = frida.get_device(device_id, timeout=2)

        print("> Adjuntando a la aplicación en ejecución...")
        session = device.attach(process_name)

        print("> Cargando el script de análisis...")
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()

        print("> Script cargado. Analizando métodos...")
        input("[*] Presiona enter para detener el script...")
    except Exception as e:
        print(f"> Error: {e}")
        print(f"> Tipo de error: {type(e).__name__}")
        print(f"> Detalles del error: {e.args}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    config = load_config('configMe.json')
    device_id = config['device_id']
    process_name = config['process_name']
    package_name = config['package_name']
    main_activity = config['main_activity']
    method_names = ['Q0', 'd1', 'Y0']

    print("Asegúrate de que la aplicación está en ejecución antes de continuar.")
    input("Presiona Enter después de que la aplicación esté en ejecución para iniciar el análisis.")

    analyze_specific_methods(device_id, process_name, package_name, main_activity, method_names)

if __name__ == "__main__":
    main()