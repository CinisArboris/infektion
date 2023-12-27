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

def analyze_specific_methods(device_id, process_name, package_name, main_activity, method_names):
    full_activity_name = package_name + "." + main_activity
    analysis_scripts = generate_analysis_scripts(method_names)

    jscode = f"""
        Java.perform(function () {
            var MainActivity = Java.use('{full_activity_name}');
            {analysis_scripts}
        });
    """

    try:
        print("> Analizando métodos específicos en: " + process_name)
        device = frida.get_device(device_id, timeout=2)
        session = device.attach(process_name)
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        print("> Script cargado. Analizando métodos...")
        input("[*] Presiona enter para detener el script...")
    except Exception as e:
        print(f"> Error: {e}")

def generate_analysis_scripts(method_names):
    analysis_scripts = ""
    for name in method_names:
        analysis_script = f"""
            var method = MainActivity['{name}'];
            if (method) {
                var overloads = method.overloads;
                overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var args = Array.prototype.slice.call(arguments);
                        send('Método {name} llamado. Argumentos: ' + JSON.stringify(args));
                        var returnValue = this['{name}'].apply(this, arguments);
                        send('Valor de retorno de {name}: ' + returnValue);
                        return returnValue;
                    };
                });
            }
        """
        analysis_scripts += analysis_script
    return analysis_scripts

def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    config = load_config('configMe.json')
    device_id = config['device_id']
    process_name = config['process_name']
    package_name = config['package_name']
    main_activity = config['main_activity']
    method_names = ['Q0', 'd1', 'Y0']

    analyze_specific_methods(device_id, process_name, package_name, main_activity, method_names)

if __name__ == "__main__":
    main()
