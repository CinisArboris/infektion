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

def modify_method_return_value(device_id, process_name, full_activity_name, method_name):
    jscode = f"""
        Java.perform(function () {
            var MainActivity = Java.use('{full_activity_name}');
            var method = MainActivity['{method_name}'];
            if (method) {
                var overloads = method.overloads;
                overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        send('Método {method_name} llamado. Forzando retorno a true.');
                        return true;  // Forzar el valor de retorno a true
                    };
                });
            }
        });
    """

    try:
        print(f"> Forzando el valor de retorno del método '{method_name}' a 'true'...")
        device = frida.get_device(device_id, timeout=2)
        session = device.attach(process_name)
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        print(f"> Script cargado. Modificando método '{method_name}'...")
        input("[*] Presiona enter para detener el script...")
    except Exception as e:
        print(f"> Error: {e}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    config = load_config('configMe.json')
    device_id = config['device_id']
    process_name = config['process_name']
    package_name = config['package_name']
    main_activity = config['main_activity']
    method_name = config['method_name']
    full_activity_name = f"{package_name}.{main_activity}"

    modify_method_return_value(device_id, process_name, full_activity_name, method_name)

if __name__ == "__main__":
    main()
