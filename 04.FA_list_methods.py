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

def list_app_events(device_id, process_name, package_name, main_activity):
    full_activity_name = package_name + "." + main_activity
    jscode = """
        Java.perform(function () {
            var MainActivity = Java.use('""" + full_activity_name + """');
            var methods = MainActivity.class.getDeclaredMethods();
            methods.forEach(function (method) {
                var methodName = method.getName();
                send('Método encontrado: ' + methodName);
                // Aquí podrías agregar enganches a métodos específicos
            });
        });
    """
    try:
        print("> Adjuntando script a la aplicación...")
        device = frida.get_device(device_id, timeout=2)
        session = device.attach(process_name)
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        print("> Script cargado. Monitoreando eventos...")
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
    list_app_events(device_id, process_name, package_name, main_activity)

if __name__ == "__main__":
    main()
