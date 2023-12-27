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

def check_app_running(device_id, process_name):
    try:
        print("> Verificando si la aplicación está en ejecución...")
        device = frida.get_device(device_id, timeout=10)
        device.attach(process_name)
        print(f"> La aplicación '{process_name}' está en ejecución.")
        return True
    except frida.ProcessNotFoundError:
        print(f"> No se pudo encontrar el proceso para '{process_name}'. Asegúrate de que la aplicación está instalada y en ejecución.")
        return False
    except frida.ServerNotRunningError:
        print(f"> El servidor de Frida no se está ejecutando en '{device_id}'.")
        return False
    except Exception as e:
        print(f"> Error inesperado: {e}")
        return False

def list_app_events(device_id, process_name, jscode):
    try:
        print("> Adjuntando script a la aplicación...")
        device = frida.get_device(device_id, timeout=10)
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

    if check_app_running(device_id, process_name):
        script_xxxxzxxx = """
            Java.perform(function () {
                var MainActivity = Java.use('""" + package_name + "." + main_activity + """');
                var methods = MainActivity.class.getDeclaredMethods();
                methods.forEach(function (method) {
                    var methodName = method.getName();
                    send('Método encontrado: ' + methodName);
                    // Aquí podrías agregar enganches a métodos específicos
                });
            });
        """
        list_app_events(device_id, process_name, script_xxxxzxxx)

if __name__ == "__main__":
    main()