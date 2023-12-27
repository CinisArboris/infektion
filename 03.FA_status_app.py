import frida
import sys
import os
import json

def load_config(config_file):
    with open(config_file, 'r', encoding='utf-8') as file:
        return json.load(file)

def check_app_running(device_id, process_name):
    try:
        print("> Verificando si la aplicación está en ejecución...")
        device = frida.get_device(device_id, timeout=2)
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

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    config = load_config('configMe.json')
    device_id = config['device_id']
    process_name = config['process_name']
    check_app_running(device_id, process_name)

if __name__ == "__main__":
    main()
