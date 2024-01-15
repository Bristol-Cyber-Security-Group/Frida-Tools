"""
python intercept.py <process> <outdir>

Example usage:
python intercept.py signal ./logs/signal
python intercept.py telegram ./logs/telegram
"""

import os
import datetime
import sys
from pathlib import Path
import frida

from process_data import process_data

try:
    PROCESS_NAME = sys.argv[1]
    outdir = sys.argv[2]
except:
    print("Usage: 'python intercept.py <packagename> <outdir>'")
    sys.exit(1)


processes = {
    'signal': 'org.thoughtcrime.securesms',
    'whatsapp': 'com.whatsapp',
    'messenger': 'com.facebook.orca',
    'telegram': 'org.telegram.messenger.web',
    'wire': 'com.wire',
    'element': 'im.vector.app',
    'viber': 'com.viber.voip'
}

log_folder = f"{outdir}/TLSintercept"
os.makedirs(log_folder)

if PROCESS_NAME in processes.keys():
    PROCESS_NAME = processes[PROCESS_NAME]

log_file_name = 'timeline.log'
log_file = f"{log_folder}/{log_file_name}"
with open(log_file, 'w') as file:
    file.write(f'{PROCESS_NAME}, \n')

device = frida.get_usb_device()
pid = device.spawn([PROCESS_NAME])
session = device.attach(pid)

script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'script.js')
with open(script_path) as f:
    script = session.create_script(f.read())

def decode(bytes):
    print("=" * 100)
    print(f"{len(bytes)} bytes")
    s = ""
    for byte in bytes:
        s += chr(byte)
    print(s)
    print("=" * 100)

def write_log(message, time=None):
    if not time:
        time = datetime.datetime.now().isoformat()
    with open(log_file, 'a') as file:
        file.write('-' * 120 + '\n' + time + '\n' + message + '\n')


file_counters = {}

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload['TYPE'] == 'data':
            info, processed_data = process_data(data)
            if processed_data:
                # Create a unique file
                base_filename = f"{payload['STREAM_ID']}-{payload['DIRECTION']}"
                
                counter = file_counters.get(base_filename, 1)
                filename = f"{log_folder}/{base_filename}_{counter}.txt"

                while Path(filename).exists():
                    counter += 1
                    filename = f"{log_folder}/{base_filename}_{counter}.txt"

                file_counters[base_filename] = counter + 1

                with open(filename, 'w+') as file:
                    file.write(str(info['DATA_ALERTS']) + "\n")
                    file.write(str(processed_data))
            
            write_log(str({**payload, **info}))

    elif message['type'] == 'error':
        write_log(message['stack'])
    else:
        write_log(str(message))

script.on('message', on_message)

script.load()
device.resume(pid)

# UNCOMMENT THIS IF YOU WANT USER INPUT TO EXIT SCRIPT
# print("Script loaded, press any key to exit:")

# try:
#     input()
# except KeyboardInterrupt:
#     pass
# print('Exiting...')

# Prevent script from terminating immediately
import time
time.sleep(10)
sys.exit(0)