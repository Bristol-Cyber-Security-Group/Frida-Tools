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
import csv
import frida

from process_data import process_data

# Create csv file for storing intercepted messages
def create_csv_file(file_path):
    headers = ["MESSAGE_ID", "TIMESTAMP", "MESSAGE"]
    if not Path(file_path).exists():
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
    else:
        print("Messages csv already exists at this location, exiting.")
        sys.exit(1)

try:
    PROCESS_NAME = sys.argv[1]
    outdir = sys.argv[2]
except:
    print("Usage: 'python intercept.py <packagename> <outdir>'")
    sys.exit(1)

# Create log path and initiate timeline.log and csv file
log_folder = f"{outdir}/TLSintercept"
os.makedirs(log_folder)
log_file_name = 'timeline.log'
log_file = f"{log_folder}/{log_file_name}"
with open(log_file, 'w') as file:
    file.write(f'{PROCESS_NAME}, \n')
csv_path = f"{outdir}/messages.csv"
create_csv_file(csv_path)


# Connect to process with Frida and start js script
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


ids = {'message_id': 1}

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload['TYPE'] == 'data':
            info, processed_data = process_data(data)
            if processed_data:
                timestamp = datetime.datetime.now().isoformat()
                record = [ids['message_id'], timestamp, str(processed_data)]
                with open(csv_path, 'a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(record)

                ids['message_id'] += 1
            
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