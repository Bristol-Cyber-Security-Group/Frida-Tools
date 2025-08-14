import datetime
import pathlib
import frida
import time
import sys
import os

from process_data import process_data

# Parse args
try:
    PROCESS_NAME = sys.argv[1]
    outdir = sys.argv[2]
except:
    print("Usage: 'python intercept.py <packagename> <outdir>'")
    sys.exit(1)

ids = {'message_id': 1}
messages = {}
def on_message(message, data):
    if message['type'] == 'send':
        # determine which TLS intercept this was, either low level or Java based
        payload = message['payload']
        if payload.get("TYPE") is not None:
            # TODO process this data
            info, processed_data = process_data(data)
            if processed_data:
                # timestamp = datetime.datetime.now().isoformat()
                # record = [ids['message_id'], timestamp, str(processed_data)]
                # with open(csv_path, 'a', newline='') as file:
                #     writer = csv.writer(file)
                #     writer.writerow(record)

                ids['message_id'] += 1

            # TODO - write to csv
            # write_log(str({**payload, **info}))

            # TODO - temp processing
            time = datetime.datetime.now().isoformat()
            if messages.get(payload['STREAM_ID']) is None:
                messages[payload['STREAM_ID']] = [{'time': time, 'payload': payload, 'processed_data': processed_data}]
            else:
                messages[payload['STREAM_ID']].append({'time': time, 'payload': payload, 'processed_data': processed_data})
        else:
            # TODO - write to csv
            time = datetime.datetime.now().isoformat()
            if messages.get(payload['session']) is None:
                messages[payload['session']] = [{'time': time, 'payload': payload, 'data': data}]
            else:
                messages[payload['session']].append({'time': time, 'payload': payload, 'data': data})

# This frida script will compile the javascript file with node.js to include
# the Frida Java bridge. This will create a 'node_modules' in the Frida-Tools
# folder, in addition to other npm files such as the packages.json will be
# created.

PROJECT_ROOT = pathlib.Path(os.path.dirname(os.path.abspath(__file__))).resolve()
ENTRYPOINT   = PROJECT_ROOT / "script.js"

# create the package manager and install the Java bridge
pm = frida.PackageManager()
pm.on("install-progress", lambda phase, fraction, details: print({"phase": phase, "fraction": fraction, "details": details}))
pm.install(specs=["frida-java-bridge"])


# add a hook to print out diagnostics from the compilation stage to show any errors
diag_logging = []
def on_diag(diag):
    diag_logging.append(f"compiler log: {diag}")

# compile with the diagnostics hook
compiler = frida.Compiler()
compiler.on("diagnostics", on_diag)
try:
    bundle = compiler.build(str(ENTRYPOINT), project_root=str(PROJECT_ROOT))
except Exception as e:
    #
    if diag_logging:
        for ii in diag_logging:
            print(ii)
    print(e)
    sys.exit(1)

# we will now attach to the process on the device, or start the process
device = frida.get_usb_device()

processes = device.enumerate_processes()
running = next((p for p in processes if p.name.lower() == PROCESS_NAME.lower()), None)

is_spawn = False
if running:
    # the application is running, we will just attach
    pid = running.pid
    session = device.attach(pid)
    # TODO - if app has crashed or is frozen but is in background with a pid, spawn instead
else:
    # the application is not running, we will spawn it
    # TODO - we need the full identifier
    pid = device.spawn(PROCESS_NAME)
    session = device.attach(pid)
    is_spawn = True

# now attach the script we built into the running process
script = session.create_script(bundle)
script.on('message', on_message)
script.load()
if is_spawn:
    device.resume(pid)

# TODO - wait for SIGINT
time.sleep(10)

for key, val in messages.items():
    print("="*100)
    print(key, "n elements: ", len(val))
    for ii in val:
        print("=" * 20)
        print(ii['time'], ii['payload'])
        if ii.get('data') is not None:
            print(ii['data'])
        else:
            print(ii['processed_data'])

print(f"Intercepted {ids['message_id'] - 1} messages, exiting.")
sys.exit(0)
