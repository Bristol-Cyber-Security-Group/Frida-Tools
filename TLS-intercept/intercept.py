import datetime
import pathlib
import frida
import time
import sys
import csv
import os

from process_data import process_data

# Parse args
try:
    PROCESS_NAME = sys.argv[1]
    outdir = sys.argv[2]
except:
    print("Usage: 'python intercept.py <packagename> <outdir>'")
    sys.exit(1)

# set up constant for this script run
timestamp = datetime.datetime.now().isoformat()
java_ssl_csv_filename = f"{timestamp}_{PROCESS_NAME}_java_ssl.csv"
ssl_csv_filename = f"{timestamp}_{PROCESS_NAME}_ssl.csv"

# create a csv file with headers ready to be written into, return the handle to be used elsewhere
def create_csv(process_name: str, out_dir: str, headers: list[str]):
    file_name = f"{out_dir}/{process_name}.csv"
    csvfile = open(file_name, "w")
    writer = csv.writer(csvfile)
    writer.writerow(headers)
    return csvfile, writer

ssl_csv_headers = ["session", "time", "direction", "type", "data"]
ssl_csv, ssl_csv_writer = create_csv(ssl_csv_filename, outdir, ssl_csv_headers)
java_ssl_csv_headers = ["stream_id", "time", "direction", "type", "length", "data"]
java_ssl_csv, java_ssl_csv_writer = create_csv(java_ssl_csv_filename, outdir, java_ssl_csv_headers)


ids = {'message_id': 1}
messages = {}
def on_message(message, data):
    time = datetime.datetime.now().isoformat()
    if message['type'] == 'send':
        # determine which TLS intercept this was, either low level or Java based
        payload = message['payload']
        if payload.get("TYPE") is not None:
            # TODO process this data
            info, processed_data = process_data(data)
            if processed_data:
                ids['message_id'] += 1

            # write message to csv
            java_ssl_csv_writer.writerow([payload["STREAM_ID"], time, payload['DIRECTION'], payload['TYPE'], payload['LENGTH'], processed_data])

        else:
            ssl_csv_writer.writerow([payload['session'], time, payload['direction'], payload['type'], data])

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

# TODO - remove this in favour of the log streaming to file
#  stream to a separate csv for each intercept
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

java_ssl_csv.close()
ssl_csv.close()

print(f"Intercepted {ids['message_id'] - 1} messages, exiting.")
sys.exit(0)
