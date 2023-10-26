import frida
import sys, os
import subprocess
import re


def adb_pull(file_path, local_path):
    try:
        command = ["adb", "pull", file_path, local_path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)        
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        return False
    

def readfiles(unique_files, out_dir):
    LOCAL_DIR = f"{out_dir}/files"
    KEYWORDS = ["credentials", "login", "password", "key", "token", "auth"]
    LOG_FILE_PATH = f"{out_dir}/interesting-files.txt"

    if not os.path.exists(LOCAL_DIR):
        os.makedirs(LOCAL_DIR)

    for file_path in unique_files:
        local_file_path = os.path.join(LOCAL_DIR, os.path.basename(file_path))
        if adb_pull(file_path, local_file_path):
            try:
                with open(local_file_path, 'r', encoding='utf-8') as file:
                    content = file.read()

                found_keywords = []
                for keyword in KEYWORDS:
                    if re.search(re.escape(keyword), content, re.IGNORECASE):
                        found_keywords.append(keyword)

                if found_keywords:
                    line_to_prepend = "[" + ", ".join(found_keywords) + "]\n"
                    modified_content = line_to_prepend + content

                    with open(local_file_path, 'w', encoding='utf-8') as file:
                        file.write(modified_content)

                    # Open the log file and append the message.
                    with open(LOG_FILE_PATH, 'a') as log_file:
                        log_file.write(f"file: {local_file_path} contains keywords: {', '.join(found_keywords)}\n")

            except Exception as e:
                print(f"An error occurred while processing the file: {e}")
        else:
            print(f"Failed to pull the file: {file_path}")


js_code = """
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        send(Memory.readUtf8String(args[0]));
    }
});

Interceptor.attach(Module.findExportByName(null, 'fopen'), {
    onEnter: function(args) {
        send(Memory.readUtf8String(args[0]));
    }
});

"""

unique_files = set()

def on_message(message, data):
    if message['type'] == 'send':
        file_path_msg = message['payload']
        if file_path_msg.endswith(('.json', '.xml', '.log', '.txt')):
            unique_files.add(file_path_msg)
    else:
        print(message)


try:
    PROCESS_NAME = sys.argv[1]
    OUT_DIR = sys.argv[2]
except:
    print("Usage: 'python dump-files.py <packagename> <outdir>'")
    sys.exit(1)

# Attach to the target process
device = frida.get_usb_device()
pid = device.spawn([PROCESS_NAME])
session = device.attach(pid)
script = session.create_script(js_code)
script.on('message', on_message)
script.load()
device.resume(pid)

# Prevent script from terminating immediately
import time
time.sleep(10)

with open(f"{OUT_DIR}/accessed-files.txt", "w") as f:
    f.write(str(unique_files))

readfiles(unique_files, OUT_DIR)

sys.exit(0)