"""
The intention of this script is to log all of the memory locations in the app which are
readable, writeable, and executable to memory_ranges.log. These regions could be considered to be a security risk as
attackers could inject malicious code and execute it.
"""

import frida
import json


with open("memory_ranges.log", "w") as log_file:

    # Script to inject into application
    js_code = """
        // Enumerate all readable, writable, and executable memory ranges
        Process.enumerateRanges('rwx').forEach(function(range){
            send(range);
        });
    """

    def on_message(message, data):
        if message['type'] == 'send':
            print("[*] {0}".format(json.dumps(message['payload'])))
            log_file.write(json.dumps(message['payload']) + "\n")
        else:
            print(message)

    # Attach to the target process
    device = frida.get_usb_device()
    pid = device.spawn(["com.bose.bosemusic"])
    session = device.attach(pid)
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()

    # Resume app's main thread after injecting js
    device.resume(pid)

    # Prevent script from terminating immediately
    input("Press enter to exit...")
