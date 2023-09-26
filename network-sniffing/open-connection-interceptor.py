
""" 
This script hooks into the java.net.URL library and picks up every time new connections are opened. 
All connections are output to 'networking.log' and after 30 seconds 'network_summary.txt' is created
containing a summary of which connections were opened and how many times they were accessed.
"""

import frida
import sys
import logging
from collections import defaultdict

# Initialize logging
logging.basicConfig(level=logging.INFO,
                    format='%(message)s',
                    handlers=[logging.FileHandler("networking.log"),
                              logging.StreamHandler()])

networkConnections = defaultdict(int)

# JavaScript code for hooking
js_code = """
var openConnections = [];

// Hook the java.net.URL class
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    var openConnection = URL.openConnection.overload();

    openConnection.implementation = function() {
        var urlString = this.toString();
        send({'message': "openConnection called for URL: " + urlString, 'url': urlString});
        return openConnection.call(this);
    };
});

// Send summary flags after 30 seconds
Java.perform(function() {
    setTimeout(function() {
        send({
            'openConnections': openConnections
        });
    }, 30000);
});
"""

# Handle messages from JavaScript
def on_message(message, data):
    global networkConnections
    if message["type"] == "send":
        payload = message.get("payload", {})
        log_message = payload.get('message')
        
        if log_message:
            logging.info(log_message)
            url = payload.get('url')
            if url:
                networkConnections[url] += 1

        else:
            openConnections = payload.get("openConnections")
            with open("network_summary.txt", "w") as f:
                f.write("Open Network Connections:\n")
                for url, count in networkConnections.items():
                    f.write(f"{url} was accessed {count} times.\n")
            sys.exit(0)

# Select Bose App from processes and attach Frida
target_process = "com.bose.bosemusic"
device = frida.get_usb_device()
pid = device.spawn([target_process])
session = device.attach(pid)

# Create and load the JS script
script = session.create_script(js_code)
script.on("message", on_message)
script.load()

# Resume the app and keep the python script running
device.resume(pid)
sys.stdin.read()
