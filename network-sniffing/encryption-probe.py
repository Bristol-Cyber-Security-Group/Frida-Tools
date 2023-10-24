
"""
Hooks into the libssl.so library for native SSL functions (SSL_new and SSL_connect).
Also hooks into the Java SSLContext class to determine when SSL context is being initialized.
The SSLParameters.getProtocols method is hooked to identify the supported protocols.
All findings are logged in encryption_protocol.log.
"""

import frida
import sys
import logging


# JavaScript code to hook into SSL/TLS methods
js_code = """
// Native function hooks
Interceptor.attach(Module.findExportByName("libssl.so", "SSL_new"), {
    onEnter: function(args) {
        send({'message': "SSL_new called"});
    },
    onLeave: function(retval) {
        send({'message': "SSL Context: " + retval});
    }
});

Interceptor.attach(Module.findExportByName("libssl.so", "SSL_connect"), {
    onEnter: function(args) {
        send({'message': "SSL_connect called"});
    },
    onLeave: function(retval) {
        send({'message': "SSL_connect return: " + retval});
    }
});

// Java function hooks
Java.perform(function() {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var SSLParameters = Java.use("javax.net.ssl.SSLParameters");
    
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, random) {
        send({'message': 'SSLContext.init()'});
        return this.init(keyManager, trustManager, random);
    };
    
    SSLParameters.getProtocols.implementation = function() {
        var protocols = this.getProtocols();
        send({'message': "Supported Protocols: " + protocols.toString()});
        return protocols;
    };
});
"""

# Function to handle messages from JavaScript
def on_message(message, data):
    if message["type"] == "send":
        log_message = message.get("payload", {}).get('message')
        if log_message:
            logging.info(log_message)

try:
    PROCESS_NAME = sys.argv[1]
    OUT_DIR = sys.argv[2]
except:
    print("Usage: 'python encryption-probe.py <packagename> <outdir>'")
    sys.exit(1)

# Initialize logging
logging.basicConfig(level=logging.INFO,
                    format='%(message)s',
                    handlers=[logging.FileHandler(f"{OUT_DIR}/encryption_protocol.log")])

# Attach Frida to the target process
target_process = PROCESS_NAME
device = frida.get_usb_device()
pid = device.spawn([target_process])
session = device.attach(pid)

# Create and load the script
script = session.create_script(js_code)
script.on("message", on_message)
script.load()
device.resume(pid)

# Prevent script from terminating immediately
import time
time.sleep(10)
sys.exit(0)