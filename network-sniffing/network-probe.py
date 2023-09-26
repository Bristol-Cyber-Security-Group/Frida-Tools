
""" 
This script hooks into the running application to probe for which networking libraries the 
app is using. If one of the libraries is used it will be printed. 
"""

import frida
import sys

js_code = """
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function(str) {
        send('java.net.URL is being used.');
        return this.$init(str);
    };

    var Socket = Java.use('java.net.Socket');
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
        send('java.net.Socket is being used.');
        return this.$init(host, port);
    };

    try {
        var HttpClient = Java.use('org.apache.http.impl.client.DefaultHttpClient');
        HttpClient.execute.overload('org.apache.http.HttpUriRequest').implementation = function(request) {
            send('org.apache.http.impl.client.DefaultHttpClient is being used.');
            return this.execute(request);
        };
    } catch (error) {
        send('org.apache.http.impl.client.DefaultHttpClient not used in this app.');
    }

    try {
        var HttpUrlConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpUrlConnection.connect.implementation = function() {
            send('javax.net.ssl.HttpsURLConnection is being used.');
            return this.connect();
        };
    } catch (error) {
        send('javax.net.ssl.HttpsURLConnection not used in this app.');
    }

});
"""

def on_message(message, data):
    if message["type"] == "send":
        print("[+] " + message["payload"])
    else:
        print("[-] " + message["description"])

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