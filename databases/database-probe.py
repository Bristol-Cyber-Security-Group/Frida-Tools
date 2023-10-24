
""" 
This script runs for 30 seconds, checking for the presence of local
databases and outputs a summary file of what it found at the end called 
'database_summary.txt'.
"""

import frida
import sys
import logging


try:
    PROCESS_NAME = sys.argv[1]
    OUT_DIR = sys.argv[2]
except:
    print("Usage: 'python database-probe.py <packagename> <outdir>'")
    sys.exit(1)


# Initialize logging
logging.basicConfig(level=logging.INFO,
                    format='%(message)s',
                    handlers=[logging.FileHandler(f"{OUT_DIR}/db.log")])

# Javascript functions to be injected
js_code = """
var sharedPrefFlag = false;
var fileIOFlag = false;
var sqliteFlag = false;

// Hook SharedPreferences
Java.perform(function () {
    var sharedPreferences = Java.use("android.content.SharedPreferences");
    var editor = Java.use("android.content.SharedPreferences$Editor");

    editor.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
        sharedPrefFlag = true;
        send({'message': "SharedPreferences::putString - Key: " + key + ", Value: " + value});
        return this.putString(key, value);
    };

    sharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        sharedPrefFlag = true;
        var value = this.getString(key, defValue);
        send({'message': "SharedPreferences::getString - Key: " + key + ", Value: " + value});
        return value;
    };
});

// Hook File I/O
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        fileIOFlag = true;
        this.path = Memory.readCString(args[0]);
    },
    onLeave: function(retval) {
        if (this.path) {
            send({'message': "fopen - Path: " + this.path});
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "fwrite"), {
    onEnter: function(args) {
        fileIOFlag = true;
        send({'message': "fwrite called - Size: " + args[2].toInt32()});
    }
});

// Hook SQLiteDatabase
Java.perform(function() {
    var sqliteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    sqliteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
        sqliteFlag = true;
        send({'message': "SQLiteDatabase::execSQL - SQL Query: " + sql});
        return this.execSQL(sql);
    };

    sqliteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, selectionArgs) {
        sqliteFlag = true;
        send({'message': "SQLiteDatabase::rawQuery - SQL Query: " + sql});
        return this.rawQuery(sql, selectionArgs);
    };
});

// Send summary flags after 10 seconds
Java.perform(function() {
    setTimeout(function() {
        send({
            'sharedPrefFlag': sharedPrefFlag,
            'fileIOFlag': fileIOFlag,
            'sqliteFlag': sqliteFlag
        });
    }, 10000);
});
"""

# Receives the summary flags from JS, writes summary and exits
def on_message(message, data):
    global sharedPrefFlag, fileIOFlag, sqliteFlag
    if message["type"] == "send":
        payload = message.get("payload", {})
        log_message = payload.get('message')
        if log_message:
            logging.info(log_message)
        else:
            sharedPrefFlag = payload.get("sharedPrefFlag")
            fileIOFlag = payload.get("fileIOFlag")
            sqliteFlag = payload.get("sqliteFlag")
            with open(f"{OUT_DIR}/database_summary.txt", "w") as f:
                f.write(f"SharedPreferences used: {sharedPrefFlag}\n")
                f.write(f"File I/O used: {fileIOFlag}\n")
                f.write(f"SQLite used: {sqliteFlag}\n")
            print(f"SharedPreferences used: {sharedPrefFlag}")
            print(f"File I/O used: {fileIOFlag}")
            print(f"SQLite used: {sqliteFlag}")
    

# Select Bose App from processes and attach Frida
target_process = PROCESS_NAME
device = frida.get_usb_device()
pid = device.spawn([target_process])
session = device.attach(pid)

# Create and load the JS script
script = session.create_script(js_code)
script.on("message", on_message)
script.load()
device.resume(pid)

# Prevent script from terminating immediately
import time
time.sleep(15)
sys.exit(0)