
""" 
This script runs for 30 seconds, checking for the presence of local
databases and outputs a summary file of what it found at the end called 
'database_summary.txt'.
"""

import frida
import sys

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
        console.log("SharedPreferences::putString - Key:", key, ", Value:", value);
        return this.putString(key, value);
    };

    sharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        sharedPrefFlag = true;
        var value = this.getString(key, defValue);
        console.log("SharedPreferences::getString - Key:", key, ", Value:", value);
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
            console.log("fopen - Path:", this.path);
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "fwrite"), {
    onEnter: function(args) {
        fileIOFlag = true;
        console.log("fwrite called - Size:", args[2].toInt32());
    }
});

// Hook SQLiteDatabase
Java.perform(function() {
    var sqliteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    sqliteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
        sqliteFlag = true;
        console.log("SQLiteDatabase::execSQL - SQL Query:", sql);
        return this.execSQL(sql);
    };

    sqliteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, selectionArgs) {
        sqliteFlag = true;
        console.log("SQLiteDatabase::rawQuery - SQL Query:", sql);
        return this.rawQuery(sql, selectionArgs);
    };
});

// Send summary flags after 30 seconds
Java.perform(function() {
    setTimeout(function() {
        send({
            'sharedPrefFlag': sharedPrefFlag,
            'fileIOFlag': fileIOFlag,
            'sqliteFlag': sqliteFlag
        });
    }, 30000);
});
"""

# Receives the summary flags from JS, writes summary and exits
def on_message(message, data):
    global sharedPrefFlag, fileIOFlag, sqliteFlag
    if message["type"] == "send":
        payload = message.get("payload", {})
        print(payload)
        sharedPrefFlag = payload.get("sharedPrefFlag")
        fileIOFlag = payload.get("fileIOFlag")
        sqliteFlag = payload.get("sqliteFlag")

    with open("database_summary.txt", "w") as f:
        f.write(f"SharedPreferences used: {sharedPrefFlag}\n")
        f.write(f"File I/O used: {fileIOFlag}\n")
        f.write(f"SQLite used: {sqliteFlag}\n")

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