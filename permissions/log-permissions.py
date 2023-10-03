""" 
This script checks for which permissions are granted for the application. It produces 
permissions.txt which logs all of the permission statuses and a summary at the end of 
all permissions which are granted to the application.
"""

import frida

# Global list to hold all the permissions and their statuses
permissions_list = []

def on_message(message, data):
    global permissions_list
    if message['type'] == 'send':
        log_message = f"[LOG]: {message['payload']}"
        print(log_message)
        
        # Append permission status to the global list
        if "Permission:" in log_message:
            permissions_list.append(log_message)
        
        # Write to the log file
        with open('permissions.txt', 'a') as f:
            f.write(log_message + '\n')

js_code = '''
Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    var PackageManager = Java.use("android.content.pm.PackageManager");
    var Context = Java.use("android.content.Context");

    function listAllPermissions() {
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var currentApplication = ActivityThread.currentApplication();
            var context = currentApplication.getApplicationContext();
            
            var allPermissions = [
                "android.permission.ACCEPT_HANDOVER",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
                "android.permission.ACCESS_MEDIA_LOCATION",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.ACCESS_NOTIFICATION_POLICY",
                "android.permission.ACCESS_WIFI_STATE",
                "android.permission.ACCOUNT_MANAGER",
                "android.permission.ACTIVITY_RECOGNITION",
                "android.permission.ADD_VOICEMAIL",
                "android.permission.ANSWER_PHONE_CALLS",
                "android.permission.BATTERY_STATS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BLUETOOTH",
                "android.permission.BLUETOOTH_ADMIN",
                "android.permission.BLUETOOTH_CONNECT",
                "android.permission.BLUETOOTH_SCAN",
                "android.permission.BLUETOOTH_STACK",
                "android.permission.BODY_SENSORS",
                "android.permission.BROADCAST_STICKY",
                "android.permission.CALL_PHONE",
                "android.permission.CAMERA",
                "android.permission.CHANGE_WIFI_MULTICAST_STATE",
                "android.permission.CHANGE_WIFI_STATE",
                "android.permission.CLEAR_APP_CACHE",
                "android.permission.CONTROL_LOCATION_UPDATES",
                "android.permission.DELETE_PACKAGES",
                "android.permission.DEVICE_POWER",
                "android.permission.DIAGNOSTIC",
                "android.permission.DISABLE_KEYGUARD",
                "android.permission.DUMP",
                "android.permission.FOREGROUND_SERVICE",
                "android.permission.GET_ACCOUNTS",
                "android.permission.GET_PACKAGE_SIZE",
                "android.permission.GET_TASKS",
                "android.permission.INSTALL_LOCATION_PROVIDER",
                "android.permission.INTERNET",
                "android.permission.KILL_BACKGROUND_PROCESSES",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.MODIFY_AUDIO_SETTINGS",
                "android.permission.MODIFY_PHONE_STATE",
                "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
                "android.permission.NFC",
                "android.permission.PACKAGE_USAGE_STATS",
                "android.permission.PERSISTENT_ACTIVITY",
                "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.QUERY_ALL_PACKAGES",
                "android.permission.READ_CALENDAR",
                "android.permission.READ_CALL_LOG",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.READ_FRAME_BUFFER",
                "android.permission.READ_LOGS",
                "android.permission.READ_PHONE_NUMBERS",
                "android.permission.READ_PHONE_STATE",
                "android.permission.READ_SMS",
                "android.permission.READ_SYNC_SETTINGS",
                "android.permission.REBOOT",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.RECEIVE_MMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECEIVE_WAP_PUSH",
                "android.permission.RECORD_AUDIO",
                "android.permission.REORDER_TASKS",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.SEND_SMS",
                "android.permission.SET_ALARM",
                "android.permission.SET_TIME",
                "android.permission.SET_WALLPAPER",
                "android.permission.SET_WALLPAPER_HINTS",
                "android.permission.SMS_FINANCIAL_TRANSACTIONS",
                "android.permission.STATUS_BAR",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.TRANSMIT_IR",
                "android.permission.USE_BIOMETRIC",
                "android.permission.USE_FINGERPRINT",
                "android.permission.VIBRATE",
                "android.permission.WAKE_LOCK",
                "android.permission.WRITE_APN_SETTINGS",
                "android.permission.WRITE_CALENDAR",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.WRITE_CONTACTS",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.WRITE_SECURE_SETTINGS",
                "android.permission.WRITE_SETTINGS",
                "android.permission.WRITE_SYNC_SETTINGS"
            ];

            
            for (var i = 0; i < allPermissions.length; i++) {
                var permissionStatus = context.checkSelfPermission(allPermissions[i]);
                send("Permission: " + allPermissions[i] + ", Status: " + permissionStatus + " (" + (permissionStatus == 0 ? "Granted" : "Denied") + ")");
            }

        } catch (e) {
            send("Exception: " + e.message);
        }
    }
    
    setTimeout(function() {
        listAllPermissions();
    }, 5000);
});
'''

device = frida.get_usb_device()
pid = device.spawn(["com.bose.bosemusic"])
session = device.attach(pid)
script = session.create_script(js_code)
script.on('message', on_message)
script.load()

device.resume(pid)

# Wait for user input to terminate the script
input("Press enter to exit...")

# Write summary of granted permissions to file
with open('permissions.txt', 'a') as f:
    f.write('\n\n--- Summary of granted permissions ---\n')
    for line in permissions_list:
        if "Status: 0" in line: 
            f.write(line + '\n')