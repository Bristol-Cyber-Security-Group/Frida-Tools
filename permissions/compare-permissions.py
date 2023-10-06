import sys

package = sys.argv[1]

# Define sensitive permissions
highly_sensitive_permissions = {
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_SMS",
    "android.permission.BODY_SENSORS"
}

moderately_sensitive_permissions = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.ACTIVITY_RECOGNITION"
}

potentially_sensitive_permissions = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN"
}


# Read content from granted-perms.txt
with open(f'logs/{package}/granted-perms.txt', 'r') as f:
    granted_perms = set(f.readlines())

# Read content from requested-perms.txt
with open(f'logs/{package}/requested-perms.txt', 'r') as f:
    requested_perms = set(f.readlines())

# Find differences
only_requested = requested_perms - granted_perms
only_granted = granted_perms - requested_perms

# Filter sensitive and non-sensitive from requested and granted
highly_sensitive_granted = set(perm for perm in granted_perms if perm.strip() in highly_sensitive_permissions)
moderately_sensitive_granted = set(perm for perm in granted_perms if perm.strip() in moderately_sensitive_permissions)
potentially_sensitive_granted = set(perm for perm in granted_perms if perm.strip() in potentially_sensitive_permissions)


# Write to summary.txt
with open(f'logs/{package}/summary.txt', 'w') as f:
    f.write("Only requested, not granted:\n")
    for perm in only_requested:
        f.write(perm)
    
    f.write("\nOnly granted, not requested:\n")
    for perm in only_granted:
        f.write(perm)

    f.write("\nHighly Sensitive permissions granted:\n")
    for perm in highly_sensitive_granted:
        f.write(perm)
        
    f.write("\nModerately Sensitive permissions granted:\n")
    for perm in moderately_sensitive_granted:
        f.write(perm)
        
    f.write("\nPotentially Sensitive permissions granted:\n")
    for perm in potentially_sensitive_granted:
        f.write(perm)