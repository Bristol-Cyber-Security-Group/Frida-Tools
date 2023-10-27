# Frida Scripts for App Analysis

## Overview

This repository contains various Frida scripts to perform static and dynamic privacy analysis on Android applications to produce summary files.


## Setup

### AVD Install and Setup

1. **Install AVD and cmdline tools** (an install of Android Studio comes with all required tools). The chosen AVD must be a rooted device, example commands for installation are:
`sdkmanager "system-images;android-30;google_apis;arm64-v8a"`, followed by
`avdmanager create avd --name Pixel3RootedArm64 --device "pixel_3" --package "system-images;android-30;google_apis;arm64-v8a" --abi "arm64-v8a"`
  
2. To **see installed emulators** use `emulator -list-avds` and to **run instance of emulator** use `emulator -avd Pixel3RootedArm64`


### Attach Frida to emulator

1. **Download Frida Server**: Download the Frida server for Android from [Frida Releases](https://github.com/frida/frida/releases). Ensure the version installed matches the emulator OS version.

2. **Push Frida Server to Emulator**: Push the downloaded Frida server to the emulator's `/data/local/tmp` directory.
    ```bash
    adb root
    adb push frida-server-XX.X-android-arm64 /data/local/tmp/
    ```

3. **Start Frida Server on Emulator**: Change relevant permissions and start the Frida server.
    ```bash
    adb shell chmod 755 /data/local/tmp/frida-server-XX.X-android-arm64
    adb shell /data/local/tmp/frida-server-XX.X-android-arm64 &
    ```
4. **Test installation:** Run `frida-ps -U` to list processes on the connected emulator. 

## Run

### Requirements:
- Emulator is running with Frida server started as setup above.
- Android platform tools and build tools are in PATH (the commands `aapt` and `adb` are required).
- This repository provides a requirements.txt for installing requirements via pip, but the recommended dependency management system is Poetry. Run `poetry install` in the root repository to install dependencies, then `poetry shell` to activate the environment.

### Running the tools:
To do a complete run using all tools, use `test-privacy.sh`. 

Usage: `./test-privacy.sh <package-name> <path-to-apk>`.

Example usage: `./test-privacy.sh com.bose.bosemusic ../apkfiles/BoseMusic_8.0.5_Apkpure.apk`.