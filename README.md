# Frida Scripts for App Analysis

## Overview

This repository contains various Frida scripts to analyze and reverse engineer apps. The app which is used for testing in all scripts currently is the bose music app (`com.bose.bosemusic`). Scripts are aimed at intercepting various local storage and I/O operations within the app, and development is ongoing. Future scripts will include memory violation and TLS encryption experiments. 

### Repository Structure

- `./databases/`: This folder contains scripts and example log/summary files from local database experiments.
  - `database_detection.py`: Script to detect presence of local databases, creating a summary and log of findings.
- `./network-sniffing/`: Folder contains scripts for hooking into networking apis used. 
  - `network-probe.py`: Probes for which networking libraries the application is using to communicate with external endpoints and outputs to commandline.
  - `open-connection-interceptor.py`: hooks into the java.net.URL library and picks up every time new connections are opened. All connections are output to `networking.log` and after 30 seconds `network_summary.txt` is created containing a summary of which connections were opened and how many times they were accessed.
- TODO: Update list with new scripts as they're added

## Prerequisites

- Python 3.9.13
- Frida Tools installed (`pip install frida-tools`)
- Android Emulator (e.g., Android Studio's built-in emulator or Genymotion)
- ADB Tools

## Setup and Run

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