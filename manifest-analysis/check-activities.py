"""
Parse an AndroidManifest.xml file and print out all activities that are exported.
"""

import xml.etree.ElementTree as ET
import sys, os
import subprocess


def decompile_apk(apk_path, output_dir):
    # Skip decompilation if directory already exists
    if os.path.exists(output_dir):
        print(f"Directory {output_dir} already exists. Skipping decompilation.")
        return

    cmd = ["apktool", "d", apk_path, "-o", output_dir]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during decompilation: {str(e)}")
        sys.exit(1) 

def find_exported_activities(manifest_path):
    namespaces = {
        'android': 'http://schemas.android.com/apk/res/android'
    }

    for prefix, uri in namespaces.items():
        ET.register_namespace(prefix, uri)

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Failed to parse the manifest file: {e}")
        return
    
    exported_activities = []

    # Check each activity for the 'exported' attribute
    for activity in root.findall(".//activity"):
        exported = activity.get(f"{{{namespaces['android']}}}exported")
        if exported is not None and exported.lower() == 'true':
            activity_name = activity.get(f"{{{namespaces['android']}}}name")
            exported_activities.append(activity_name)

    return exported_activities


if len(sys.argv) < 3:
    print("Usage: python find_exported_activities.py <path_to_apk> <outdir>")
    sys.exit(1)

apk_path = sys.argv[1]
outdir = sys.argv[2]
decompile_dir = f"{outdir}/decompile"

decompile_apk(apk_path, decompile_dir)
activities = find_exported_activities(f"{decompile_dir}/AndroidManifest.xml")

with open(f"{outdir}/exported-activities.txt", 'w') as file:
            if activities:
                for activity in activities:
                    file.write(f"{activity}\n")
            else:
                file.write("No exported activities found.\n")
