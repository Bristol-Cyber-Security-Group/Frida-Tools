"""
Parse an AndroidManifest.xml file and print out the minimum SDK version.
"""

import yaml
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

def find_sdk_info(yml_file_path):
    try:
        with open(yml_file_path, 'r') as stream:
            data_loaded = yaml.safe_load(stream)

        sdk_info = data_loaded.get('sdkInfo')

        if sdk_info is not None:
            return sdk_info
        else:
            print("No sdkInfo found in the apktool.yml file.")
            return None

    except yaml.YAMLError as exc:
        print(f"Error while parsing the apktool.yml file: {exc}")
        return None
    except FileNotFoundError:
        print(f"File not found: {yml_file_path}")
        return None


if len(sys.argv) < 3:
    print("Usage: python check-version.py <path_to_apk> <outdir>")
    sys.exit(1)

apk_path = sys.argv[1]
outdir = sys.argv[2]
decompile_dir = f"{outdir}/decompile"

decompile_apk(apk_path, decompile_dir)
sdk_info = find_sdk_info(f"{decompile_dir}/apktool.yml")

with open(f"{outdir}/version-check.txt", 'w') as file:
    if sdk_info:
        file.write(str(sdk_info))
    else:
        file.write("No SDK information available.")
