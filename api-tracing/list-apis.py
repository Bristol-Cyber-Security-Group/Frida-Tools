import os
import subprocess
import sys

"""
Decompile the APK
"""
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

"""
Extract API usage from the decompiled APK source.
"""
def extract_apis(package_name, output_dir, api_list_file):
    # Assuming APIs would be invoked with dot notation.
    cmd = f"grep -rEo '[A-Za-z_]+\\.[A-Za-z_]+\\([A-Za-z_]*\\)' {output_dir} | sort | uniq > {api_list_file}"
    os.system(cmd)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 api_analysis.py <package_name> <apk_path>")
        sys.exit(1)

    apk_path = sys.argv[2]
    output_dir = f"{sys.argv[1]}/decompile"
    api_list_file = f"{sys.argv[1]}/apis.txt"

    decompile_apk(apk_path, output_dir)
    extract_apis(sys.argv[1], output_dir, api_list_file)
    
    print(f"APIs extracted and saved in {api_list_file}")

if __name__ == "__main__":
    main()
