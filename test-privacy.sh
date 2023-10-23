#!/bin/bash

# Usage
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <package> <path-to-apk>"
    exit 1
fi

package="$1"
apk="$2"

# PERMISSIONS ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning permissions analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd permissions
python log-permissions.py $package &
wait $!
filename=${package%.app}
echo "Beginning static permissions analysis"
aapt dump xmltree ../$apk AndroidManifest.xml | grep 'android.permission.' | awk -F\" '{print $2}' | sort > logs/$filename/requested-perms.txt
python compare-permissions.py $package
cd ..

# API ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning API analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd api-tracing
python list-apis.py $package ../$apk
cd ..

# TLS INTERCEPT AND NETWORK SNIFFING
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning TLS intercept"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd TLS-intercept
python intercept.py $package
cd ../network-sniffing
python encryption-probe.py $package
cd ..

# MEMORY ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning memory analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd memory-testing
python get-memory-ranges.py $package
cd ..

# DATABASE ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning database analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd databases
python database-probe.py $package
cd ..