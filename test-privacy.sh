#!/bin/bash

# Determine the directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Usage
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <package> <path-to-apk>"
    exit 1
fi

package="$1"
filename=${package%.app}
apk="$2"
outdir="$(pwd)/logs/$filename"
mkdir -p "$outdir"

# STATIC MANIFEST ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning static manifest analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/manifest-analysis"
python check-activities.py "$DIR/$apk" "$outdir"
python check-version.py "$DIR/$apk" "$outdir"
cd "$DIR"

# PERMISSIONS ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning permissions analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/permissions"
python log-permissions.py "$package" "$outdir" &
wait $!
echo "Beginning static permissions analysis"
aapt dump xmltree "$DIR/$apk" AndroidManifest.xml | grep 'android.permission.' | awk -F\" '{print $2}' | sort > "$outdir/requested-perms.txt"
python compare-permissions.py "$package" "$outdir"
cd "$DIR"

# API ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning API analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/api-tracing"
python list-apis.py "$package" "$DIR/$apk" "$outdir"
cd "$DIR"

# TLS INTERCEPT AND NETWORK SNIFFING
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning TLS intercept"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/TLS-intercept"
python intercept.py "$package" "$outdir"
cd "$DIR/network-sniffing"
python encryption-probe.py "$package" "$outdir"
cd "$DIR"

# MEMORY ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning memory analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/memory-testing"
python get-memory-ranges.py "$package" "$outdir"
cd "$DIR"

# DATABASE ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning database analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/databases"
python database-probe.py "$package" "$outdir"
if grep -q "File I/O used: True" "$outdir/database_summary.txt"; then
    echo "File I/O usage detected. Running searchFiles.py..."
    python dump-files.py "$package" "$outdir"
fi
cd "$DIR"

# PRODUCE PDF REPORT
python produce-pdf.py "$package" "$outdir"
