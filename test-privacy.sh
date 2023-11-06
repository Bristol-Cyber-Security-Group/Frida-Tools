#!/bin/bash

# Set poetry environment
PYTHON="/path/to/poetry/env/bin/python"

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
$PYTHON check-activities.py "$apk" "$outdir"
$PYTHON check-version.py "$apk" "$outdir"
cd "$DIR"

# PERMISSIONS ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning permissions analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/permissions"
$PYTHON log-permissions.py "$package" "$outdir" &
wait $!
echo "Beginning static permissions analysis"
aapt dump xmltree "$apk" AndroidManifest.xml | grep 'android.permission.' | awk -F\" '{print $2}' | sort > "$outdir/requested-perms.txt"
$PYTHON compare-permissions.py "$package" "$outdir"
cd "$DIR"

# API ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning API analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/api-tracing"
$PYTHON list-apis.py "$package" "$apk" "$outdir"
cd "$DIR"

# TLS INTERCEPT AND NETWORK SNIFFING
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning TLS intercept"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/TLS-intercept"
$PYTHON intercept.py "$package" "$outdir"
cd "$DIR/network-sniffing"
$PYTHON encryption-probe.py "$package" "$outdir"
cd "$DIR"

# MEMORY ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning memory analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/memory-testing"
$PYTHON get-memory-ranges.py "$package" "$outdir"
cd "$DIR"

# DATABASE ANALYSIS
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
echo "Beginning database analysis"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -

cd "$DIR/databases"
$PYTHON database-probe.py "$package" "$outdir"
if grep -q "File I/O used: True" "$outdir/database_summary.txt"; then
    echo "File I/O usage detected. Running searchFiles.py..."
    $PYTHON dump-files.py "$package" "$outdir"
fi
cd "$DIR"

# PRODUCE PDF REPORT
$PYTHON produce-pdf.py "$package" "$outdir"
