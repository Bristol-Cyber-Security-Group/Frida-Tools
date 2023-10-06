
# Iterate over apk files in specified location, install to emualator and log permissions requested and used.

apkfiles=$(ls /Path/To/APKs/*.apk)

for apk in $apkfiles
do
    adb install $apk
    package=$(aapt dump badging $apk | awk -v FS="'" '/package: name=/{print $2}')
    python3 log-permissions.py $package &
    wait $!
    filename=${package%.app}
    aapt dump xmltree $apk AndroidManifest.xml | grep 'android.permission.' | awk -F\" '{print $2}' | sort > logs/$filename/requested-perms.txt
    python3 compare-permissions.py $filename
done

