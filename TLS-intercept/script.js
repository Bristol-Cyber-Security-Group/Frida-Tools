import Java from "frida-java-bridge";

// the following looks for both the SSL read and writes being used in the application. This will pick up multiple SSL
// libraries, that are being used

const write_matches = DebugSymbol.findFunctionsNamed("SSL_write");
write_matches.forEach((addr, idx) => {
    const module = Process.findModuleByAddress(addr);
    const tag = `${module ? module.name : 'unknown'} [${idx}]`;

    console.log(`Attaching to SSL_write in ${tag} at ${addr}`);

    Interceptor.attach(ptr(addr), {
        onEnter(args) {
            try {

                const len = args[2].toInt32();
                const buf = args[1];

                const key = args[0].toString();

                console.log("(write) len:", len, "key:", key, "buf:", buf);

                var data = buf.readByteArray(len);
                send({
                    type: 'ssl_pair',
                    session: key,
                    direction: "write",
                }, data);

            } catch (e) {
                console.error(`(write) Error in ${tag}:`, e);
            }
        }
    });
});

const read_matches = DebugSymbol.findFunctionsNamed("SSL_read");
read_matches.forEach((addr, idx) => {
    const module = Process.findModuleByAddress(addr);
    const tag = `${module ? module.name : 'unknown'} [${idx}]`;

    console.log(`Attaching to SSL_read in ${tag} at ${addr}`);

    Interceptor.attach(ptr(addr), {
        onEnter(args) {
            this.key = args[0].toString();
            this.buf = args[1];
            this.num = args[2].toInt32();

            console.log("(read) len:", this.num, "key:", this.key, "buf:", this.buf);

        },
        onLeave(retval) {
            try {

                const len = retval.toInt32();
                if (len <= 0 || len > this.num) return;

                const data = this.buf.readByteArray(len);
                send({
                    type: 'ssl_pair',
                    session: this.key,
                    direction: "read",
                }, data);

            } catch (e) {
                console.error(`(read) Error in ${tag}:`, e);
            }
        }
    });
});


var data = {};

function saveData(byteArray, offset, byteCount, hashCode, direction) {
    var intArray = byteArrayToIntArray(byteArray, offset, byteCount);
    if (hashCode in data) {
        data[hashCode] = data[hashCode].concat(intArray);
    } else {
        data[hashCode] = intArray;
    }
    ;
    send(
        {
            TYPE: 'data',
            DIRECTION: direction,
            STREAM_ID: hashCode,
            LENGTH: byteCount,
        },
        intArray
    );

    send(
        {
            TYPE: 'combined-data',
            DIRECTION: direction,
            STREAM_ID: hashCode,
            LENGTH: data[hashCode].length,
        },
        data[hashCode]
    );
}

function byteArrayToIntArray(array, offset, length) {
    var result = [];
    for (var i = offset; i < offset + length; ++i) {
        result.push(
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
                16
            )
        );
    }
    return result;
}

function processData(byteArray, offset, byteCount, outputStream, direction) {
    saveData(byteArray, offset, byteCount, outputStream.hashCode(), direction);
}

Java.perform(() => {

    // TODO - look for the conscript namespace and use that
    // Java.enumerateLoadedClasses({
    //     onMatch(name) {
    //         if (name.toLowerCase().includes("ssl") || name.toLowerCase().includes("socket"))
    //             console.log(name);
    //     },
    //     onComplete() {
    //         console.log("Done listing classes.");
    //     }
    // });

    // TODO - different conscrypt namespace if signal - is this still the case?
    // const ActivityThread = Java.use('android.app.ActivityThread');
    // const processName = ActivityThread.currentProcessName();
    //
    // if (processName === 'org.thoughtcrime.securesms') {
    //     var conscrypt_id = 'org.conscrypt';
    // } else {
    //     var conscrypt_id = 'com.android.org.conscrypt';
    // }

    // TODO - handle the change of namespace from old to new android versions of conscrypt so we can use this on old apps
    //  ConscryptFileDescriptorSocket vs. ConscryptEngineSocket

    const EngineSocketOutputStream = Java.use('org.conscrypt.ConscryptEngineSocket$SSLOutputStream');
    EngineSocketOutputStream.write.overload('[B', 'int', 'int').implementation = function (byteArray, offset, byteCount) {
        this.write(byteArray, offset, byteCount);
        processData(byteArray, offset, byteCount, this, 'sent');
    }

    const EngineSocketInputStream = Java.use('org.conscrypt.ConscryptEngineSocket$SSLInputStream');
    EngineSocketInputStream.read.overload('[B', 'int', 'int').implementation = function (byteArray, offset, byteCount) {
        var ret = this.read(byteArray, offset, byteCount);
        processData(byteArray, offset, byteCount, this, 'received');
        return ret;
    }

});
