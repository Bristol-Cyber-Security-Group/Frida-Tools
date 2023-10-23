var data = {};

function saveData(byteArray, offset, byteCount, hashCode, direction) {
  var intArray = byteArrayToIntArray(byteArray, offset, byteCount);
  if (hashCode in data) {
    data[hashCode] = data[hashCode].concat(intArray);
  } else {
    data[hashCode] = intArray;
  };
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

  const ActivityThread = Java.use('android.app.ActivityThread');
  const processName = ActivityThread.currentProcessName();

  if (processName === 'org.thoughtcrime.securesms') {
    var conscrypt_id = 'org.conscrypt';
  } else {
    var conscrypt_id = 'com.android.org.conscrypt';
  }

  // Android 8 Conscrypt
  const FileDescriptorOutputStream = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket$SSLOutputStream');
  FileDescriptorOutputStream.write.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    processData(byteArray, offset, byteCount, this, 'sent');
    this.write(byteArray, offset, byteCount);
  }
  const FileDescriptorInputStream = Java.use(conscrypt_id + '.ConscryptFileDescriptorSocket$SSLInputStream');
  FileDescriptorInputStream.read.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    var ret = this.read(byteArray, offset, byteCount);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }

  // Android 12 Conscrypt
  const EngineSocketOutputStream = Java.use(conscrypt_id + '.ConscryptEngineSocket$SSLOutputStream');
  EngineSocketOutputStream.write.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    processData(byteArray, offset, byteCount, this, 'sent');
    this.write(byteArray, offset, byteCount);
  }
  const EngineSocketInputStream = Java.use(conscrypt_id + '.ConscryptEngineSocket$SSLInputStream');
  EngineSocketInputStream.read.overload('[B', 'int', 'int').implementation = function(byteArray, offset, byteCount) {
    var ret = this.read(byteArray, offset, byteCount);
    processData(byteArray, offset, byteCount, this, 'received');
    return ret;
  }

});
