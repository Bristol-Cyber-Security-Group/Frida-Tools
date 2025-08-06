// the following looks for both the SSL read and writes being used in the application. This will pick up multiple SSL
// libraries, that are being used

const write_matches = DebugSymbol.findFunctionsNamed("SSL_write");
write_matches.forEach((addr, idx) => {
    const module = Process.findModuleByAddress(addr);
    const tag = `${module ? module.name : 'unknown'} [${idx}]`;


    Interceptor.attach(ptr(addr), {
        onEnter(args) {
            try {

                const len = args[2].toInt32();
                const buf = args[1];

                const key = args[0].toString();

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


    Interceptor.attach(ptr(addr), {
        onEnter(args) {
            this.key = args[0].toString();
            this.buf = args[1];
            this.num = args[2].toInt32();

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
