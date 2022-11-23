import frida
import sys

# e.g. "dockerd"
process = sys.argv[1]
debug = True

session = frida.attach(process)

# assumes register convention for function calls i.e. go >= 1.17
script = session.create_script("""
        const symbol = 'crypto/x509.(*Certificate).VerifyHostname'

        var verifyHostname = Module.findExportByName(null, symbol);
        if (verifyHostname === null) {
            verifyHostname = DebugSymbol.fromName(symbol).address;
        }
        Interceptor.attach(verifyHostname, {
            onEnter(args) {
                if (%s) {
                    send(this.context.rbx.readUtf8String(this.context.rcx.toInt32()));
                }
            },
            onLeave(retval) {
                retval.replace(0);
            }
        })
""" % "true" if debug else "false")

def on_message(message, data):
    print(message)



script.on('message', on_message)
script.load()
sys.stdin.read()
