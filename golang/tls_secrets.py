import frida
import sys

# e.g. "dockerd"
process = sys.argv[1]

session = frida.attach(process)

# assumes register convention for function calls i.e. go >= 1.17
script = session.create_script("""
        function bufferToHex (buffer) {
            return [...new Uint8Array (buffer)]
                .map (b => b.toString (16).padStart (2, "0"))
                .join ("");
        }

        const symbol = 'crypto/tls.(*Config).writeKeyLog'

        var writeKeyLog = Module.findExportByName(null, symbol);
        console.log(writeKeyLog);
        if (writeKeyLog === null) {
            writeKeyLog = DebugSymbol.fromName(symbol).address;
        }

        Interceptor.attach(writeKeyLog, {
            onEnter(args) {
                const label = this.context.rbx.readUtf8String(this.context.rcx.toInt32());
                const clientRandom = bufferToHex(this.context.rdi.readByteArray(this.context.rsi.toInt32()));
                const secret = bufferToHex(this.context.r9.readByteArray(this.context.r10.toInt32()));
                send(`${label} ${clientRandom} ${secret}`);
            }
        })
""")

def on_message(message, data):
    print(message["payload"])



script.on('message', on_message)
script.load()
sys.stdin.read()
