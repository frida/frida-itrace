# frida-itrace

Instruction tracer powered by Frida.

## Example

```js
import {
    TraceBuffer,
    TraceBufferReader,
    TraceSession,
    TraceStrategy,
} from "frida-itrace";

const strategy: TraceStrategy = {
    type: "thread",
    threadId: Process.enumerateThreads()[0].id
};

const buffer = TraceBuffer.alloc();

const session = new TraceSession(strategy, buffer);
session.events.on("start", (regSpecs, regValues) => {
    send({ type: "itrace:start", payload: regSpecs }, regValues);
});
session.events.on("end", () => {
    send({ type: "itrace:end" });
});
session.events.on("compile", (block) => {
    send({ type: "itrace:compile", payload: block });
});
session.events.on("panic", (message) => {
    console.error(message);
});
session.open();

const reader = new TraceBufferReader(buffer);
setInterval(() => {
    const chunk: ArrayBuffer = reader.read();
    if (chunk.byteLength === 0) {
        return;
    }
    send({ type: "itrace:chunk" }, chunk);
}, 10);
```
