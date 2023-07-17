# frida-itrace

Instruction tracer powered by Frida.

## Example

```js
import { TraceBuffer, TraceSession } from "@frida/itrace";

const buffer = new TraceBuffer();

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

setInterval(() => {
    const chunk: ArrayBuffer = buffer.read();
    if (chunk.byteLength === 0) {
        return;
    }
    send({ type: "itrace:chunk" }, chunk);
}, 10);
```
