# frida-itrace

Instruction tracer powered by Frida.

## Example

```js
import {
    TraceBuffer,
    TraceBufferReader,
    TraceSession,
} from "frida-itrace";

const strategy = {
    type: "thread",
    threadId: Process.enumerateThreads()[0].id,
};

const buffer = TraceBuffer.create();

const session = new TraceSession(strategy, buffer);
session.events.on("end", () => {
    send({ type: "itrace:end" });
});
session.open();

const reader = new TraceBufferReader(buffer);
setInterval(() => {
    const chunk = reader.read();
    if (chunk.byteLength === 0) return;
    send({ type: "itrace:chunk" }, chunk);
}, 10);
```

## Buffer format

All data — both trace records and metadata events — is delivered
through the ringbuffer. This means the buffer can be drained
out-of-process (e.g. via shared memory on Darwin), and no data is
lost if the target crashes.

### Ringbuffer layout

```
offset 0:   uint64  head        (read cursor, owned by consumer)
offset 8:   uint64  tail        (write cursor, owned by producer)
offset 16:  uint64  lost        (records dropped due to full buffer)
offset 24:  uint64  capacity
offset 32:  uint8[] data
```

### Trace records

Written at the end of each executed basic block. The first 8 bytes
are the block's virtual address (always non-zero):

```
uint64_t block_address          (non-zero)
<register writes>               (layout defined by the compile event)
```

The total size of each trace record is given by the `record_size`
field in the corresponding compile event.

### Events

Events are distinguished from trace records by a zero sentinel in the
first 8 bytes. All events share a common 16-byte header:

```
uint64_t sentinel = 0
uint32_t type
uint32_t payload_size           (bytes after header, 8-byte aligned)
```

Event types:

| Type | Value | Description             |
|------|-------|-------------------------|
| compile | 1 | Basic block compiled    |
| start   | 2 | Tracing started         |
| end     | 3 | Tracing ended           |
| panic   | 4 | Fatal instrumentation error |

#### compile (type=1)

Emitted each time Stalker compiles a new basic block. Provides the
metadata needed to parse subsequent trace records for that block.

```
uint64_t block_address
uint32_t block_size
uint32_t record_size            (trace record size for this block)
uint16_t num_writes
uint16_t name_size
uint64_t compiled_address
uint32_t compiled_size
uint64_t module_base            (0 if no module)
uint16_t module_path_size       (0 if no module)
uint16_t reserved
write[num_writes]:
    uint32_t block_offset
    uint32_t reg_index
char     name[name_size]
char     module_path[module_path_size]
<padding to 8-byte alignment>
```

#### start (type=2)

Emitted once when the first block executes. Contains the register
schema and initial CPU context.

```
uint32_t num_regs
uint32_t context_size
reg_spec[num_regs]:             (8 bytes each)
    uint8_t  name_size
    char     name[6]            (zero-padded)
    uint8_t  reg_size
uint8_t  context[context_size]  (raw GumCpuContext)
<padding to 8-byte alignment>
```

#### end (type=3)

Emitted when the end address is reached (range-based tracing). Empty
payload.

#### panic (type=4)

Emitted on fatal instrumentation errors (e.g. unhandled register).
Payload is the raw message bytes; length equals `payload_size`.

## Out-of-process reading

The ringbuffer can be read from another process using
`TraceBuffer.open()`, which remaps the buffer's memory via Mach VM
APIs (Darwin only for now):

```js
const buffer = TraceBuffer.open(location);
const reader = new TraceBufferReader(buffer);
```

Where `location` is the string returned by `buffer.location` in the
target process.
