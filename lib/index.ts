import * as backend from "./backend.js";

import EventEmitter from "events";
import type { TypedEmitter } from "tiny-typed-emitter";

const POINTER_SIZE = Process.pointerSize;

const BUFFER_OFFSET_LOST = 2 * POINTER_SIZE;
const BUFFER_OFFSET_CAPACITY = 3 * POINTER_SIZE;

const _bufferRead = makeBufferReadImpl();

export type TraceStrategy = TraceThreadStrategy | TraceRangeStrategy;

export interface TraceThreadStrategy {
    type: "thread";
    threadId: number;
}

export interface TraceRangeStrategy {
    type: "range";
    start: NativePointer;
    end: NativePointer;
}

export class TraceSession {
    events = new EventEmitter() as TypedEmitter<TraceSessionEvents>;

    #cm: CModule;
    #threadId: number | undefined;

    constructor(public strategy: TraceStrategy, public buffer: TraceBuffer) {
        const nativeSession = Memory.alloc(16384);
        nativeSession.add(POINTER_SIZE).writePointer(buffer.regionBase);

        const endBuf = Memory.alloc(POINTER_SIZE);
        if (strategy.type === "range") {
            endBuf.writePointer(strategy.end);
        }

        this.#cm = new CModule(backend.code, {
            session: nativeSession,
            end_address: endBuf,
            on_start: new NativeCallback(this.#onStart, "void", ["pointer", "pointer", "uint"]),
            on_end: new NativeCallback(this.#onEnd, "void", []),
            on_compile: new NativeCallback(this.#onCompile, "void", ["pointer"]),
            on_panic: new NativeCallback(this.#onPanic, "void", ["pointer"]),
        });
    }

    open() {
        const { strategy } = this;
        if (strategy.type === "thread") {
            this.#followThread(strategy.threadId);
        } else {
            const session = this;
            Interceptor.attach(strategy.start, function () {
                if (session.#threadId === undefined) {
                    session.#followThread(this.threadId);
                }
            });
        }
    }

    #followThread(threadId: number) {
        this.#threadId = threadId;
        Stalker.follow(threadId, {
            transform: this.#cm.transform,
        });
    }

    #onStart = (metaJson: NativePointer, cpuContext: NativePointer, length: number) => {
        const specs = JSON.parse(metaJson.readUtf8String()!) as RegisterSpec[];
        const values = cpuContext.readByteArray(length)!;
        this.events.emit("start", specs, values);
    };

    #onEnd = () => {
        setImmediate(() => {
          Stalker.unfollow(this.#threadId);
          this.events.emit("end");
        });
    };

    #onCompile = (metaJson: NativePointer) => {
        const block = JSON.parse(metaJson.readUtf8String()!);

        block.address = ptr(block.address);

        const compiled = block.compiled;
        compiled.address = ptr(compiled.address);

        const module = block.module;
        if (module !== undefined) {
            module.base = ptr(module.base);
        }

        this.events.emit("compile", block);
    };

    #onPanic = (messagePtr: NativePointer) => {
        const message = messagePtr.readUtf8String()!;
        this.events.emit("panic", message);
    };
}

export interface TraceSessionEvents {
    start: (regSpecs: RegisterSpec[], regValues: ArrayBuffer) => void,
    end: () => void,
    compile: (block: BlockSpec) => void,
    panic: (message: string) => void,
}

export interface RegisterSpec {
    /**
     * Name of register, e.g. `x0`.
     */
    name: string;

    /**
     * Size of register, e.g. `8`.
     */
    size: number;
}

/**
 * Basic block that was just compiled.
 */
export interface BlockSpec {
    /**
     * Human-readable name.
     */
    name: string;

    /**
     * Memory address where block starts.
     */
    address: NativePointer;

    /**
     * Block size, in bytes.
     */
    size: number;

    /**
     * Where in memory the compiled version of the block resides. This is the
     * code that actually gets executed.
     */
    compiled: {
        /**
         * Memory address where compiled block starts.
         */
        address: NativePointer;

        /**
         * Compiled block size, in bytes.
         */
        size: number;
    }

    /**
     * Module that this block is part of, if any.
     */
    module?: {
        /**
         * Module path.
         */
        path: string;

        /**
         * Module base address.
         */
        base: NativePointer;
    }

    /**
     * Register writes performed by the block. This is needed to parse the data
     * written to the `TraceBuffer`.
     */
    writes: BlockWriteSpec[];
}

export type BlockWriteSpec = [ blockOffset: number, registerIndex: number ];

/**
 * Ringbuffer where data gets written at the end of each basic block executed.
 *
 * Each written record has the following format on arm64:
 * ```
 * uint64_t block_address;
 * uint64_t link_register;
 * RegisterValue reg_writes[n];
 * ```
 * Where `n` depends on the particular block, specified by
 * `BlockSpec#writes`.
 */
export class TraceBuffer {
    get location(): string {
        const pid = Process.id;
        const { regionBase, regionSize } = this;
        return JSON.stringify({ pid, regionBase, regionSize });
    }

    constructor(
        public regionBase: NativePointer,
        public regionSize: number) {
    }

    static alloc(config: TraceBufferConfig = {}): TraceBuffer {
        const stateSize = 4 * POINTER_SIZE;
        const capacity = config.capacity ?? 32 * 1024 * 1024;
        const regionSize = roundUpToPageSize(stateSize + capacity);

        const nativeBuffer = Memory.alloc(regionSize);
        nativeBuffer.add(BUFFER_OFFSET_CAPACITY).writePointer(ptr(capacity));

        return new TraceBuffer(nativeBuffer, regionSize);
    }
}

export interface TraceBufferConfig {
    /**
     * Buffer capacity, in bytes.
     */
    capacity?: number;
}

export class TraceBufferReader {
    #chunkBuf: NativePointer;
    #chunkSize: number;

    #emptyBuffer = new ArrayBuffer(0);

    #lost: NativePointer;

    get lost(): number {
        return this.#lost.readPointer().toUInt32();
    }

    constructor(
            public buffer: TraceBuffer,
            config: TraceBufferReaderConfig = {}) {
        const chunkSize = config.chunkSize ?? 4 * 1024 * 1024;
        this.#chunkBuf = Memory.alloc(chunkSize);
        this.#chunkSize = chunkSize;

        this.#lost = buffer.regionBase.add(BUFFER_OFFSET_LOST);
    }

    read(): ArrayBuffer {
        const n = _bufferRead(this.buffer.regionBase, this.#chunkBuf, this.#chunkSize);
        if (n === 0) {
            return this.#emptyBuffer;
        }
        return this.#chunkBuf.readByteArray(n)!;
    }
}

export interface TraceBufferReaderConfig {
    /**
     * Maximum number of bytes per read.
     */
    chunkSize?: number;
}

function makeBufferReadImpl() {
    const machineCodeTemplate = [
        0xf8, 0x5f, 0xbc, 0xa9, /* stp x24, x23, [sp, -0x40]! */
        0xf6, 0x57, 0x01, 0xa9, /* stp x22, x21, [sp, 0x10]   */
        0xf4, 0x4f, 0x02, 0xa9, /* stp x20, x19, [sp, 0x20]   */
        0xfd, 0x7b, 0x03, 0xa9, /* stp x29, x30, [sp, 0x30]   */
        0xfd, 0xc3, 0x00, 0x91, /* add x29, sp, 0x30          */
        0x18, 0x00, 0x40, 0xf9, /* ldr x24, [x0]              */
        0x08, 0x20, 0x00, 0x91, /* add x8, x0, 8              */
        0x08, 0xc1, 0xbf, 0xf8, /* ldapr x8, [x8]             */
        0x08, 0x01, 0x18, 0xeb, /* subs x8, x8, x24           */
        0x61, 0x00, 0x00, 0x54, /* b.ne not_empty             */
        0x14, 0x00, 0x80, 0xd2, /* mov x20, 0                 */
        0x20, 0x00, 0x00, 0x14, /* b beach                    */
        /* not_empty:                                         */
        0xf5, 0x03, 0x01, 0xaa, /* mov x21, x1                */
        0xf3, 0x03, 0x00, 0xaa, /* mov x19, x0                */
        0x09, 0x01, 0x00, 0x54, /* b.ls copy_with_wrap        */
        0x1f, 0x01, 0x02, 0xeb, /* cmp x8, x2                 */
        0x14, 0x31, 0x82, 0x9a, /* csel x20, x8, x2, lo       */
        0x68, 0x02, 0x18, 0x8b, /* add x8, x19, x24           */
        0x01, 0x81, 0x00, 0x91, /* add x1, x8, 0x20           */
        0xe0, 0x03, 0x15, 0xaa, /* mov x0, x21                */
        0xe2, 0x03, 0x14, 0xaa, /* mov x2, x20                */
        0x0f, 0x00, 0x00, 0x14, /* b do_memcpy                */
        /* copy_with_wrap:                                    */
        0x69, 0x0e, 0x40, 0xf9, /* ldr x9, [x19, 0x18]        */
        0x08, 0x01, 0x09, 0x8b, /* add x8, x8, x9             */
        0x1f, 0x01, 0x02, 0xeb, /* cmp x8, x2                 */
        0x14, 0x31, 0x82, 0x9a, /* csel x20, x8, x2, lo       */
        0x36, 0x01, 0x18, 0xcb, /* sub x22, x9, x24           */
        0x77, 0x82, 0x00, 0x91, /* add x23, x19, 0x20         */
        0xe1, 0x02, 0x18, 0x8b, /* add x1, x23, x24           */
        0xe0, 0x03, 0x15, 0xaa, /* mov x0, x21                */
        0xe2, 0x03, 0x16, 0xaa, /* mov x2, x22                */
        0x7e, 0x02, 0x00, 0x58, /* ldr x30, =memcpy_address   */
        0xc0, 0x03, 0x3f, 0xd6, /* blr x30                    */
        0xa0, 0x02, 0x16, 0x8b, /* add x0, x21, x22           */
        0x82, 0x02, 0x16, 0xcb, /* sub x2, x20, x22           */
        0xe1, 0x03, 0x17, 0xaa, /* mov x1, x23                */
        /* do_memcpy:                                         */
        0xde, 0x01, 0x00, 0x58, /* ldr x30, =memcpy_address   */
        0xc0, 0x03, 0x3f, 0xd6, /* blr x30                    */
        0x88, 0x02, 0x18, 0x8b, /* add x8, x20, x24           */
        0x69, 0x0e, 0x40, 0xf9, /* ldr x9, [x19, 0x18]        */
        0x0a, 0x09, 0xc9, 0x9a, /* udiv x10, x8, x9           */
        0x48, 0xa1, 0x09, 0x9b, /* msub x8, x10, x9, x8       */
        0x68, 0xfe, 0x9f, 0xc8, /* stlr x8, [x19]             */
        /* beach:                                             */
        0xe0, 0x03, 0x14, 0xaa, /* mov x0, x20                */
        0xfd, 0x7b, 0x43, 0xa9, /* ldp x29, x30, [sp, 0x30]   */
        0xf4, 0x4f, 0x42, 0xa9, /* ldp x20, x19, [sp, 0x20]   */
        0xf6, 0x57, 0x41, 0xa9, /* ldp x22, x21, [sp, 0x10]   */
        0xf8, 0x5f, 0xc4, 0xa8, /* ldp x24, x23, [sp], 0x40   */
        0xc0, 0x03, 0x5f, 0xd6, /* ret                        */
        0x00, 0x00, 0x00, 0x00, /* <alignment padding>        */
        /* memcpy_address:                                    */
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff,
    ];

    const code = Memory.alloc(Process.pageSize);

    Memory.patchCode(code, machineCodeTemplate.length, codeBuf => {
        codeBuf.writeByteArray(machineCodeTemplate);
        codeBuf.add(machineCodeTemplate.length - POINTER_SIZE).writePointer(Module.getExportByName(null, "memcpy"));
    });

    const read = new NativeFunction(code, "uint", ["pointer", "pointer", "uint"], { exceptions: "propagate" });
    Object.defineProperty(read, "$code", { value: code });
    return read;
}

function roundUpToPageSize(size: number) {
    const { pageSize } = Process;
    const offset = size % pageSize;
    return (offset === 0)
        ? size
        : size + (pageSize - offset);
}
