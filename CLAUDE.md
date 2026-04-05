# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## Project

frida-itrace is an instruction-level tracer powered by Frida. It traces
CPU instruction execution on ARM64 with full register state tracking,
using a lock-free ringbuffer for high-performance data collection.

Published as an npm package, `frida-itrace`.

## Build Commands

```bash
npm run build       # Compile TypeScript to dist/
npm run watch       # Watch mode for development
```

No test suite exists.

## Architecture

Three layers, top to bottom:

1. **TypeScript API** (`lib/index.ts`) — `TraceSession`,
   `TraceBuffer`, `TraceBufferReader`. TraceSession is the main entry
   point; it accepts a `TraceStrategy` (thread-based or
   address-range-based tracing). Events: `start`, `compile`, `chunk`,
   `end`, `panic`.

2. **Embedded C backend** (`lib/backend.ts`) — C source code as a
   template string, compiled at runtime via Frida's `CModule`.
   Implements Stalker transform logic: iterates ARM64 instructions per
   basic block, tracks register reads/writes via Capstone, injects
   buffer-write code. Session state machine:
   `CREATED → STARTING → STARTED → ENDED`.

3. **Lock-free ringbuffer** (`helpers/`) — Single-producer
   single-consumer ringbuffer. `itracebuffer.c` is the reference C
   implementation, compiled to a .dylib. `itracebuffer_read.s` and
   `itracebuffer_write.s` are hand-crafted ARM64 assembly derived by
   disassembling the C output and then manually rewriting it to avoid
   clobbering CPU flags and registers. This allows the code to be
   inlined directly from Stalker-generated blocks without the full
   save/restore cost that the C ABI would require.

Key patterns:
- Frida APIs: `Stalker` for instruction-level hooking, `Interceptor`
  for function hooks, `CModule` for native code injection,
  `NativeCallback`/`NativeFunction` for C↔JS transitions.
- Darwin-specific shared memory via Mach kernel APIs for cross-process
  tracing.
- Lazy native API binding with memoization to avoid missing symbol
  errors.
- Scratch register management (x21–x28) during ARM64 block
  instrumentation.
- `Script.bindWeak()` for automatic resource cleanup, plus explicit
  `close()`.

## Conventions

- **Newspaper code order**: if function A calls B, then B should be
  defined after A. The further down a function is, the lower level it
  is. Entry points (e.g. `init`, `transform`) come first; leaf helpers
  come last.
- **CModule uses TinyCC** by default. TCC does not support GCC
  builtins like `__sync_synchronize` or `__atomic_*`. Use inline
  assembly or raw instruction encodings for barriers and atomics.
- **Minimal comments**: don't add header-style comments that label
  obvious sections (e.g. `/* Header */`, `/* Payload */`). Prefer
  well-named variables and clear structure. Only comment when the
  code cannot communicate something — like explaining a raw
  instruction encoding. Be mindful that TCC lacks an optimizer, so
  don't introduce variables solely for readability if it adds
  runtime cost.
