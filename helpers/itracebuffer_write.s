.text
.align 2

_itrace_buffer_write:
  add x27, x28, 0x228          ; offsetof (session->stack) + sizeof (session->stack)

  stp x24, x23, [x27, -0x90]!  ; itracebuffer.c:32 {
  stp x22, x21, [x27, 0x10]
  stp x20, x19, [x27, 0x20]
  stp x12, x11, [x27, 0x30]
  stp x10, x9, [x27, 0x40]
  stp x8, x2, [x27, 0x50]
  stp x1, x0, [x27, 0x60]
  stp x29, x30, [x27, 0x70]
  add x29, x27, 0x70

  mrs x0, nzcv
  str x0, [x27, 0x80]

  ldr x19, [x28, 8]           ; session->buffer

  ldr x20, [x28, 0x10]        ; session->pending_size
  add x21, x28, 0x268         ; session->log_buf

  ldr x8, [x19, 8]            ; itracebuffer.c:33   const size_t current_tail = atomic_load_explicit (&self->tail, memory_order_relaxed); ; 0xda ; arg1
  ldr x9, [x19, 0x18]         ; itracebuffer.c:102   return (cursor + amount) % self->capacity; ; 0xda ; arg1
  ldapr x10, [x19]            ; itracebuffer.c:36   const size_t current_head = atomic_load_explicit (&self->head, memory_order_acquire);
  cmp x10, x8                 ; itracebuffer.c:39   if (current_tail == current_head)
  b.ne .Lnot_empty
  ldr x10, [x19, 0x18]        ; itracebuffer.c:40     headroom = self->capacity - 1; ; 0xed
  sub x10, x10, 1
  b .Lcheck_headroom          ; itracebuffer.c:0
.Lnot_empty:
  b.hs .Ltail_has_wrapped     ; itracebuffer.c:41   else if (current_tail > current_head)
  ldr x11, [x19, 0x18]        ; itracebuffer.c:42     headroom = (self->capacity - current_tail) + current_head - 1; ; 0xed
  mvn x12, x8
  add x10, x10, x12
  b .Lcompute_final_headroom  ; itracebuffer.c:0
.Ltail_has_wrapped:
  mvn x11, x8                 ; itracebuffer.c:44     headroom = current_head - current_tail - 1;
.Lcompute_final_headroom:
  add x10, x10, x11           ; itracebuffer.c:0
.Lcheck_headroom:
  cmp x10, x20                ; itracebuffer.c:45   if (headroom < size)
  b.hs .Lsufficient_headroom
  add x8, x19, 0x10           ; itracebuffer.c:47     self->lost++;
  mov w9, 1                   ; itracebuffer.c:0
  ldaddal x9, x8, [x8]        ; itracebuffer.c:47     self->lost++;
  b .Lbeach
.Lsufficient_headroom:
  add x10, x8, x20            ; itracebuffer.c:0
  udiv x11, x10, x9
  msub x24, x11, x9, x10
  cmp x24, x8                 ; itracebuffer.c:51   if (next_tail > current_tail)
  b.ls .Lcopy_with_wrap
  add x8, x19, x8             ; itracebuffer.c:53     itrace_memcpy (self->data + current_tail, data, size);
  add x0, x8, 0x20
  mov x1, x21
  mov x2, x20
  b .Ldo_memcpy
.Lcopy_with_wrap:
  ldr x9, [x19, 0x18]         ; itracebuffer.c:57     const size_t first_chunk_size = self->capacity - current_tail; ; 0xed
  sub x22, x9, x8
  add x23, x19, 0x20          ; itracebuffer.c:58     itrace_memcpy (self->data + current_tail, data, first_chunk_size);
  add x0, x23, x8
  mov x1, x21
  mov x2, x22
  bl _itrace_memcpy
  add x1, x21, x22            ; itracebuffer.c:59     itrace_memcpy (self->data, data + first_chunk_size, size - first_chunk_size);
  sub x2, x20, x22
  mov x0, x23
.Ldo_memcpy:
  bl _itrace_memcpy           ; itracebuffer.c:0
  add x8, x19, 8              ; itracebuffer.c:62   atomic_store_explicit (&self->tail, next_tail, memory_order_release);
  stlr x24, [x8]
.Lbeach:
  ldr x0, [x27, 0x80]
  msr nzcv, x0

  ldp x29, x30, [x27, 0x70]   ; itracebuffer.c:63 }
  ldp x1, x0, [x27, 0x60]
  ldp x8, x2, [x27, 0x50]
  ldp x10, x9, [x27, 0x40]
  ldp x12, x11, [x27, 0x30]
  ldp x20, x19, [x27, 0x20]
  ldp x22, x21, [x27, 0x10]
  ldp x24, x23, [x27], 0x90

  ret

_itrace_memcpy:
  lsr x8, x2, 3               ; itracebuffer.c:109 { ; arg3
  cbz x8, .Lbeach2            ; itracebuffer.c:112   for (size_t i = 0; i != n / sizeof (uint64_t); i++)
.Lagain:
  ldr x9, [x1], 8             ; itracebuffer.c:113     d[i] = s[i]; ; 0xdb ; arg2
  str x9, [x0], 8             ; arg1
  sub x8, x8, 1               ; itracebuffer.c:112   for (size_t i = 0; i != n / sizeof (uint64_t); i++)
  cbnz x8, .Lagain
.Lbeach2:
  ret                         ; itracebuffer.c:114 }
