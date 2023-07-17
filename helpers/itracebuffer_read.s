.text
.align 2

_itrace_buffer_read:
  stp x24, x23, [sp, -0x40]!  ; itracebuffer.c:69 {
  stp x22, x21, [sp, 0x10]
  stp x20, x19, [sp, 0x20]
  stp x29, x30, [sp, 0x30]
  add x29, sp, 0x30
  ldr x24, [x0]               ; itracebuffer.c:70   const size_t current_head = atomic_load_explicit (&self->head, memory_order_relaxed); ; 0xda ; arg1
  add x8, x0, 8               ; itracebuffer.c:71   const size_t current_tail = atomic_load_explicit (&self->tail, memory_order_acquire); ; arg1
  ldapr x8, [x8]
  subs x8, x8, x24            ; itracebuffer.c:73   if (current_tail == current_head)
  b.ne .Lnot_empty
  mov x20, 0                  ; itracebuffer.c:0
  b .Lbeach
.Lnot_empty:
  mov x21, x1                 ; arg2
  mov x19, x0                 ; arg1
  b.ls .Lcopy_with_wrap       ; itracebuffer.c:76   size_t available = (current_tail > current_head)
  cmp x8, x2                  ; itracebuffer.c:80   size_t n = MIN (available, size); ; arg3
  csel x20, x8, x2, lo
  add x8, x19, x24            ; itracebuffer.c:83     itrace_memcpy (data, self->data + current_head, n);
  add x1, x8, 0x20
  mov x0, x21
  mov x2, x20
  b .Ldo_memcpy               ; itracebuffer.c:0
.Lcopy_with_wrap:
  ldr x9, [x19, 0x18]         ; itracebuffer.c:78       : (self->capacity - current_head) + current_tail; ; 0xed
  add x8, x8, x9
  cmp x8, x2                  ; itracebuffer.c:80   size_t n = MIN (available, size); ; arg3
  csel x20, x8, x2, lo
  sub x22, x9, x24            ; itracebuffer.c:87     const size_t first_chunk_size = self->capacity - current_head;
  add x23, x19, 0x20          ; itracebuffer.c:88     itrace_memcpy (data, self->data + current_head, first_chunk_size);
  add x1, x23, x24
  mov x0, x21
  mov x2, x22
  ldr x30, =0xffdebc9a78563412
  blr x30
  add x0, x21, x22            ; itracebuffer.c:89     itrace_memcpy (data + first_chunk_size, self->data, n - first_chunk_size);
  sub x2, x20, x22
  mov x1, x23
.Ldo_memcpy:
  ldr x30, =0xffdebc9a78563412
  blr x30
  add x8, x20, x24            ; itracebuffer.c:102   return (cursor + amount) % self->capacity;
  ldr x9, [x19, 0x18]         ; 0xed
  udiv x10, x8, x9
  msub x8, x10, x9, x8
  stlr x8, [x19]              ; itracebuffer.c:92   atomic_store_explicit (&self->head, itrace_buffer_increment (self, current_head, n), memory_order_release);
.Lbeach:
  mov x0, x20                 ; itracebuffer.c:95 }
  ldp x29, x30, [sp, 0x30]
  ldp x20, x19, [sp, 0x20]
  ldp x22, x21, [sp, 0x10]
  ldp x24, x23, [sp], 0x40
  ret
