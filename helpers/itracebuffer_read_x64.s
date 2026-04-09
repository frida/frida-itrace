.intel_syntax noprefix
.text

# Hand-crafted x86_64 buffer read, derived from the compiler output of
# itracebuffer.c's itrace_buffer_read(). Unlike the write side this runs
# as a normal function (not inside Stalker blocks), so it follows the
# System V AMD64 ABI and may clobber caller-saved registers freely.
#
# Prototype: uint64_t buffer_read(ITraceBuffer *self, void *data, uint64_t size)
#
# The itrace_memcpy is word-at-a-time (8 bytes), matching the ARM64 version.

_itrace_buffer_read:
  push rbx
  push r12
  push r13
  push r14
  push r15

  mov r12, rdi                          # r12 = self
  mov r13, rsi                          # r13 = data
  mov r14, rdx                          # r14 = size

  mov r15, [r12]                        # r15 = current_head (relaxed)
  mov rbx, [r12 + 0x08]               # rbx = current_tail (acquire — x86 TSO)

  cmp rbx, r15                          # if (current_tail == current_head)
  jne .Lnot_empty
  xor eax, eax                          # return 0
  jmp .Lbeach

.Lnot_empty:
  ja .Lstraight                         # tail > head => no wrap

  # Wrapped case: available = (capacity - head) + tail
  mov rcx, [r12 + 0x18]               # rcx = capacity
  mov rax, rcx
  sub rax, r15                          # capacity - head
  add rax, rbx                          # + tail = available

  cmp rax, r14                          # n = min(available, size)
  cmovae rax, r14
  mov rbx, rax                          # rbx = n

  # first_chunk = min(capacity - head, n)
  sub rcx, r15                          # rcx = capacity - head
  cmp rcx, rbx
  cmovae rcx, rbx                      # rcx = first_chunk

  # memcpy(data, self->data + head, first_chunk)
  push rcx
  xor edx, edx
  mov rdi, rcx
  shr rdi, 3
  je .Lfirst_done
  lea r8, [r12 + r15 + 0x20]
.Lfirst_loop:
  mov rax, [r8 + rdx*8]
  mov [r13 + rdx*8], rax
  add rdx, 1
  cmp rdx, rdi
  jne .Lfirst_loop
.Lfirst_done:
  pop rcx

  # memcpy(data + first_chunk, self->data, n - first_chunk)
  mov rdi, rbx
  sub rdi, rcx
  shr rdi, 3
  je .Lupdate_head
  xor edx, edx
  lea r8, [r13 + rcx]
.Lsecond_loop:
  mov rax, [r12 + rdx*8 + 0x20]
  mov [r8 + rdx*8], rax
  add rdx, 1
  cmp rdx, rdi
  jne .Lsecond_loop
  jmp .Lupdate_head

.Lstraight:
  # available = tail - head
  mov rax, rbx
  sub rax, r15

  cmp rax, r14                          # n = min(available, size)
  cmovae rax, r14
  mov rbx, rax                          # rbx = n

  # memcpy(data, self->data + head, n)
  mov rdi, rbx
  shr rdi, 3
  je .Lupdate_head
  xor edx, edx
  lea r8, [r12 + r15 + 0x20]
.Lstraight_loop:
  mov rax, [r8 + rdx*8]
  mov [r13 + rdx*8], rax
  add rdx, 1
  cmp rdx, rdi
  jne .Lstraight_loop

.Lupdate_head:
  # new_head = (head + n) % capacity
  lea rax, [r15 + rbx]
  xor edx, edx
  div qword ptr [r12 + 0x18]
  mov [r12], rdx                        # store-release (x86 TSO)

  mov rax, rbx                          # return n

.Lbeach:
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbx
  ret
