.intel_syntax noprefix
.text

# Hand-crafted x86_64 buffer write, derived from the compiler output of
# itracebuffer.c's itrace_buffer_write(). Rewritten so that no CPU flags
# or general-purpose registers are clobbered. All temporaries are saved to
# and restored from session->stack[], using only MOV (which never touches
# RFLAGS). Flags are captured with LAHF+SETO and restored with ADD+SAHF.
#
# r15 = session pointer (SCRATCH_REG_TOP).
# Called via CALL; red zone skipped by caller.
#
# Session struct offsets (x86_64, saved_regs[2], scratch_regs[4]):
#   buffer:       0x08
#   pending_size: 0x10
#   stack[0]:     0x28
#   log_buf:      0x248

_itrace_buffer_write:
  mov [r15 + 0x28], rax                # stack[0]
  mov [r15 + 0x30], rcx                # stack[1]
  mov [r15 + 0x38], rdx                # stack[2]
  mov [r15 + 0x40], rsi                # stack[3]
  mov [r15 + 0x48], rdi                # stack[4]
  mov [r15 + 0x50], r8                 # stack[5]
  mov [r15 + 0x58], r9                 # stack[6]
  mov [r15 + 0x60], r10                # stack[7]
  mov [r15 + 0x68], r11                # stack[8]

  lahf
  seto al
  mov [r15 + 0x70], rax                # stack[9] = flags

  mov rdi, [r15 + 0x08]                # rdi = session->buffer
  lea rsi, [r15 + 0x248]               # rsi = session->log_buf
  mov rcx, [r15 + 0x10]                # rcx = session->pending_size

  mov r10, [rdi + 0x08]                # r10 = current_tail (relaxed)
  mov r8, [rdi + 0x18]                 # r8 = capacity
  mov rax, [rdi]                        # rax = current_head (acquire — x86 TSO)
  cmp r10, rax                          # itracebuffer.c:39
  je .Lempty
  cmp rax, r10                          # itracebuffer.c:41
  jb .Lhead_before_tail
  sub rax, 1                            # itracebuffer.c:44  headroom = head - tail - 1
  sub rax, r10
  jmp .Lcheck_headroom
.Lempty:
  mov rax, r8                           # itracebuffer.c:40  headroom = capacity - 1
  sub rax, 1
  jmp .Lcheck_headroom
.Lhead_before_tail:
  mov rdx, [rdi + 0x18]                # itracebuffer.c:42  headroom = cap + head - tail - 1
  lea rax, [rax + rdx - 1]
  sub rax, r10
.Lcheck_headroom:
  cmp rax, rcx                          # itracebuffer.c:45  if (headroom < size)
  jb .Llost

  lea rax, [r10 + rcx]                 # itracebuffer.c:102 next_tail = (tail+size) % cap
  xor edx, edx
  div r8                                # rdx = next_tail
  cmp r10, rdx                          # itracebuffer.c:51  if (next_tail > current_tail)
  jae .Lcopy_with_wrap

  mov r11, rcx                          # itracebuffer.c:53  straight memcpy
  shr r11, 3
  je .Lstore_tail
  xor eax, eax
  lea r8, [rdi + r10]
.Lstraight_loop:
  mov r9, [rsi + rax*8]
  mov [r8 + rax*8 + 0x20], r9
  add rax, 1
  cmp rax, r11
  jne .Lstraight_loop
  jmp .Lstore_tail

.Lcopy_with_wrap:
  mov r11, [rdi + 0x18]                # itracebuffer.c:57  first_chunk = cap - tail
  sub r11, r10

  mov rax, r11                          # itracebuffer.c:58  memcpy part 1
  shr rax, 3
  je .Lwrap_second_part
  xor r9d, r9d
  lea r8, [rdi + r10]
.Lwrap_first_loop:
  mov rcx, [rsi + r9*8]
  mov [r8 + r9*8 + 0x20], rcx
  add r9, 1
  cmp r9, rax
  jne .Lwrap_first_loop

.Lwrap_second_part:
  mov rcx, [r15 + 0x10]                # itracebuffer.c:59  memcpy part 2
  sub rcx, r11                          # size - first_chunk
  shr rcx, 3
  je .Lstore_tail
  xor eax, eax
  lea r8, [rsi + r11]
.Lwrap_second_loop:
  mov r9, [r8 + rax*8]
  mov [rdi + rax*8 + 0x20], r9
  add rax, 1
  cmp rax, rcx
  jne .Lwrap_second_loop

.Lstore_tail:
  mov [rdi + 0x08], rdx                # itracebuffer.c:62  store-release (x86 TSO)
  jmp .Lbeach

.Llost:
  lock add qword ptr [rdi + 0x10], 1   # itracebuffer.c:47  self->lost++

.Lbeach:
  mov rax, [r15 + 0x70]                # restore flags
  add al, 0x7f                          # restore OF
  sahf                                  # restore SF, ZF, AF, PF, CF

  mov r11, [r15 + 0x68]
  mov r10, [r15 + 0x60]
  mov r9, [r15 + 0x58]
  mov r8, [r15 + 0x50]
  mov rdi, [r15 + 0x48]
  mov rsi, [r15 + 0x40]
  mov rdx, [r15 + 0x38]
  mov rcx, [r15 + 0x30]
  mov rax, [r15 + 0x28]

  ret
