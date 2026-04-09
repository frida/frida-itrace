export const code = `#line 2 "backend.ts"
#include <string.h>
#include <gum/gummodulemap.h>
#include <gum/gumstalker.h>

#if defined (HAVE_ARM64)

# define RED_ZONE_SIZE 128

# define SCRATCH_REG_BOTTOM ARM64_REG_X21
# define SCRATCH_REG_TOP ARM64_REG_X28

/* dmb ish — full barrier, inner shareable domain */
# define memory_barrier() __asm__ volatile (".int 0xd5033bbf")

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8

# define RED_ZONE_SIZE 128

# define SCRATCH_REG_BOTTOM X86_REG_R12
# define SCRATCH_REG_TOP X86_REG_R15

/* x86_64 TSO makes a compiler barrier sufficient */
# define memory_barrier() __asm__ volatile ("")

#else
# error "Unsupported architecture"
#endif

#define SCRATCH_REG_INDEX(r) ((r) - SCRATCH_REG_BOTTOM)
#define SCRATCH_REG_OFFSET(r) (SCRATCH_REG_INDEX (r) * 8)

#define ITRACE_EVENT_COMPILE 1
#define ITRACE_EVENT_START   2
#define ITRACE_EVENT_END     3
#define ITRACE_EVENT_PANIC   4

typedef enum _ITraceState ITraceState;
typedef struct _ITraceSession ITraceSession;
typedef struct _ITraceBuffer ITraceBuffer;
typedef struct _ITraceBlockWrite ITraceBlockWrite;

enum _ITraceState
{
  ITRACE_STATE_CREATED,
  ITRACE_STATE_STARTING,
  ITRACE_STATE_STARTED,
  ITRACE_STATE_ENDED,
};

struct _ITraceBuffer
{
  guint64 head;
  guint64 tail;
  guint64 lost;
  guint64 capacity;
  guint8 data[];
};

struct _ITraceBlockWrite
{
  guint32 block_offset;
  guint32 reg_index;
};

struct _ITraceSession
{
  ITraceState state;
  ITraceBuffer * buffer;
  guint64 pending_size;
  guint64 saved_regs[2];
  guint64 stack[64];
  guint64 scratch_regs[SCRATCH_REG_TOP - SCRATCH_REG_BOTTOM + 1];
  guint64 log_buf[1969];
  GumAddress write_impl;
  GumModuleMap * modules;
};

extern ITraceSession session;
extern void * end_address;

extern void on_end (void);

static void on_first_block_hit (GumCpuContext * cpu_context, gpointer user_data);
static void on_end_instruction_hit (GumCpuContext * cpu_context, gpointer user_data);

#if defined (HAVE_ARM64)

static arm64_reg pick_scratch_register (cs_regs regs_read, uint8_t num_regs_read, cs_regs regs_written, uint8_t num_regs_written);
static arm64_reg register_to_full_size_register (arm64_reg reg);
static void emit_scratch_register_restore (GumArm64Writer * cw, arm64_reg reg);
static void emit_buffer_write_impl (GumArm64Writer * cw);

#elif defined (HAVE_I386)

static x86_reg pick_scratch_register (cs_regs regs_read, uint8_t num_regs_read, cs_regs regs_written, uint8_t num_regs_written);
static x86_reg register_to_full_size_register (x86_reg reg);
static void emit_scratch_register_restore (GumX86Writer * cw, x86_reg reg);
static void emit_buffer_write_impl (GumX86Writer * cw);

#endif

static void emit_event (guint32 type, const guint8 * payload, gsize payload_size);
static void write_reg_spec (guint8 ** p, const gchar * name, guint8 reg_size);
static void format_reg_name (gchar * name, gchar prefix, guint index);
static void itrace_buffer_write (ITraceBuffer * buffer, const guint8 * data, gsize size);

static void panic (const char * format, ...);

void
init (void)
{
  session.modules = gum_module_map_new ();
}

void
finalize (void)
{
  g_object_unref (session.modules);
}

void
transform (GumStalkerIterator * iterator,
           GumStalkerOutput * output,
           gpointer user_data)
{
#if defined (HAVE_ARM64)
  GumArm64Writer * cw = output->writer.arm64;
#else
  GumX86Writer * cw = output->writer.x86;
#endif
  csh capstone = gum_stalker_iterator_get_capstone (iterator);

  guint num_instructions = 0;
  GumAddress block_address = 0;
#if defined (HAVE_ARM64)
  guint log_buf_offset = 16;
  arm64_reg prev_session_reg = ARM64_REG_INVALID;
#else
  guint log_buf_offset = 8;
  x86_reg prev_session_reg = X86_REG_INVALID;
#endif

  GArray * writes = g_array_new (FALSE, FALSE, sizeof (ITraceBlockWrite));

  cs_insn * insn;
  while (gum_stalker_iterator_next (iterator, &insn))
  {
    num_instructions++;

    gboolean is_first_in_block = num_instructions == 1;
    gboolean is_last_in_block = cs_insn_group (capstone, insn, CS_GRP_JUMP) || cs_insn_group (capstone, insn, CS_GRP_RET);

    if (is_first_in_block)
      block_address = insn->address;

    if (session.state == ITRACE_STATE_CREATED)
    {
      session.state = ITRACE_STATE_STARTING;
      gum_stalker_iterator_put_callout (iterator, on_first_block_hit, NULL, NULL);
    }

    if (end_address != NULL && GUM_ADDRESS (end_address) == insn->address)
    {
      gum_stalker_iterator_put_callout (iterator, on_end_instruction_hit, NULL, NULL);
    }

    cs_regs regs_read, regs_written;
    uint8_t num_regs_read, num_regs_written;
    cs_regs_access (capstone, insn, regs_read, &num_regs_read, regs_written, &num_regs_written);
    for (uint8_t i = 0; i != num_regs_read; i++)
      regs_read[i] = register_to_full_size_register (regs_read[i]);
    for (uint8_t i = 0; i != num_regs_written; i++)
      regs_written[i] = register_to_full_size_register (regs_written[i]);

#if defined (HAVE_ARM64)
    arm64_reg session_reg = is_last_in_block
        ? SCRATCH_REG_TOP
        : pick_scratch_register (regs_read, num_regs_read, regs_written, num_regs_written);

    if (session_reg != prev_session_reg)
    {
      if (prev_session_reg != ARM64_REG_INVALID)
        gum_arm64_writer_put_mov_reg_reg (cw, session_reg, prev_session_reg);
      else
        gum_arm64_writer_put_ldr_reg_address (cw, session_reg, GUM_ADDRESS (&session));
    }

    if (prev_session_reg != ARM64_REG_INVALID && session_reg != prev_session_reg)
      emit_scratch_register_restore (cw, prev_session_reg);

    if (is_first_in_block)
    {
      gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_LR, session_reg, G_STRUCT_OFFSET (ITraceSession, log_buf) + 8);
      ITraceBlockWrite lr_write = { insn->address - block_address, 33 };
      g_array_append_val (writes, lr_write);
    }

    if (is_last_in_block)
    {
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X27, ARM64_REG_LR,
          session_reg, G_STRUCT_OFFSET (ITraceSession, saved_regs), GUM_INDEX_SIGNED_OFFSET);
      gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X27, block_address);
      gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X27, session_reg, G_STRUCT_OFFSET (ITraceSession, log_buf));
      gum_arm64_writer_put_ldr_reg_u64 (cw, ARM64_REG_X27, log_buf_offset);
      gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X27, session_reg, G_STRUCT_OFFSET (ITraceSession, pending_size));

      if (session.write_impl == 0 ||
          !gum_arm64_writer_can_branch_directly_between (cw, cw->pc, session.write_impl))
      {
        gconstpointer after_write_impl = cw->code + 1;

        gum_arm64_writer_put_b_label (cw, after_write_impl);

        session.write_impl = cw->pc;
        emit_buffer_write_impl (cw);

        gum_arm64_writer_put_label (cw, after_write_impl);
      }

      gum_arm64_writer_put_bl_imm (cw, session.write_impl);

      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X27, ARM64_REG_LR,
          session_reg, G_STRUCT_OFFSET (ITraceSession, saved_regs), GUM_INDEX_SIGNED_OFFSET);

      emit_scratch_register_restore (cw, session_reg);
    }
#else
    x86_reg session_reg = is_last_in_block
        ? SCRATCH_REG_TOP
        : pick_scratch_register (regs_read, num_regs_read, regs_written, num_regs_written);

    if (session_reg != prev_session_reg)
    {
      if (prev_session_reg != X86_REG_INVALID)
        gum_x86_writer_put_mov_reg_reg (cw, session_reg, prev_session_reg);
      else
        gum_x86_writer_put_mov_reg_address (cw, session_reg, GUM_ADDRESS (&session));
    }

    if (prev_session_reg != X86_REG_INVALID && session_reg != prev_session_reg)
      emit_scratch_register_restore (cw, prev_session_reg);

    if (is_last_in_block)
    {
      gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, session_reg,
          G_STRUCT_OFFSET (ITraceSession, saved_regs), X86_REG_RAX);

      gum_x86_writer_put_mov_reg_address (cw, X86_REG_RAX, block_address);
      gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, session_reg,
          G_STRUCT_OFFSET (ITraceSession, log_buf), X86_REG_RAX);

      gum_x86_writer_put_mov_reg_address (cw, X86_REG_RAX, (GumAddress) log_buf_offset);
      gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, session_reg,
          G_STRUCT_OFFSET (ITraceSession, pending_size), X86_REG_RAX);

      if (session.write_impl == 0)
      {
        gconstpointer after_write_impl = cw->code + 1;

        gum_x86_writer_put_jmp_near_label (cw, after_write_impl);

        session.write_impl = cw->pc;
        emit_buffer_write_impl (cw);

        gum_x86_writer_put_label (cw, after_write_impl);
      }

      gum_x86_writer_put_lea_reg_reg_offset (cw, X86_REG_RSP,
          X86_REG_RSP, -RED_ZONE_SIZE);
      gum_x86_writer_put_call_address (cw, session.write_impl);
      gum_x86_writer_put_lea_reg_reg_offset (cw, X86_REG_RSP,
          X86_REG_RSP, RED_ZONE_SIZE);

      gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, X86_REG_RAX, session_reg,
          G_STRUCT_OFFSET (ITraceSession, saved_regs));

      emit_scratch_register_restore (cw, session_reg);
    }
#endif

    gum_stalker_iterator_keep (iterator);

    if (is_last_in_block)
      continue;

    guint block_offset = (insn->address + insn->size) - block_address;

#if defined (HAVE_ARM64)
    for (uint8_t i = 0; i != num_regs_written; i++)
    {
      arm64_reg reg = regs_written[i];
      gboolean is_scratch_reg = reg >= SCRATCH_REG_BOTTOM && reg <= SCRATCH_REG_TOP;
      if (is_scratch_reg)
      {
        gum_arm64_writer_put_str_reg_reg_offset (cw, reg,
            session_reg, G_STRUCT_OFFSET (ITraceSession, scratch_regs) + SCRATCH_REG_OFFSET (reg));
      }
    }

    for (uint8_t i = 0; i != num_regs_written; i++)
    {
      arm64_reg reg = regs_written[i];

      guint cpu_reg_index;
      arm64_reg source_reg;
      gsize size;
      arm64_reg temp_reg = ARM64_REG_INVALID;

      if (reg == ARM64_REG_SP)
      {
        temp_reg = ARM64_REG_X0;

        cpu_reg_index = 1;
        source_reg = temp_reg;
        size = 8;
      }
      else if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
      {
        cpu_reg_index = 3 + (reg - ARM64_REG_X0);
        source_reg = reg;
        size = 8;
      }
      else if (reg == ARM64_REG_FP)
      {
        cpu_reg_index = 32;
        source_reg = reg;
        size = 8;
      }
      else if (reg == ARM64_REG_LR)
      {
        cpu_reg_index = 33;
        source_reg = reg;
        size = 8;
      }
      else if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31)
      {
        cpu_reg_index = 34 + (reg - ARM64_REG_Q0);
        source_reg = reg;
        size = 16;
      }
      else if (reg == ARM64_REG_NZCV)
      {
        temp_reg = ARM64_REG_X0;

        cpu_reg_index = 2;
        source_reg = temp_reg;
        size = 8;
      }
      else if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR)
      {
        continue;
      }
      else
      {
        panic ("Unhandled register: %s", cs_reg_name (capstone, reg));
        while (TRUE)
          ;
      }

      if (temp_reg != ARM64_REG_INVALID)
        gum_arm64_writer_put_str_reg_reg_offset (cw, temp_reg, session_reg, G_STRUCT_OFFSET (ITraceSession, saved_regs));

      if (reg == ARM64_REG_SP)
        gum_arm64_writer_put_mov_reg_reg (cw, temp_reg, ARM64_REG_SP);
      else if (reg == ARM64_REG_NZCV)
        gum_arm64_writer_put_mov_reg_nzcv (cw, temp_reg);

      gsize offset = G_STRUCT_OFFSET (ITraceSession, log_buf) + log_buf_offset;
      gsize alignment_delta = offset % size;
      if (alignment_delta != 0)
        offset += size - alignment_delta;
      // TODO: Handle large offsets
      gum_arm64_writer_put_str_reg_reg_offset (cw, source_reg, session_reg, offset);

      ITraceBlockWrite write = { block_offset, cpu_reg_index };
      g_array_append_val (writes, write);

      log_buf_offset += size;

      if (temp_reg != ARM64_REG_INVALID)
        gum_arm64_writer_put_ldr_reg_reg_offset (cw, temp_reg, session_reg, G_STRUCT_OFFSET (ITraceSession, saved_regs));
    }
#else
    for (uint8_t i = 0; i != num_regs_written; i++)
    {
      x86_reg reg = regs_written[i];
      if (reg >= SCRATCH_REG_BOTTOM && reg <= SCRATCH_REG_TOP)
      {
        gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, session_reg,
            G_STRUCT_OFFSET (ITraceSession, scratch_regs) + SCRATCH_REG_OFFSET (reg), reg);
      }
    }

    for (uint8_t i = 0; i != num_regs_written; i++)
    {
      x86_reg reg = regs_written[i];

      if (reg == X86_REG_EFLAGS || reg == X86_REG_RIP)
        continue;

      guint cpu_reg_index;

      switch (reg)
      {
        case X86_REG_R15: cpu_reg_index = 1; break;
        case X86_REG_R14: cpu_reg_index = 2; break;
        case X86_REG_R13: cpu_reg_index = 3; break;
        case X86_REG_R12: cpu_reg_index = 4; break;
        case X86_REG_R11: cpu_reg_index = 5; break;
        case X86_REG_R10: cpu_reg_index = 6; break;
        case X86_REG_R9:  cpu_reg_index = 7; break;
        case X86_REG_R8:  cpu_reg_index = 8; break;
        case X86_REG_RDI: cpu_reg_index = 9; break;
        case X86_REG_RSI: cpu_reg_index = 10; break;
        case X86_REG_RBP: cpu_reg_index = 11; break;
        case X86_REG_RSP: cpu_reg_index = 12; break;
        case X86_REG_RBX: cpu_reg_index = 13; break;
        case X86_REG_RDX: cpu_reg_index = 14; break;
        case X86_REG_RCX: cpu_reg_index = 15; break;
        case X86_REG_RAX: cpu_reg_index = 16; break;
        default: continue;
      }

      gsize offset = G_STRUCT_OFFSET (ITraceSession, log_buf) + log_buf_offset;
      gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, session_reg, offset, reg);

      ITraceBlockWrite write = { block_offset, cpu_reg_index };
      g_array_append_val (writes, write);

      log_buf_offset += 8;
    }
#endif

    prev_session_reg = session_reg;
  }

  guint32 block_size = (insn->address + insn->size) - block_address;
#if defined (HAVE_ARM64)
  guint32 compiled_code_size = gum_arm64_writer_offset (cw);
#else
  guint32 compiled_code_size = gum_x86_writer_offset (cw);
#endif
  GumAddress compiled_address = cw->pc - compiled_code_size;

  GumModule * m = gum_module_map_find (session.modules, block_address);

  const gchar * module_path = NULL;
  GumAddress module_base = 0;
  gchar * name_buf = NULL;

  if (m != NULL)
  {
    const GumMemoryRange * range = gum_module_get_range (m);
    module_base = range->base_address;
    module_path = gum_module_get_path (m);
    name_buf = g_strdup_printf ("%s!0x%x",
        gum_module_get_name (m),
        (guint) (block_address - module_base));
  }
  else
  {
    name_buf = g_strdup_printf ("0x%" G_GINT64_MODIFIER "x", block_address);
  }

  guint16 name_size = (guint16) strlen (name_buf);
  guint16 module_path_size = (module_path != NULL)
      ? (guint16) strlen (module_path)
      : 0;

  gsize writes_size = writes->len * sizeof (ITraceBlockWrite);
  gsize payload_size =
      8 +                  /* block_address */
      4 +                  /* block_size */
      4 +                  /* record_size */
      2 +                  /* num_writes */
      2 +                  /* name_size */
      8 +                  /* compiled_address */
      4 +                  /* compiled_size */
      8 +                  /* module_base */
      2 +                  /* module_path_size */
      2 +                  /* reserved */
      writes_size +
      name_size +
      module_path_size +
      block_size;

  guint8 * buf = (guint8 *) session.log_buf;
  guint8 * p = buf;

  memset (p, 0, 8); p += 8;
  guint32 event_type = ITRACE_EVENT_COMPILE;
  memcpy (p, &event_type, 4); p += 4;
  guint32 ps = (guint32) payload_size;
  memcpy (p, &ps, 4); p += 4;

  memcpy (p, &block_address, 8); p += 8;
  memcpy (p, &block_size, 4); p += 4;
  guint32 record_size = log_buf_offset;
  memcpy (p, &record_size, 4); p += 4;
  guint16 nw = (guint16) writes->len;
  memcpy (p, &nw, 2); p += 2;
  memcpy (p, &name_size, 2); p += 2;
  memcpy (p, &compiled_address, 8); p += 8;
  memcpy (p, &compiled_code_size, 4); p += 4;
  memcpy (p, &module_base, 8); p += 8;
  memcpy (p, &module_path_size, 2); p += 2;
  guint16 reserved = 0;
  memcpy (p, &reserved, 2); p += 2;

  memcpy (p, writes->data, writes_size); p += writes_size;

  memcpy (p, name_buf, name_size); p += name_size;
  if (module_path_size > 0)
  {
    memcpy (p, module_path, module_path_size);
    p += module_path_size;
  }

  memcpy (p, (const guint8 *) (gsize) block_address, block_size);
  p += block_size;

  itrace_buffer_write (session.buffer, buf, 16 + payload_size);

  g_array_free (writes, TRUE);
  g_free (name_buf);
}

static void
on_first_block_hit (GumCpuContext * cpu_context,
                    gpointer user_data)
{
  if (session.state != ITRACE_STATE_STARTING)
    return;
  session.state = ITRACE_STATE_STARTED;

#if defined (HAVE_ARM64)
  memcpy (session.scratch_regs,
      cpu_context->x + (SCRATCH_REG_BOTTOM - ARM64_REG_X0),
      sizeof (session.scratch_regs));

  guint32 num_regs =
      1 +                              /* pc */
      1 +                              /* sp */
      1 +                              /* nzcv */
      G_N_ELEMENTS (cpu_context->x) +  /* x0-x28 */
      1 +                              /* fp */
      1 +                              /* lr */
      G_N_ELEMENTS (cpu_context->v);   /* v0-v31 */
#else
  session.scratch_regs[SCRATCH_REG_INDEX (X86_REG_R12)] = cpu_context->r12;
  session.scratch_regs[SCRATCH_REG_INDEX (X86_REG_R13)] = cpu_context->r13;
  session.scratch_regs[SCRATCH_REG_INDEX (X86_REG_R14)] = cpu_context->r14;
  session.scratch_regs[SCRATCH_REG_INDEX (X86_REG_R15)] = cpu_context->r15;

  guint32 num_regs = 17;
#endif
  guint32 context_size = sizeof (GumCpuContext);

  gsize payload_size = 4 + 4 + (num_regs * 8) + context_size;

  guint8 * buf = (guint8 *) session.log_buf;
  guint8 * p = buf;

  memset (p, 0, 8); p += 8;
  guint32 event_type = ITRACE_EVENT_START;
  memcpy (p, &event_type, 4); p += 4;
  guint32 ps = (guint32) payload_size;
  memcpy (p, &ps, 4); p += 4;

  memcpy (p, &num_regs, 4); p += 4;
  memcpy (p, &context_size, 4); p += 4;

#if defined (HAVE_ARM64)
  write_reg_spec (&p, "pc", sizeof (cpu_context->pc));
  write_reg_spec (&p, "sp", sizeof (cpu_context->sp));
  write_reg_spec (&p, "nzcv", sizeof (cpu_context->nzcv));

  for (guint i = 0; i != G_N_ELEMENTS (cpu_context->x); i++)
  {
    gchar name[4];
    format_reg_name (name, 'x', i);
    write_reg_spec (&p, name, sizeof (cpu_context->x[0]));
  }

  write_reg_spec (&p, "fp", sizeof (cpu_context->fp));
  write_reg_spec (&p, "lr", sizeof (cpu_context->lr));

  for (guint i = 0; i != G_N_ELEMENTS (cpu_context->v); i++)
  {
    gchar name[4];
    format_reg_name (name, 'v', i);
    write_reg_spec (&p, name, sizeof (cpu_context->v[0]));
  }
#else
  write_reg_spec (&p, "rip", 8);
  write_reg_spec (&p, "r15", 8);
  write_reg_spec (&p, "r14", 8);
  write_reg_spec (&p, "r13", 8);
  write_reg_spec (&p, "r12", 8);
  write_reg_spec (&p, "r11", 8);
  write_reg_spec (&p, "r10", 8);
  write_reg_spec (&p, "r9", 8);
  write_reg_spec (&p, "r8", 8);
  write_reg_spec (&p, "rdi", 8);
  write_reg_spec (&p, "rsi", 8);
  write_reg_spec (&p, "rbp", 8);
  write_reg_spec (&p, "rsp", 8);
  write_reg_spec (&p, "rbx", 8);
  write_reg_spec (&p, "rdx", 8);
  write_reg_spec (&p, "rcx", 8);
  write_reg_spec (&p, "rax", 8);
#endif

  memcpy (p, cpu_context, context_size);
  p += context_size;

  itrace_buffer_write (session.buffer, buf, 16 + payload_size);
}

static void
on_end_instruction_hit (GumCpuContext * cpu_context,
                        gpointer user_data)
{
  if (session.state != ITRACE_STATE_STARTED)
    return;
  session.state = ITRACE_STATE_ENDED;

  emit_event (ITRACE_EVENT_END, NULL, 0);

  on_end ();
}

static void
panic (const char * format,
       ...)
{
  va_list args;
  va_start (args, format);
  gchar * message = g_strdup_vprintf (format, args);
  va_end (args);

  emit_event (ITRACE_EVENT_PANIC, (const guint8 *) message, strlen (message));

  g_free (message);
}

#if defined (HAVE_ARM64)

static arm64_reg
pick_scratch_register (cs_regs regs_read,
                       uint8_t num_regs_read,
                       cs_regs regs_written,
                       uint8_t num_regs_written)
{
  arm64_reg candidate;

  for (candidate = SCRATCH_REG_TOP; candidate != SCRATCH_REG_BOTTOM - 1; candidate--)
  {
    gboolean available = TRUE;

    for (uint8_t i = 0; i != num_regs_read; i++)
    {
      if (regs_read[i] == candidate)
      {
        available = FALSE;
        break;
      }
    }
    if (!available)
      continue;

    for (uint8_t i = 0; i != num_regs_written; i++)
    {
      if (regs_written[i] == candidate)
      {
        available = FALSE;
        break;
      }
    }
    if (!available)
      continue;

    break;
  }

  return candidate;
}

static arm64_reg
register_to_full_size_register (arm64_reg reg)
{
  switch (reg)
  {
    case ARM64_REG_SP:
    case ARM64_REG_FP:
    case ARM64_REG_LR:
    case ARM64_REG_NZCV:
    case ARM64_REG_XZR:
    case ARM64_REG_WZR:
      return reg;
  }

  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
    return reg;
  if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28)
    return ARM64_REG_X0 + (reg - ARM64_REG_W0);
  if (reg == ARM64_REG_W29)
    return ARM64_REG_FP;
  if (reg == ARM64_REG_W30)
    return ARM64_REG_LR;

  if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31)
    return reg;
  if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_V0);
  if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_D0);
  if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_S0);
  if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_H0);
  if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31)
    return ARM64_REG_Q0 + (reg - ARM64_REG_B0);

  return reg;
}

static void
emit_scratch_register_restore (GumArm64Writer * cw,
                               arm64_reg reg)
{
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, reg,
      reg, G_STRUCT_OFFSET (ITraceSession, scratch_regs) + SCRATCH_REG_OFFSET (reg));
}

static void
emit_buffer_write_impl (GumArm64Writer * cw)
{
  static const guint32 write_impl[] = {
    0x9108a39bU, /* add x27, x28, 0x228         */

    0xa9b75f78U, /* stp x24, x23, [x27, -0x90]! */
    0xa9015776U, /* stp x22, x21, [x27, 0x10]   */
    0xa9024f74U, /* stp x20, x19, [x27, 0x20]   */
    0xa9032f6cU, /* stp x12, x11, [x27, 0x30]   */
    0xa904276aU, /* stp x10, x9, [x27, 0x40]    */
    0xa9050b68U, /* stp x8, x2, [x27, 0x50]     */
    0xa9060361U, /* stp x1, x0, [x27, 0x60]     */
    0xa9077b7dU, /* stp x29, x30, [x27, 0x70]   */
    0x9101c37dU, /* add x29, x27, 0x70          */

    0xd53b4200U, /* mrs x0, nzcv                */
    0xf9004360U, /* str x0, [x27, 0x80]         */

    0xf9400793U, /* ldr x19, [x28, 8]           */

    0xf9400b94U, /* ldr x20, [x28, 0x10]        */
    0x9109a395U, /* add x21, x28, 0x268         */

    0xf9400668U, /* ldr x8, [x19, 8]            */
    0xf9400e69U, /* ldr x9, [x19, 0x18]         */
    0xc8dffe6aU, /* ldar x10, [x19]             */
    0xeb08015fU, /* cmp x10, x8                 */
    0x54000081U, /* b.ne not_empty              */
    0xf9400e6aU, /* ldr x10, [x19, 0x18]        */
    0xd100054aU, /* sub x10, x10, 1             */
    0x14000008U, /* b check_headroom            */
    /* not_empty:                               */
    0x540000a2U, /* b.hs tail_has_wrapped       */
    0xf9400e6bU, /* ldr x11, [x19, 0x18]        */
    0xaa2803ecU, /* mvn x12, x8                 */
    0x8b0c014aU, /* add x10, x10, x12           */
    0x14000002U, /* b compute_final_headroom    */
    /* tail_has_wrapped:                        */
    0xaa2803ebU, /* mvn x11, x8                 */
    /* compute_final_headroom:                  */
    0x8b0b014aU, /* add x10, x10, x11           */
    /* check_headroom:                          */
    0xeb14015fU, /* cmp x10, x20                */
    0x540000e2U, /* b.hs sufficient_headroom    */
    0x91004268U, /* add x8, x19, 0x10           */
    /* retry:                                   */
    0xc85ffd09U, /* ldaxr x9, [x8]              */
    0x91000529U, /* add x9, x9, 1               */
    0xc80afd09U, /* stlxr w10, x9, [x8]         */
    0x35ffffaaU, /* cbnz w10, retry             */
    0x14000018U, /* b beach                     */
    /* sufficient_headroom:                     */
    0x8b14010aU, /* add x10, x8, x20            */
    0x9ac9094bU, /* udiv x11, x10, x9           */
    0x9b09a978U, /* msub x24, x11, x9, x10      */
    0xeb08031fU, /* cmp x24, x8                 */
    0x540000c9U, /* b.ls copy_with_wrap         */
    0x8b080268U, /* add x8, x19, x8             */
    0x91008100U, /* add x0, x8, 0x20            */
    0xaa1503e1U, /* mov x1, x21                 */
    0xaa1403e2U, /* mov x2, x20                 */
    0x1400000bU, /* b do_memcpy                 */
    /* copy_with_wrap:                          */
    0xf9400e69U, /* ldr x9, [x19, 0x18]         */
    0xcb080136U, /* sub x22, x9, x8             */
    0x91008277U, /* add x23, x19, 0x20          */
    0x8b0802e0U, /* add x0, x23, x8             */
    0xaa1503e1U, /* mov x1, x21                 */
    0xaa1603e2U, /* mov x2, x22                 */
    0x94000012U, /* bl itrace_memcpy            */
    0x8b1602a1U, /* add x1, x21, x22            */
    0xcb160282U, /* sub x2, x20, x22            */
    0xaa1703e0U, /* mov x0, x23                 */
    /* do_memcpy:                               */
    0x9400000eU, /* bl itrace_memcpy            */
    0x91002268U, /* add x8, x19, 8              */
    0xc89ffd18U, /* stlr x24, [x8]              */
    /* beach:                                   */
    0xf9404360U, /* ldr x0, [x27, 0x80]         */
    0xd51b4200U, /* msr nzcv, x0                */

    0xa9477b7dU, /* ldp x29, x30, [x27, 0x70]   */
    0xa9460361U, /* ldp x1, x0, [x27, 0x60]     */
    0xa9450b68U, /* ldp x8, x2, [x27, 0x50]     */
    0xa944276aU, /* ldp x10, x9, [x27, 0x40]    */
    0xa9432f6cU, /* ldp x12, x11, [x27, 0x30]   */
    0xa9424f74U, /* ldp x20, x19, [x27, 0x20]   */
    0xa9415776U, /* ldp x22, x21, [x27, 0x10]   */
    0xa8c95f78U, /* ldp x24, x23, [x27], 0x90   */

    0xd65f03c0U, /* ret                         */

    /* itrace_memcpy:                           */
    0xd343fc48U, /* lsr x8, x2, 3               */
    0xb40000a8U, /* cbz x8, beach2              */
    0xf8408429U, /* ldr x9, [x1], 8             */
    0xf8008409U, /* str x9, [x0], 8             */
    0xd1000508U, /* sub x8, x8, 1               */
    0xb5ffffa8U, /* cbnz x8, again              */
    /* beach2:                                  */
    0xd65f03c0U, /* ret                         */
  };

  gum_arm64_writer_put_bytes (cw, (const guint8 *) write_impl, sizeof (write_impl));
}

#elif defined (HAVE_I386)

static x86_reg
pick_scratch_register (cs_regs regs_read,
                       uint8_t num_regs_read,
                       cs_regs regs_written,
                       uint8_t num_regs_written)
{
  x86_reg candidate;

  for (candidate = SCRATCH_REG_TOP; candidate != SCRATCH_REG_BOTTOM - 1; candidate--)
  {
    gboolean available = TRUE;

    for (uint8_t i = 0; i != num_regs_read; i++)
    {
      if (regs_read[i] == candidate)
      {
        available = FALSE;
        break;
      }
    }
    if (!available)
      continue;

    for (uint8_t i = 0; i != num_regs_written; i++)
    {
      if (regs_written[i] == candidate)
      {
        available = FALSE;
        break;
      }
    }
    if (!available)
      continue;

    break;
  }

  return candidate;
}

static x86_reg
register_to_full_size_register (x86_reg reg)
{
  switch (reg)
  {
    case X86_REG_RAX: case X86_REG_RBX: case X86_REG_RCX: case X86_REG_RDX:
    case X86_REG_RSI: case X86_REG_RDI: case X86_REG_RSP: case X86_REG_RBP:
    case X86_REG_R8:  case X86_REG_R9:  case X86_REG_R10: case X86_REG_R11:
    case X86_REG_R12: case X86_REG_R13: case X86_REG_R14: case X86_REG_R15:
    case X86_REG_RIP: case X86_REG_EFLAGS:
      return reg;

    case X86_REG_EAX: return X86_REG_RAX;
    case X86_REG_EBX: return X86_REG_RBX;
    case X86_REG_ECX: return X86_REG_RCX;
    case X86_REG_EDX: return X86_REG_RDX;
    case X86_REG_ESI: return X86_REG_RSI;
    case X86_REG_EDI: return X86_REG_RDI;
    case X86_REG_ESP: return X86_REG_RSP;
    case X86_REG_EBP: return X86_REG_RBP;
    case X86_REG_EIP: return X86_REG_RIP;

    case X86_REG_AX: case X86_REG_AH: case X86_REG_AL: return X86_REG_RAX;
    case X86_REG_BX: case X86_REG_BH: case X86_REG_BL: return X86_REG_RBX;
    case X86_REG_CX: case X86_REG_CH: case X86_REG_CL: return X86_REG_RCX;
    case X86_REG_DX: case X86_REG_DH: case X86_REG_DL: return X86_REG_RDX;
    case X86_REG_SI: case X86_REG_SIL: return X86_REG_RSI;
    case X86_REG_DI: case X86_REG_DIL: return X86_REG_RDI;
    case X86_REG_SP: case X86_REG_SPL: return X86_REG_RSP;
    case X86_REG_BP: case X86_REG_BPL: return X86_REG_RBP;
    case X86_REG_IP: return X86_REG_RIP;

    case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  return X86_REG_R8;
    case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  return X86_REG_R9;
    case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return X86_REG_R10;
    case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return X86_REG_R11;
    case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return X86_REG_R12;
    case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return X86_REG_R13;
    case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return X86_REG_R14;
    case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return X86_REG_R15;

    default:
      return reg;
  }
}

static void
emit_scratch_register_restore (GumX86Writer * cw,
                               x86_reg reg)
{
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, reg,
      reg, G_STRUCT_OFFSET (ITraceSession, scratch_regs) + SCRATCH_REG_OFFSET (reg));
}

static void
emit_buffer_write_impl (GumX86Writer * cw)
{
  static const guint8 write_impl[] = {
    0x49, 0x89, 0x47, 0x28,             /* mov [r15+0x28], rax              */
    0x49, 0x89, 0x4f, 0x30,             /* mov [r15+0x30], rcx              */
    0x49, 0x89, 0x57, 0x38,             /* mov [r15+0x38], rdx              */
    0x49, 0x89, 0x77, 0x40,             /* mov [r15+0x40], rsi              */
    0x49, 0x89, 0x7f, 0x48,             /* mov [r15+0x48], rdi              */
    0x4d, 0x89, 0x47, 0x50,             /* mov [r15+0x50], r8               */
    0x4d, 0x89, 0x4f, 0x58,             /* mov [r15+0x58], r9               */
    0x4d, 0x89, 0x57, 0x60,             /* mov [r15+0x60], r10              */
    0x4d, 0x89, 0x5f, 0x68,             /* mov [r15+0x68], r11              */

    0x9f,                               /* lahf                             */
    0x0f, 0x90, 0xc0,                   /* seto al                          */
    0x49, 0x89, 0x47, 0x70,             /* mov [r15+0x70], rax              */

    0x49, 0x8b, 0x7f, 0x08,             /* mov rdi, [r15+0x08]              */
    0x49, 0x8d, 0xb7, 0x48, 0x02, 0x00, /* lea rsi, [r15+0x248]            */
    0x00,
    0x49, 0x8b, 0x4f, 0x10,             /* mov rcx, [r15+0x10]              */

    0x4c, 0x8b, 0x57, 0x08,             /* mov r10, [rdi+0x08]              */
    0x4c, 0x8b, 0x47, 0x18,             /* mov r8, [rdi+0x18]               */
    0x48, 0x8b, 0x07,                   /* mov rax, [rdi]                   */
    0x49, 0x39, 0xc2,                   /* cmp r10, rax                     */
    0x74, 0x0e,                         /* je empty                         */
    0x4c, 0x39, 0xd0,                   /* cmp rax, r10                     */
    0x72, 0x12,                         /* jb head_before_tail              */
    0x48, 0x83, 0xe8, 0x01,             /* sub rax, 1                       */
    0x4c, 0x29, 0xd0,                   /* sub rax, r10                     */
    0xeb, 0x15,                         /* jmp check_headroom               */
    /* empty:                                                               */
    0x4c, 0x89, 0xc0,                   /* mov rax, r8                      */
    0x48, 0x83, 0xe8, 0x01,             /* sub rax, 1                       */
    0xeb, 0x0c,                         /* jmp check_headroom               */
    /* head_before_tail:                                                    */
    0x48, 0x8b, 0x57, 0x18,             /* mov rdx, [rdi+0x18]              */
    0x48, 0x8d, 0x44, 0x10, 0xff,       /* lea rax, [rax+rdx-1]            */
    0x4c, 0x29, 0xd0,                   /* sub rax, r10                     */
    /* check_headroom:                                                      */
    0x48, 0x39, 0xc8,                   /* cmp rax, rcx                     */
    0x0f, 0x82, 0x85, 0x00, 0x00, 0x00, /* jb lost                         */

    0x49, 0x8d, 0x04, 0x0a,             /* lea rax, [r10+rcx]              */
    0x31, 0xd2,                         /* xor edx, edx                     */
    0x49, 0xf7, 0xf0,                   /* div r8                           */
    0x49, 0x39, 0xd2,                   /* cmp r10, rdx                     */
    0x73, 0x23,                         /* jae copy_with_wrap               */

    0x49, 0x89, 0xcb,                   /* mov r11, rcx                     */
    0x49, 0xc1, 0xeb, 0x03,             /* shr r11, 3                       */
    0x74, 0x68,                         /* je store_tail                    */
    0x31, 0xc0,                         /* xor eax, eax                     */
    0x4e, 0x8d, 0x04, 0x17,             /* lea r8, [rdi+r10]               */
    /* straight_loop:                                                       */
    0x4c, 0x8b, 0x0c, 0xc6,             /* mov r9, [rsi+rax*8]             */
    0x4d, 0x89, 0x4c, 0xc0, 0x20,       /* mov [r8+rax*8+0x20], r9         */
    0x48, 0x83, 0xc0, 0x01,             /* add rax, 1                       */
    0x4c, 0x39, 0xd8,                   /* cmp rax, r11                     */
    0x75, 0xee,                         /* jne straight_loop                */
    0xeb, 0x4e,                         /* jmp store_tail                   */

    /* copy_with_wrap:                                                      */
    0x4c, 0x8b, 0x5f, 0x18,             /* mov r11, [rdi+0x18]             */
    0x4d, 0x29, 0xd3,                   /* sub r11, r10                     */
    0x4c, 0x89, 0xd8,                   /* mov rax, r11                     */
    0x48, 0xc1, 0xe8, 0x03,             /* shr rax, 3                       */
    0x74, 0x19,                         /* je wrap_second_part              */
    0x45, 0x31, 0xc9,                   /* xor r9d, r9d                     */
    0x4e, 0x8d, 0x04, 0x17,             /* lea r8, [rdi+r10]               */
    /* wrap_first_loop:                                                     */
    0x4a, 0x8b, 0x0c, 0xce,             /* mov rcx, [rsi+r9*8]             */
    0x4b, 0x89, 0x4c, 0xc8, 0x20,       /* mov [r8+r9*8+0x20], rcx         */
    0x49, 0x83, 0xc1, 0x01,             /* add r9, 1                        */
    0x49, 0x39, 0xc1,                   /* cmp r9, rax                      */
    0x75, 0xee,                         /* jne wrap_first_loop              */

    /* wrap_second_part:                                                    */
    0x49, 0x8b, 0x4f, 0x10,             /* mov rcx, [r15+0x10]             */
    0x4c, 0x29, 0xd9,                   /* sub rcx, r11                     */
    0x48, 0xc1, 0xe9, 0x03,             /* shr rcx, 3                       */
    0x74, 0x18,                         /* je store_tail                    */
    0x31, 0xc0,                         /* xor eax, eax                     */
    0x4e, 0x8d, 0x04, 0x1e,             /* lea r8, [rsi+r11]               */
    /* wrap_second_loop:                                                    */
    0x4d, 0x8b, 0x0c, 0xc0,             /* mov r9, [r8+rax*8]              */
    0x4c, 0x89, 0x4c, 0xc7, 0x20,       /* mov [rdi+rax*8+0x20], r9        */
    0x48, 0x83, 0xc0, 0x01,             /* add rax, 1                       */
    0x48, 0x39, 0xc8,                   /* cmp rax, rcx                     */
    0x75, 0xee,                         /* jne wrap_second_loop             */

    /* store_tail:                                                          */
    0x48, 0x89, 0x57, 0x08,             /* mov [rdi+0x08], rdx              */
    0xeb, 0x06,                         /* jmp beach                        */
    /* lost:                                                                */
    0xf0, 0x48, 0x83, 0x47, 0x10, 0x01, /* lock add qword [rdi+0x10], 1   */

    /* beach:                                                               */
    0x49, 0x8b, 0x47, 0x70,             /* mov rax, [r15+0x70]              */
    0x04, 0x7f,                         /* add al, 0x7f                     */
    0x9e,                               /* sahf                             */

    0x4d, 0x8b, 0x5f, 0x68,             /* mov r11, [r15+0x68]              */
    0x4d, 0x8b, 0x57, 0x60,             /* mov r10, [r15+0x60]              */
    0x4d, 0x8b, 0x4f, 0x58,             /* mov r9, [r15+0x58]               */
    0x4d, 0x8b, 0x47, 0x50,             /* mov r8, [r15+0x50]               */
    0x49, 0x8b, 0x7f, 0x48,             /* mov rdi, [r15+0x48]              */
    0x49, 0x8b, 0x77, 0x40,             /* mov rsi, [r15+0x40]              */
    0x49, 0x8b, 0x57, 0x38,             /* mov rdx, [r15+0x38]              */
    0x49, 0x8b, 0x4f, 0x30,             /* mov rcx, [r15+0x30]              */
    0x49, 0x8b, 0x47, 0x28,             /* mov rax, [r15+0x28]              */

    0xc3,                               /* ret                              */
  };

  gum_x86_writer_put_bytes (cw, write_impl, sizeof (write_impl));
}

#endif

static void
emit_event (guint32 type,
            const guint8 * payload,
            gsize payload_size)
{
  guint8 * buf = (guint8 *) session.log_buf;
  guint8 * p = buf;

  memset (p, 0, 8); p += 8;
  memcpy (p, &type, 4); p += 4;
  guint32 ps = (guint32) payload_size;
  memcpy (p, &ps, 4); p += 4;

  if (payload_size > 0)
  {
    memcpy (p, payload, payload_size);
    p += payload_size;
  }

  itrace_buffer_write (session.buffer, buf, 16 + payload_size);
}

static void
write_reg_spec (guint8 ** p,
                const gchar * name,
                guint8 reg_size)
{
  guint8 name_len = (guint8) strlen (name);

  *(*p)++ = name_len;
  memcpy (*p, name, name_len);
  memset (*p + name_len, 0, 6 - name_len);
  *p += 6;
  *(*p)++ = reg_size;
}

static void
format_reg_name (gchar * name,
                 gchar prefix,
                 guint index)
{
  name[0] = prefix;
  if (index < 10)
  {
    name[1] = '0' + index;
    name[2] = '\\0';
  }
  else
  {
    name[1] = '0' + (index / 10);
    name[2] = '0' + (index % 10);
    name[3] = '\\0';
  }
}

static void
itrace_buffer_write (ITraceBuffer * buffer,
                     const guint8 * data,
                     gsize size)
{
  guint64 tail = buffer->tail;

  guint64 head = *(volatile guint64 *) &buffer->head;
  memory_barrier ();

  guint64 capacity = buffer->capacity;

  guint64 available;
  if (head == tail)
    available = capacity - 1;
  else if (head < tail)
    available = capacity - (tail - head) - 1;
  else
    available = head - tail - 1;

  if (available < size)
  {
    buffer->lost += 1;
    return;
  }

  gsize first_part = capacity - tail;
  if (first_part >= size)
  {
    memcpy (buffer->data + tail, data, size);
  }
  else
  {
    memcpy (buffer->data + tail, data, first_part);
    memcpy (buffer->data, data + first_part, size - first_part);
  }

  guint64 new_tail = (tail + size) % capacity;

  memory_barrier ();
  *(volatile guint64 *) &buffer->tail = new_tail;
}
`;
