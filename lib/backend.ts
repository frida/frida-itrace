export const code = `#line 2 "backend.ts"
#include <string.h>
#include <gum/gummodulemap.h>
#include <gum/gumstalker.h>
#include <json-glib/json-glib.h>

#define RED_ZONE_SIZE 128

#define SCRATCH_REG_BOTTOM ARM64_REG_X21
#define SCRATCH_REG_TOP ARM64_REG_X28

#define SCRATCH_REG_INDEX(r) ((r) - SCRATCH_REG_BOTTOM)
#define SCRATCH_REG_OFFSET(r) (SCRATCH_REG_INDEX (r) * 8)

typedef enum _ITraceState ITraceState;
typedef struct _ITraceSession ITraceSession;
typedef struct _ITraceBuffer ITraceBuffer;

enum _ITraceState
{
  ITRACE_STATE_CREATED,
  ITRACE_STATE_STARTING,
  ITRACE_STATE_STARTED,
  ITRACE_STATE_ENDED,
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

extern void on_start (const gchar * meta_json, const GumCpuContext * cpu_context, guint length);
extern void on_end (void);
extern void on_compile (const gchar * meta_json);
extern void on_panic (const gchar * message);

static void on_first_block_hit (GumCpuContext * cpu_context, gpointer user_data);
static void on_end_instruction_hit (GumCpuContext * cpu_context, gpointer user_data);
static void add_cpu_register_meta (JsonBuilder * meta, const gchar * name, guint size);
static void add_block_write_meta (JsonBuilder * meta, guint block_offset, guint cpu_reg_index);
static void add_memory_address (JsonBuilder * builder, GumAddress address);
static gchar * make_json (JsonBuilder ** builder);
static arm64_reg pick_scratch_register (cs_regs regs_read, uint8_t num_regs_read, cs_regs regs_written, uint8_t num_regs_written);
static arm64_reg register_to_full_size_register (arm64_reg reg);
static void emit_scratch_register_restore (GumArm64Writer * cw, arm64_reg reg);
static void emit_buffer_write_impl (GumArm64Writer * cw);

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
  GumArm64Writer * cw = output->writer.arm64;
  csh capstone = gum_stalker_iterator_get_capstone (iterator);

  guint num_instructions = 0;
  GumAddress block_address = 0;
  guint log_buf_offset = 16;
  arm64_reg prev_session_reg = ARM64_REG_INVALID;

  JsonBuilder * meta = json_builder_new_immutable ();
  json_builder_begin_object (meta);

  cs_insn * insn;
  while (gum_stalker_iterator_next (iterator, &insn))
  {
    num_instructions++;

    gboolean is_first_in_block = num_instructions == 1;
    gboolean is_last_in_block = cs_insn_group (capstone, insn, CS_GRP_JUMP) || cs_insn_group (capstone, insn, CS_GRP_RET);

    if (is_first_in_block)
    {
      block_address = insn->address;

      json_builder_set_member_name (meta, "writes");
      json_builder_begin_array (meta);
    }

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
      add_block_write_meta (meta, insn->address - block_address, 33);
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

    gum_stalker_iterator_keep (iterator);

    if (is_last_in_block)
      continue;

    guint block_offset = (insn->address + insn->size) - block_address;

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
      add_block_write_meta (meta, block_offset, cpu_reg_index);
      log_buf_offset += size;

      if (temp_reg != ARM64_REG_INVALID)
        gum_arm64_writer_put_ldr_reg_reg_offset (cw, temp_reg, session_reg, G_STRUCT_OFFSET (ITraceSession, saved_regs));
    }

    prev_session_reg = session_reg;
  }

  json_builder_end_array (meta);

  json_builder_set_member_name (meta, "address");
  add_memory_address (meta, block_address);

  json_builder_set_member_name (meta, "size");
  json_builder_add_int_value (meta, (insn->address + insn->size) - block_address);

  json_builder_set_member_name (meta, "compiled");
  json_builder_begin_object (meta);
  {
    guint compiled_code_size = gum_arm64_writer_offset (cw);

    json_builder_set_member_name (meta, "address");
    add_memory_address (meta, cw->pc - compiled_code_size);

    json_builder_set_member_name (meta, "size");
    json_builder_add_int_value (meta, compiled_code_size);
  }
  json_builder_end_object (meta);

  GumModule * m = gum_module_map_find (session.modules, block_address);
  if (m != NULL)
  {
    const GumMemoryRange * range = gum_module_get_range (m);

    json_builder_set_member_name (meta, "name");
    gchar * name = g_strdup_printf ("%s!0x%x", gum_module_get_name (m), (guint) (block_address - range->base_address));
    json_builder_add_string_value (meta, name);
    g_free (name);

    json_builder_set_member_name (meta, "module");
    json_builder_begin_object (meta);

    json_builder_set_member_name (meta, "path");
    json_builder_add_string_value (meta, gum_module_get_path (m));

    json_builder_set_member_name (meta, "base");
    add_memory_address (meta, range->base_address);

    json_builder_end_object (meta);
  }
  else
  {
    json_builder_set_member_name (meta, "name");
    add_memory_address (meta, block_address);
  }

  json_builder_end_object (meta);

  gchar * json = make_json (&meta);
  on_compile (json);
  g_free (json);
}

static void
on_first_block_hit (GumCpuContext * cpu_context,
                    gpointer user_data)
{
  if (session.state != ITRACE_STATE_STARTING)
    return;
  session.state = ITRACE_STATE_STARTED;

  memcpy (session.scratch_regs, cpu_context->x + (SCRATCH_REG_BOTTOM - ARM64_REG_X0), sizeof (session.scratch_regs));

  JsonBuilder * meta = json_builder_new_immutable ();
  json_builder_begin_array (meta);
  add_cpu_register_meta (meta, "pc", sizeof (cpu_context->pc));
  add_cpu_register_meta (meta, "sp", sizeof (cpu_context->sp));
  add_cpu_register_meta (meta, "nzcv", sizeof (cpu_context->nzcv));
  for (guint i = 0; i != G_N_ELEMENTS (cpu_context->x); i++)
  {
    gchar * name = g_strdup_printf ("x%u", i);
    add_cpu_register_meta (meta, name, sizeof (cpu_context->x[0]));
    g_free (name);
  }
  add_cpu_register_meta (meta, "fp", sizeof (cpu_context->fp));
  add_cpu_register_meta (meta, "lr", sizeof (cpu_context->lr));
  for (guint i = 0; i != G_N_ELEMENTS (cpu_context->v); i++)
  {
    gchar * name = g_strdup_printf ("v%u", i);
    add_cpu_register_meta (meta, name, sizeof (cpu_context->v[0]));
    g_free (name);
  }
  json_builder_end_array (meta);

  gchar * json = make_json (&meta);
  on_start (json, cpu_context, sizeof (GumCpuContext));
  g_free (json);
}

static void
on_end_instruction_hit (GumCpuContext * cpu_context,
                        gpointer user_data)
{
  if (session.state != ITRACE_STATE_STARTED)
    return;
  session.state = ITRACE_STATE_ENDED;

  on_end ();
}

static void
add_cpu_register_meta (JsonBuilder * meta,
                       const gchar * name,
                       guint size)
{
  json_builder_begin_object (meta);

  json_builder_set_member_name (meta, "name");
  json_builder_add_string_value (meta, name);

  json_builder_set_member_name (meta, "size");
  json_builder_add_int_value (meta, size);

  json_builder_end_object (meta);
}

static void
add_block_write_meta (JsonBuilder * meta,
                      guint block_offset,
                      guint cpu_ctx_offset)
{
  json_builder_begin_array (meta);
  json_builder_add_int_value (meta, block_offset);
  json_builder_add_int_value (meta, cpu_ctx_offset);
  json_builder_end_array (meta);
}

static void
add_memory_address (JsonBuilder * builder,
                    GumAddress address)
{
  gchar * str = g_strdup_printf ("0x%" G_GINT64_MODIFIER "x", address);
  json_builder_add_string_value (builder, str);
  g_free (str);
}

static gchar *
make_json (JsonBuilder ** builder)
{
  JsonBuilder * b = *builder;
  *builder = NULL;

  JsonNode * node = json_builder_get_root (b);
  gchar * json = json_to_string (node, FALSE);
  json_node_unref (node);

  g_object_unref (b);

  return json;
}

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

static void
panic (const char * format,
       ...)
{
  va_list args;
  va_start (args, format);
  gchar * message = g_strdup_vprintf (format, args);
  va_end (args);

  on_panic (message);

  g_free (message);
}
`;
