/*
 * Based on https://www.codeproject.com/Articles/43510/Lock-Free-Single-Producer-Single-Consumer-Circular
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

typedef struct _ITraceBuffer ITraceBuffer;

struct _ITraceBuffer
{
  _Atomic size_t head;
  _Atomic size_t tail;
  _Atomic size_t lost;
  size_t capacity;
  uint8_t data[1024];
};

static size_t itrace_buffer_increment (const ITraceBuffer * self, size_t cursor, size_t amount);
static void itrace_memcpy (void * dst, const void * src, size_t n);

void
itrace_buffer_write (ITraceBuffer * self,
                     const void * data,
                     size_t size)
{
  const size_t current_tail = atomic_load_explicit (&self->tail, memory_order_relaxed);
  const size_t next_tail = itrace_buffer_increment (self, current_tail, size);

  const size_t current_head = atomic_load_explicit (&self->head, memory_order_acquire);

  size_t headroom;
  if (current_tail == current_head)
    headroom = self->capacity - 1;
  else if (current_tail > current_head)
    headroom = (self->capacity - current_tail) + current_head - 1;
  else
    headroom = current_head - current_tail - 1;
  if (headroom < size)
  {
    self->lost++;
    return;
  }

  if (next_tail > current_tail)
  {
    itrace_memcpy (self->data + current_tail, data, size);
  }
  else
  {
    const size_t first_chunk_size = self->capacity - current_tail;
    itrace_memcpy (self->data + current_tail, data, first_chunk_size);
    itrace_memcpy (self->data, data + first_chunk_size, size - first_chunk_size);
  }

  atomic_store_explicit (&self->tail, next_tail, memory_order_release);
}

size_t
itrace_buffer_read (ITraceBuffer * self,
                    void * data,
                    size_t size)
{
  const size_t current_head = atomic_load_explicit (&self->head, memory_order_relaxed);
  const size_t current_tail = atomic_load_explicit (&self->tail, memory_order_acquire);

  if (current_tail == current_head)
    return 0;

  size_t available = (current_tail > current_head)
      ? current_tail - current_head
      : (self->capacity - current_head) + current_tail;

  size_t n = MIN (available, size);
  if (current_tail > current_head)
  {
    itrace_memcpy (data, self->data + current_head, n);
  }
  else
  {
    const size_t first_chunk_size = self->capacity - current_head;
    itrace_memcpy (data, self->data + current_head, first_chunk_size);
    itrace_memcpy (data + first_chunk_size, self->data, n - first_chunk_size);
  }

  atomic_store_explicit (&self->head, itrace_buffer_increment (self, current_head, n), memory_order_release);

  return n;
}

static size_t
itrace_buffer_increment (const ITraceBuffer * self,
                         size_t cursor,
                         size_t amount)
{
  return (cursor + amount) % self->capacity;
}

static void
itrace_memcpy (void * dst,
               const void * src,
               size_t n)
{
  uint64_t * d = dst;
  const uint64_t * s = src;
  for (size_t i = 0; i != n / sizeof (uint64_t); i++)
    d[i] = s[i];
}
