/*
 *  UCW Library -- Memory Pools (Formatting)
 *
 *  (c) 2005 Martin Mares <mj@ucw.cz>
 *  (c) 2007 Pavel Charvat <pchar@ucw.cz>
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  Source: https://www.ucw.cz/libucw/
 */

#include <ucw/lib.h>
#include <ucw/mempool.h>

#include <stdio.h>
#include <string.h>

/* FIXME: migrate to Knot DNS version of mempools. */
#pragma GCC diagnostic ignored "-Wpointer-arith"

static char *
mp_vprintf_at(struct mempool *mp, size_t ofs, const char *fmt, va_list args)
{
  char *ret = mp_grow(mp, ofs + 1) + ofs;
  va_list args2;
  va_copy(args2, args);
  int cnt = vsnprintf(ret, mp_avail(mp) - ofs, fmt, args2);
  va_end(args2);
  if (cnt < 0)
    {
      /* Our C library doesn't support C99 return value of vsnprintf, so we need to iterate */
      do
  {
    ret = mp_expand(mp) + ofs;
    va_copy(args2, args);
    cnt = vsnprintf(ret, mp_avail(mp) - ofs, fmt, args2);
    va_end(args2);
  }
      while (cnt < 0);
    }
  else if ((uint)cnt >= mp_avail(mp) - ofs)
    {
      ret = mp_grow(mp, ofs + cnt + 1) + ofs;
      va_copy(args2, args);
      vsnprintf(ret, cnt + 1, fmt, args2);
      va_end(args2);
    }
  mp_end(mp, ret + cnt + 1);
  return ret - ofs;
}

char *
mp_vprintf(struct mempool *mp, const char *fmt, va_list args)
{
  mp_start(mp, 1);
  return mp_vprintf_at(mp, 0, fmt, args);
}

char *
mp_printf(struct mempool *p, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  char *res = mp_vprintf(p, fmt, args);
  va_end(args);
  return res;
}

char *
mp_vprintf_append(struct mempool *mp, char *ptr, const char *fmt, va_list args)
{
  size_t ofs = mp_open(mp, ptr);
  ASSERT(ofs && !ptr[ofs - 1]);
  return mp_vprintf_at(mp, ofs - 1, fmt, args);
}

char *
mp_printf_append(struct mempool *mp, char *ptr, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  char *res = mp_vprintf_append(mp, ptr, fmt, args);
  va_end(args);
  return res;
}

#ifdef TEST

int main(void)
{
  struct mempool *mp = mp_new(64);
  char *x = mp_printf(mp, "<Hello, %s!>", "World");
  fputs(x, stdout);
  x = mp_printf_append(mp, x, "<Appended>");
  fputs(x, stdout);
  x = mp_printf(mp, "<Hello, %50s!>\n", "World");
  fputs(x, stdout);
  return 0;
}

#endif
