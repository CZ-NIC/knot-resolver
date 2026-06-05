/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once
#include <stddef.h>

/*
 * see sanitizer/asan_interface.h in compiler-rt (LLVM)
 */
#ifndef __has_feature
  #define __has_feature(feature) 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
  void __asan_poison_memory_region(void const volatile *addr, size_t size);
  void __asan_unpoison_memory_region(void const volatile *addr, size_t size);

  #define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    __asan_unpoison_memory_region((addr), (size))

  #if defined(__GNUC__) && !defined(__clang__)  /* A faulty GCC workaround. */
    #if (__GNUC__ >= 14)  /* newer versions of gcc */
      #define ASAN_POISON_MEMORY_REGION(addr, size)                    \
        do {                                                           \
          _Pragma("GCC diagnostic push");                              \
          _Pragma("GCC diagnostic ignored \"-Wmaybe-uninitialized\""); \
          __asan_poison_memory_region((addr), (size));                 \
          _Pragma("GCC diagnostic pop");                               \
        } while (0)
    #else  /* older versions of gcc */
      #pragma GCC diagnostic push
      #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
      #define ASAN_POISON_MEMORY_REGION(addr, size) \
        __asan_poison_memory_region((addr), (size));
      #pragma GCC diagnostic pop
    #endif
  #else  /* non-gcc (clang) definition */
    #define ASAN_POISON_MEMORY_REGION(addr, size) \
      __asan_poison_memory_region((addr), (size));
  #endif

#else /* __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__) */
  #define ASAN_POISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
  #define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#endif /* __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__) */
