#pragma once

#include "kresconfig.h"
#include <asan.h>

#if ENABLE_VALGRIND
	#include <valgrind/memcheck.h>
	#include <valgrind/valgrind.h>

	#define MEMCHECK_NOACCESS(ptr, size) { \
		VALGRIND_MAKE_MEM_NOACCESS(ptr, size); \
		ASAN_POISON_MEMORY_REGION(ptr, size); \
	}
	#define MEMCHECK_UNDEFINED(ptr, size) { \
		VALGRIND_MAKE_MEM_UNDEFINED(ptr, size); \
		ASAN_UNPOISON_MEMORY_REGION(ptr, size); \
	}
	#define MEMCHECK_DEFINED(ptr, size) { \
		VALGRIND_MAKE_MEM_DEFINED(ptr, size); \
		ASAN_UNPOISON_MEMORY_REGION(ptr, size); \
	}
#else
	#define MEMCHECK_NOACCESS(ptr, size) ASAN_POISON_MEMORY_REGION(ptr, size)
	#define MEMCHECK_UNDEFINED(ptr, size) ASAN_UNPOISON_MEMORY_REGION(ptr, size);
	#define MEMCHECK_DEFINED(ptr, size) ASAN_UNPOISON_MEMORY_REGION(ptr, size);
	#define VALGRIND_PRINTF(...)
	#define RUNNING_ON_VALGRIND 0
#endif
