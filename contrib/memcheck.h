#pragma once

#include <asan.h>
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


// #else
//  #define RUNNING_ON_VALGRIND 0
//  #define VALGRIND_MAKE_MEM_NOACCESS(...)
//  #define VALGRIND_MAKE_MEM_UNDEFINED(...)
//  #define VALGRIND_MAKE_MEM_DEFINED(...)
// #endif
