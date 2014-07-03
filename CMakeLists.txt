cmake_minimum_required(VERSION 2.8)
project(resolver C)
set(RESOLVER_VERSION 0.0.1) 
set(LIBS_VERSION 0.0.1)

# Compiler flags

if(NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type specified, setting to 'Release'.")
	set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_C_FLAGS         "-std=gnu99 -Wall -g")
set(CMAKE_C_FLAGS_DEBUG   "-O0")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Modules compilation

include_directories(include)

set(resolver_sources
	lib/context.c
	lib/info.c
)

add_library(resolver SHARED ${resolver_sources})
set_target_properties(resolver PROPERTIES VERSION ${LIBS_VERSION})
