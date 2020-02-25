/* SPDX-License-Identifier: CC0-1.0
 * Source: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp */

#pragma once

#include <stdlib.h>
#include <stdint.h>

uint32_t hash(const char* data, size_t len);
