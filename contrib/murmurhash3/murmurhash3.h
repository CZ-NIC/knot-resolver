/* SPDX-License-Identifier: CC0-1.0
 * Source: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include "lib/defines.h"

KR_EXPORT uint32_t murmurhash(const char* data, size_t len);
