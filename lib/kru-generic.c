/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "lib/defines.h"
#include "./kru.inc.c"  // NOLINT(bugprone-suspicious-include)

KR_EXPORT
const struct kru_api KRU_GENERIC = KRU_API_INITIALIZER;

KR_EXPORT
struct kru_api KRU = KRU_API_INITIALIZER; // generic version is the default
