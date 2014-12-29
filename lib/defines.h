/* Copyright 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <libknot/errcode.h>
#include <libknot/dname.h>
#include <libknot/rrset.h>

/*
 * Connection limits.
 */
#define KR_CONN_RTT_MAX 10000

/*
 * Timers.
 */
#define KR_TTL_GRACE  ((KR_CONN_RTT_MAX) / 1000) /* TTL expire grace period. */

/*
 * Defines.
 */
#define KR_DNS_PORT   53
#define KR_DNAME_ROOT ((const knot_dname_t*)"")
