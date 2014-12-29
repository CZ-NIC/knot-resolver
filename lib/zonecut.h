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

#include <libknot/dname.h>
#include <libknot/rrset.h>
#include <libknot/internal/sockaddr.h>
#include <libknot/internal/namedb/namedb.h>

struct kr_rplan;

/*!
 * \brief Current zone cut representation.
*/
struct kr_zonecut {
	knot_dname_t name[KNOT_DNAME_MAXLEN]; /*!< Current zone cut */
	knot_dname_t ns[KNOT_DNAME_MAXLEN];   /*!< Authoritative NS */
	struct sockaddr_storage addr;         /*!< Authoritative NS address. */
};

/*!
 * \brief Set zone cut to given name and name server.
 * \note Name server address is blanked.
 * \param cut zone cut to be set
 * \param name zone cut name
 * \param ns   zone cut nameserver
 * \return KNOT_E*
 */
int kr_set_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, const knot_dname_t *ns);

/*!
 * \brief Find the closest enclosing zone cut/nameserver from the cache.
 * \param cut zone cut to be set
 * \param name zone cut name
 * \param txn cache transaction
 * \param timestamp transaction timestamp
 * \return KNOT_E*
 */
int kr_find_zone_cut(struct kr_zonecut *cut, const knot_dname_t *name, namedb_txn_t *txn, uint32_t timestamp);
