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
#include <libknot/internal/lists.h>
#include <libknot/internal/namedb/namedb.h>
#include <libknot/internal/sockaddr.h>

#include "lib/context.h"
#include "lib/zonecut.h"

/*!
 * \brief Single query representation.
 */
struct kr_query {
	node_t node;
	struct timeval timestamp;
	knot_dname_t *sname;
	uint16_t stype;
	uint16_t sclass;
	uint16_t id;
	uint16_t flags;
};

/*!
 * \brief Query resolution plan structure.
 *
 * The structure most importantly holds the original query, answer and the
 * list of pending queries required to resolve the original query.
 * It also keeps a notion of current zone cut.
 */
struct kr_rplan {
	unsigned state;              /*!< Query resolution state. */
	struct kr_zonecut zone_cut;
	unsigned txn_flags;          /*!< Current transaction flags. */
	namedb_txn_t txn;            /*!< Current transaction (may be r/o). */
	list_t pending;              /*!< List of pending queries. */
	list_t resolved;             /*!< List of resolved queries. */
	struct kr_context *context;  /*!< Parent resolution context. */
	mm_ctx_t *pool;              /*!< Temporary memory pool. */
};

/*!
 * \brief Initialize resolution plan (empty).
 * \param rplan plan instance
 * \param context resolution context
 * \param pool ephemeral memory pool for whole resolution
 */
void kr_rplan_init(struct kr_rplan *rplan, struct kr_context *context, mm_ctx_t *pool);

/*!
 * \brief Deinitialize resolution plan, aborting any uncommited transactions.
 * \param rplan plan instance
 */
void kr_rplan_deinit(struct kr_rplan *rplan);

/*!
 * \brief Return true if the resolution plan is empty (i.e. finished or initialized)
 * \param rplan plan instance
 * \return true or false
 */
bool kr_rplan_empty(struct kr_rplan *rplan);

/*!
 * \brief Acquire rplan transaction (read or write only).
 * \note The transaction is shared during the whole resolution, read only transactions
 *       may be promoted to write-enabled transactions if requested, but never demoted.
 * \param rplan plan instance
 * \param flags transaction flags
 * \return transaction instance or NULL
 */
namedb_txn_t *kr_rplan_txn_acquire(struct kr_rplan *rplan, unsigned flags);

/*!
 * \brief Commit any existing transaction, read-only transactions may be just aborted.
 * \param rplan plan instance
 * \return KNOT_E*
 */
int kr_rplan_txn_commit(struct kr_rplan *rplan);

/*!
 * \brief Push a query to the top of the resolution plan.
 * \note This means that this query takes precedence before all pending queries.
 * \param rplan plan instance
 * \param name resolved name
 * \param cls  resolved class
 * \param type resolved type
 * \return query instance or NULL
 */
struct kr_query *kr_rplan_push(struct kr_rplan *rplan, const knot_dname_t *name, uint16_t cls, uint16_t type);

/*!
 * \brief Pop existing query from the resolution plan.
 * \note Popped queries are not discarded, but moved to the resolved list.
 * \param rplan plan instance
 * \param qry resolved query
 * \return KNOT_E*
 */
int kr_rplan_pop(struct kr_rplan *rplan, struct kr_query *qry);

/*!
 * \brief Currently resolved query (at the top).
 * \param rplan plan instance
 * \return query instance or NULL if empty
 */
struct kr_query *kr_rplan_current(struct kr_rplan *rplan);

/*!
 * \brief Last resolved query instance (i.e. first enqueued)
 * \param rplan plan instance
 * \return query instance or NULL if empty
 */
struct kr_query *kr_rplan_last(struct kr_rplan *rplan);
