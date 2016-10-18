#pragma once

#include <libknot/rrtype/opt.h>

/*! Data for ECS handling, to reside in struct kr_query::ecs.
 *
 * A (kr_ecs_t *)NULL means that no ECS should be done nor answered. */
typedef struct kr_ecs {
	/*! ECS data; for request, ANS query (except scope_len), and answer. */
	knot_edns_client_subnet_t query_ecs;
	bool is_explicit; /*!< ECS was requested by client. */
	/*! The location identifier string.
	 *
	 * It's "0" for explicit /0, and "" for no ECS with /0 scope (like TLD). */
	char loc[2];
	uint8_t loc_len; /*!< The length of loc. */
} kr_ecs_t;

