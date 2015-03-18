#pragma once

#include <stdint.h>
#include <stdlib.h>

#define GETDNS_COMPILATION_COMMENT "Knot Resolver 0.0.1"

enum getdns_return {
	GETDNS_RETURN_GOOD,
	GETDNS_RETURN_GENERIC_ERROR,
	GETDNS_RETURN_BAD_DOMAIN_NAME,
	GETDNS_RETURN_BAD_CONTEXT,
	GETDNS_RETURN_CONTEXT_UPDATE_FAIL,
	GETDNS_RETURN_UNKNOWN_TRANSACTION,
	GETDNS_RETURN_NO_SUCH_LIST_ITEM,
	GETDNS_RETURN_NO_SUCH_DICT_NAME,
	GETDNS_RETURN_WRONG_TYPE_REQUESTED,
	GETDNS_RETURN_NO_SUCH_EXTENSION,
	GETDNS_RETURN_EXTENSION_MISFORMAT,
	GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED,
	GETDNS_RETURN_MEMORY_ERROR,
	GETDNS_RETURN_INVALID_PARAMETER,
};

typedef enum getdns_return getdns_return_t;

enum {
	/** At least one response was retuned. */
	GETDNS_RESPSTATUS_GOOD,
	/** Query for the name yielded a negative response. */
	GETDNS_RESPSTATUS_NO_NAME,
	/** All queries timed out. */
	GETDNS_RESPSTATUS_ALL_TIMEOUT,
	/** At least one response was retuned, but not secured by DNSSEC. */
	GETDNS_RESPSTATUS_NO_SECURE_ANSWERS,
};

enum {
	/** DNS name service. */
	GETDNS_NAMETYPE_DNS,
	/** WINS name service. */
	GETDNS_NAMETYPE_WINS,
};

struct getdns_dict;
typedef struct getdns_dict getdns_dict;

struct getdns_list;
typedef struct getdns_list getdns_list;

struct getdns_bindata {
	size_t size;
	uint8_t *data;
};

typedef struct getdns_bindata getdns_bindata;


/*
 * Resolution context.
 */

struct getdns_context;
typedef struct getdns_context getdns_context;

/**
 * Create a new resolution context with default values.
 *
 * @param[out] context      Newly created context.
 * @param[in]  set_from_os  Set some defaults from the operating system.
 */
getdns_return_t getdns_context_create(
	getdns_context **context,
	int set_from_os
);

/**
 * Create a new resolution context using custom memory allocator with a global context.
 *
 * \see getdns_context_create
 *
 * @param malloc   Callback for \c malloc.
 * @param realloc  Callback for \c realloc (not actually used, can be NULL).
 * @param free     Callback fro \c free.
 */
getdns_return_t getdns_context_create_with_memory_functions(
	getdns_context **context,
	int set_from_os,
	void *(*malloc)(size_t),
	void *(*realloc)(void *, size_t),
	void (*free)(void *)
);

/**
 * Create a new resolution context using custom memory allocator with a local context.
 *
 * \see getdns_context_create_with_memory_functions
 *
 * @param userarg  Memory allocation context passed to allocation functions.
 */
getdns_return_t getdns_context_create_with_extended_memory_functions(
	getdns_context  **context,
	int set_from_os,
	void *userarg,
	void *(*malloc)(void *userarg, size_t),
	void *(*realloc)(void *userarg, void *, size_t),
	void (*free)(void *userarg, void *)
);

/**
 * Destroy resolution context including all running transactions.
 *
 * Callbacks for unprocessed transactions will be called with the
 * \c callback_type parameter set to \c GETDNS_CALLBACK_CANCEL.
 *
 * @param context  Context to be destroyed.
 */
void getdns_context_destroy(getdns_context *context);

enum getdns_context_code {
	GETDNS_CONTEXT_CODE_NAMESPACES,
	GETDNS_CONTEXT_CODE_RESOLUTION_TYPE,
	GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS,
	GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS,
	GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS,
	GETDNS_CONTEXT_CODE_DNS_TRANSPORT,
	GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES,
	GETDNS_CONTEXT_CODE_APPEND_NAME,
	GETDNS_CONTEXT_CODE_SUFFIX,
	GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS,
	GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE,
	GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE,
	GETDNS_CONTEXT_CODE_EDNS_VERSION,
	GETDNS_CONTEXT_CODE_EDNS_DO_BIT,
	GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW,
	GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS,
	GETDNS_CONTEXT_CODE_TIMEOUT,
};

typedef enum getdns_context_code getdns_context_code_t;

/**
 * Set callback to notify the application when the resolution context changes.
 *
 * @param context  Resolution context.
 * @param value    Callback to be used when the context changes (use NULL to clear).
 *
 * \retval GETDNS_RETURN_GOOD
 * \retval GETDNS_RETURN_CONTEXT_UPDATE_FAIL
 */
getdns_return_t getdns_context_set_context_update_callback(
	getdns_context *context,
	void (*value)(getdns_context *context, getdns_context_code_t changed_item)
);

enum getdns_resolution {
	GETDNS_RESOLUTION_RECURSING, // default
	GETDNS_RESOLUTION_STUB,
};

typedef enum getdns_resolution getdns_resolution_t;

/**
 * Set resolution type.
 *
 * \retval GETDNS_RETURN_GOOD
 * \retval GETDNS_RETURN_CONTEXT_UPDATE_FAIL
 */
getdns_return_t getdns_context_set_resolution_type(
	getdns_context *context,
	getdns_resolution_t value
);

enum getdns_namespace {
	GETDNS_NAMESPACE_DNS,
	GETDNS_NAMESPACE_LOCALNAMES,
	GETDNS_NAMESPACE_NETBIOS,
	GETDNS_NAMESPACE_MDNS,
	GETDNS_NAMESPACE_NIS,
};

typedef enum getdns_namespace getdns_namespace_t;

/**
 * Set ordered list of namespaces that will be queried.
 *
 * @note Ignored by \c getdns_general and \c getdns_general_sync.
 */
getdns_return_t getdns_context_set_namespaces(
	getdns_context *context,
	size_t namespace_count,
	getdns_namespace_t *namespaces
);

enum getdns_transport {
	GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP, // default
	GETDNS_TRANSPORT_UDP_ONLY,
	GETDNS_TRANSPORT_TCP_ONLY,
	GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN
};

typedef enum getdns_transport getdns_transport_t;

/**
 * Set a transport to be used for the resolutions.
 */
getdns_return_t getdns_context_set_dns_transport(
	getdns_context *context,
	getdns_transport_t value
);

/**
 * Set maximum number of queries being processed.
 *
 * @param limit  Limit of outstanding queries. Zero indicates no limit.
 */
getdns_return_t getdns_context_set_limit_outstanding_queries(
	getdns_context *context,
	uint16_t limit
);

enum getdns_redirects {
	GETDNS_REDIRECTS_FOLLOW, // default
	GETDNS_REDIRECTS_DO_NOT_FOLLOW
};

typedef enum getdns_redirects getdns_redirects_t;

/**
 * Set if the CNAME and DNAME redirects should be followed.
 */
getdns_return_t getdns_context_set_follow_redirects(
	getdns_context *context,
	getdns_redirects_t value
);

/**
 * Set the servers for top-level domain lookup.
 *
 * [
 *   { "address_type": "IPv4", "address_data": <bindata ...> },
 *   { "address_type": "IPv6", "address_data": <bindata ...> },
 *   ...
 * ]
 *
 */
getdns_return_t getdns_context_set_dns_root_servers(
	getdns_context *context,
	getdns_list *addresses
);

enum getdns_append_name {
	GETDNS_APPEND_NAME_ALWAYS, // default
	GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE,
	GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE,
	GETDNS_APPEND_NAME_NEVER
};

typedef enum getdns_append_name getdns_append_name_t;

/**
 * Set a mode of appending a suffix to queried names.
 *
 * \see getdns_context_set_suffix
 */
getdns_return_t getdns_context_set_append_name(
	getdns_context *context,
	getdns_append_name_t value
);

/**
 * Set a list of strings to be appended to queries.
 *
 * \see getdns_context_set_append_mode
 */
getdns_return_t getdns_context_set_suffix(
	getdns_context *context,
	getdns_list *value
);

/**
 * Set DNSSEC trust anchors for queries with DNSSEC extension.
 *
 * @param context  Resolution context.
 * @param value    List of RDATA (bindata) of trusted DNSKEYs.
 */
getdns_return_t getdns_context_set_dnssec_trust_anchors(
	getdns_context *context,
	getdns_list *value
);

/**
 * Set number of seconds of skew to allow when checking DNSSEC signatures.
 */
getdns_return_t getdns_context_set_dnssec_allowed_skew(
	getdns_context *context,
	uint32_t value
);

/**
 * Set upstream recursive server for stub resolution mode.
 *
 * \see getdns_context_set_resolution_type
 *
 * [
 *   { "address_type": "IPv4", "address_data": <bindata ...> },
 *   { "address_type": "IPv6", "address_data": <bindata ...>, "port": 5353,
 *     "tsig_algorithm": <bindata ...>, "tsig_secret": <bindata ...> },
 *   ...
 * ]
 */
getdns_return_t getdns_context_set_upstream_recursive_servers(
	getdns_context *context,
	getdns_list *upstream_list
);

/**
 * Set EDNS maximum UDP payload size.
 *
 * @param value  Maximum payload size (512-65535, default 512).
 */
getdns_return_t getdns_context_set_edns_maximum_udp_payload_size(
	getdns_context *context,
	uint16_t value
);

/**
 * Set EDNS extended RCODE.
 *
 * @param value  Extended RCODE (default 0).
 */
getdns_return_t getdns_context_set_edns_extended_rcode(
	getdns_context *context,
	uint8_t value
);

/**
 * Set EDNS version.
 *
 * @param value  EDNS version (default 0).
 */
getdns_return_t getdns_context_set_edns_version(
	getdns_context *context,
	uint8_t value
);

/**
 * Set EDNS DO (DNSSEC OK) bit.
 * 
 * @param value EDNS DO bit (0 or 1, default 0).
 */
getdns_return_t getdns_context_set_edns_do_bit(
	getdns_context *context,
	uint8_t value
);

/**
 * Set memory allocation functions with a global context.
 */
getdns_return_t getdns_context_set_memory_functions(
	getdns_context *context,
	void *(*malloc) (size_t),
	void *(*realloc) (void *, size_t),
	void (*free) (void *)
);

/**
 * Set memory allocation functions with a local context.
 */
getdns_return_t getdns_context_set_extended_memory_functions(
	getdns_context *context,
	void *userarg,
	void *(*malloc)(void *userarg, size_t sz),
	void *(*realloc)(void *userarg, void *ptr, size_t sz),
	void (*free)(void *userarg, void *ptr)
);

/**
 * Get information about the implementation.
 */
getdns_dict *getdns_context_get_api_information(getdns_context *context);

/*
 * Data structures.
 *
 * GETDNS_RETURN_GOOD                  Success.
 * GETDNS_RETURN_NO_SUCH_LIST_ITEM     Index argument out of range.
 * GETDNS_RETURN_NO_SUCH_DICT_NAME     Name argument does not exist.
 * GETDNS_RETURN_WRONG_TYPE_REQUESTED  Requested data type does not match the content.
 */

enum getdns_data_type {
	t_dict,
	t_list,
	t_int,
	t_bindata
};

typedef enum getdns_data_type getdns_data_type;

/* Lists: get the length, get the data_type of the value at a given
   position, and get the data at a given position */

// writing lists (the lists are extended by setting index to size of the list)

getdns_list *getdns_list_create(void);

getdns_list *getdns_list_create_with_context(getdns_context *context);

getdns_list *getdns_list_create_with_memory_functions(
	void *(*malloc)(size_t),
	void *(*realloc)(void *, size_t),
	void (*free)(void *)
);
getdns_list *getdns_list_create_with_extended_memory_functions(
	void *userarg,
	void *(*malloc)(void *userarg, size_t),
	void *(*realloc)(void *userarg, void *, size_t),
	void (*free)(void *userarg, void *)
);

void getdns_list_destroy(getdns_list *this_list);

getdns_return_t getdns_list_set_dict(
	getdns_list *this_list,
	size_t index,
	const getdns_dict *child_dict
);

getdns_return_t getdns_list_set_list(
	getdns_list *this_list,
	size_t index,
	const getdns_list *child_list
);

getdns_return_t getdns_list_set_bindata(
	getdns_list *this_list,
	size_t index,
	const getdns_bindata *child_bindata
);

getdns_return_t getdns_list_set_int(
	getdns_list *this_list,
	size_t index,
	uint32_t child_uint32
);

// reading lists

getdns_return_t getdns_list_get_length(
	const getdns_list *this_list,
	size_t *answer
);

getdns_return_t getdns_list_get_data_type(
	const getdns_list *this_list,
	size_t index,
	getdns_data_type *answer
);

getdns_return_t getdns_list_get_dict(
	const getdns_list *this_list,
	size_t index,
	getdns_dict **answer
);

getdns_return_t getdns_list_get_list(
	const getdns_list *this_list,
	size_t index,
	getdns_list **answer
);

getdns_return_t getdns_list_get_bindata(
	const getdns_list *this_list,
	size_t index,
	getdns_bindata **answer
);

getdns_return_t getdns_list_get_int(
	const getdns_list *this_list,
	size_t index,
	uint32_t *answer
);

/* Dicts: get the list of names, get the data_type of the
   value at a given name, and get the data at a given name */

// writing dicts (extended by setting non-existent name)

getdns_dict *getdns_dict_create();

getdns_dict *getdns_dict_create_with_context(getdns_context *context);

getdns_dict *getdns_dict_create_with_memory_functions(
	void *(*malloc)(size_t),
	void *(*realloc)(void *, size_t),
	void (*free)(void *)
);

getdns_dict *getdns_dict_create_with_extended_memory_functions(
	void *userarg,
	void *(*malloc)(void *userarg, size_t),
	void *(*realloc)(void *userarg, void *, size_t),
	void (*free)(void *userarg, void *)
);

void getdns_dict_destroy(getdns_dict *this_dict);

getdns_return_t getdns_dict_set_dict(
	getdns_dict *this_dict,
	const char *name,
	const getdns_dict *child_dict
);

getdns_return_t getdns_dict_set_list(
	getdns_dict *this_dict,
	const char *name,
	const getdns_list *child_list
);

getdns_return_t getdns_dict_set_bindata(
	getdns_dict *this_dict,
	const char *name,
	const getdns_bindata *child_bindata
);

getdns_return_t getdns_dict_set_int(
	getdns_dict *this_dict,
	const char *name,
	uint32_t child_uint32
);

getdns_return_t getdns_dict_remove_name(
	getdns_dict *this_dict,
	const char *name
);

// reading dicts

getdns_return_t getdns_dict_get_names(
	const getdns_dict *this_dict,
	getdns_list **answer
);

getdns_return_t getdns_dict_get_data_type(
	const getdns_dict *this_dict,
	const char *name,
	getdns_data_type *answer
);

getdns_return_t getdns_dict_get_dict(
	const getdns_dict *this_dict,
	const char *name,
	getdns_dict **answer
);

getdns_return_t getdns_dict_get_list(
	const getdns_dict *this_dict,
	const char *name,
	getdns_list **answer
);

getdns_return_t getdns_dict_get_bindata(
	const getdns_dict *this_dict,
	const char *name,
	getdns_bindata **answer
);

getdns_return_t getdns_dict_get_int(
	const getdns_dict *this_dict,
	const char *name,
	uint32_t *answer
);

// helper functions

/**
 * Get textual representation of a dictionary.
 *
 * \return Dictionary in printable format. Deallocate with \c free.
 */
char *getdns_pretty_print_dict(const getdns_dict *some_dict);

/*
 * Callback Functions
 */

typedef uint64_t getdns_transaction_t;

enum getdns_callback_type {
	GETDNS_CALLBACK_COMPLETE, /**< The response contains requested data. */
	GETDNS_CALLBACK_CANCEL,   /**< The resolution was cancelled, response is NULL. */
	GETDNS_CALLBACK_TIMEOUT,  /**< The resolution timed out. */
	GETDNS_CALLBACK_ERROR,    /**< The resolutiion failed with an error. */
};

typedef enum getdns_callback_type getdns_callback_type_t;

/**
 * Callback function definition.
 *
 * @param context         Resolution context.
 * @param callback_type   Reason for the callback.
 * @param response        An object with a response data. The object must be
 *                        destroyed by the application (\ref getdns_dict_destroy).
 * @param userarg         User defined argument.
 * @param tranasction_id  Identifier of the transaction.
 *
 */
typedef void (*getdns_callback_t)(
	getdns_context *context,
	getdns_callback_type_t callback_type,
	getdns_dict *response,
	void *userarg,
	getdns_transaction_t transaction_id
);

/**
 * Cancel outstanding callback.
 *
 * The cancelation will cause the resolution callback to be called with the
 * \c callback_type parameter set to \c GETDNS_CALLBACK_CANCEL.
 *
 * @param context         Resolution context.
 * @param transaction_id  Identifier of the transaction.
 *
 * \retval GETDNS_RETURN_GOOD                 The transaction was cancelled.
 * \retval GETDNS_RETURN_UNKNOWN_TRANSACTION  The transaction is invalid or
 *                                            the was already processed.
 */
getdns_return_t getdns_cancel_callback(
	getdns_context *context,
	getdns_transaction_t transaction_id
);

/*
 * Async Functions
 */

/**
 * Perform an asynchronous DNS resolution.
 *
 * @param[in]  context         Resolution context.
 * @param[in]  name            ASCII domain name or IP address.
 * @param[in]  request_type    RR type for the query.
 * @param[in]  extensions      Extensions for the request (can be NULL).
 * @param[in]  userarg         User data passed to callback function.
 * @param[out] transaction_id  Non-zero identifier of the transaction (can be
 *                             NULL, set to zero on error).
 * @param[in]  callbackfn      Callback function to process the result.
 *
 * \return Error code.
 * \retval GETDNS_RETURN_GOOD                 The call was properly formatted.
 * \retval GETDNS_RETURN_BAD_DOMAIN_NAME      The domain name is invalid.
 * \retval GETDNS_RETURN_BAD_CONTEXT          The context is invalid.
 * \retval GETDNS_RETURN_NO_SUCH_EXTENSION    One or more extensions do not exist.
 * \retval GETDNS_RETURN_EXTENSION_MISFORMAT  Content of one or more extensions is incorrect.
 */
getdns_return_t getdns_general(
	getdns_context *context,
	const char *name,
	uint16_t request_type,
	getdns_dict *extensions,
	void *userarg,
	getdns_transaction_t *transaction_id,
	getdns_callback_t callbackfn
);

/**
 * Perform an asynchronous hostname-to-address resolution.
 *
 * \see getdns_general
 *
 * The \c name parameter can be only a host name.
 * The \c return_both_v4_and_v6 extension is set by default.
 * The function uses all namespaces from the context.
 */
getdns_return_t getdns_address(
	getdns_context *context,
	const char *name,
	getdns_dict *extensions,
	void *userarg,
	getdns_transaction_t *transaction_id,
	getdns_callback_t callbackfn
);

/**
 * Perform an asynchronous address-to-hostname resolution.
 *
 * \see getdns_general
 *
 * Address is given as a dictionary with two names:
 * * \c address_type (binary, "IPv4" or "IPv6" case sensitive string)
 * * \c address_data (binary, address)
 */
getdns_return_t getdns_hostname(
	getdns_context *context,
	getdns_dict *address,
	getdns_dict *extensions,
	void *userarg,
	getdns_transaction_t *transaction_id,
	getdns_callback_t callbackfn
);

/**
 * Perform an asynchronous SRV lookup.
 *
 * \see getdns_general
 *
 * \c name must be a domain name.
 */
getdns_return_t getdns_service(
	getdns_context *context,
	const char *name,
	getdns_dict *extensions,
	void *userarg,
	getdns_transaction_t *transaction_id,
	getdns_callback_t callbackfn
);

/*
 * Synchronous API.
 */

/**
 * Perform a synchronous DNS resolution.
 *
 * \see getdns_general
 *
 * @param[out] response  Result of the resolution.
 */
getdns_return_t getdns_general_sync(
	getdns_context *context,
	const char *name,
	uint16_t request_type,
	getdns_dict *extensions,
	getdns_dict **response
);

/**
 * Perform a synchronous hostname-to-address resolution.
 *
 * \see getdns_general_sync
 * \see getdns_address
 */
getdns_return_t getdns_address_sync(
	getdns_context *context,
	const char *name,
	getdns_dict *extensions,
	getdns_dict **response
);

/**
 * Perform a synchronous address-to-hostname resolution.
 *
 * \see getdns_general_sync
 * \see getdns_hostname
 */
getdns_return_t getdns_hostname_sync(
	getdns_context *context,
	getdns_dict *address,
	getdns_dict *extensions,
	getdns_dict **response
);

/**
 * Perform an asynchronous SRV lookup.
 *
 * \see getdns_general_sync
 * \see getdns_service
 */
getdns_return_t getdns_service_sync(
	getdns_context *context,
	const char *name,
	getdns_dict *extensions,
	getdns_dict **response
);

/*
 * Extensions.
 *
 * dnssec_return_status
 * dnssec_return_only_secure
 * dnssec_return_validation_chain
 * return_both_v4_and_v6
 * add_opt_parameters
 * add_warning_for_bad_dns
 * specify_class
 * return_call_debugging
 */

enum {
	GETDNS_EXTENSION_FALSE = 0,
	GETDNS_EXTENSION_TRUE = 1
};

enum {
	GETDNS_BAD_DNS_CNAME_IN_TARGET,
	GETDNS_BAD_DNS_ALL_NUMERIC_LABEL,
	GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE,
};

/*
 * Domain name conversions.
 */

/**
 * Convert domain name from wire to presentation format.
 *
 * @param[in]  dns_name_wire_fmt  Domain name in wire format.
 * @param[out] fqdn_as_string     Domain name in presentation format (with
 *                                interior dots only, deallocate with \c free).
 */
getdns_return_t getdns_convert_dns_name_to_fqdn(
	const getdns_bindata *dns_name_wire_fmt,
	char **fqdn_as_string
);

/**
 * Convert domain name from presentation to wire format.
 *
 * @param[in]  fqdn_as_string    Domain name in presentation format.
 * @param[out] dns_name_wire_fmt Domain name in wire format (deallocate with
 *                               \c free).
 */
getdns_return_t getdns_convert_fqdn_to_dns_name(
	const char *fqdn_as_string,
	getdns_bindata **dns_name_wire_fmt
);

/**
 * Convert IDN label from Unicode to ASCII.
 */
char *getdns_convert_ulabel_to_alabel(const char  *ulabel);

/**
 * Convert IDN label from ASCII to Unicode.
 */
char *getdns_convert_alabel_to_ulabel(const char  *alabel);


/**
 * Convert binary IP address to nicely-formatted text representation.
 *
 * \return IP address in presentation format (deallocate with \c free).
 */
char *getdns_display_ip_address(
	const getdns_bindata *bindata_of_ipv4_or_ipv6_address
);

/*
 * DNSSEC
 */

enum {
	GETDNS_DNSSEC_SECURE,
	GETDNS_DNSSEC_BOGUS,
	GETDNS_DNSSEC_INDETERMINATE,
	GETDNS_DNSSEC_INSECURE,
};

/**
 * Perform DNSSEC validation of given records.
 */
getdns_return_t getdns_validate_dnssec(
	getdns_list *record_to_validate,
	getdns_list *bundle_of_support_records,
	getdns_list *trust_anchor_records
);

/**
 * Get default root trust anchor.
 *
 * @param[out] utc_data_of_anchor  Time of obtaining the trust anchor.
 *
 * \return Root trust anchor, NULL if no default trust anchor exists.
 */
getdns_list *getdns_root_trust_anchor(time_t *utc_date_of_anchor);
