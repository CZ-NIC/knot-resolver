/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later

    The code originated from https://github.com/fanf2/qp/blob/master/qp.c
    at revision 5f6d93753.
 */

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lib/generic/trie.h"
#include "lib/utils.h"
#include "contrib/ucw/lib.h"

#ifndef uint
typedef unsigned int uint;
#define uint uint
#endif
typedef uint bitmap_t; /*!< Bit-maps, using the range of 1<<0 to 1<<16 (inclusive). */

typedef uint64_t trie_index_t; /*!< nibble index into a key */
typedef uint64_t word; /*!< A type-punned word */


typedef char static_assert_pointer_fits_in_word
	[sizeof(word) >= sizeof(uintptr_t) ? 1 : -1];

/*! \brief trie keys have lengths
 *
 * 32 bits are enough for key lengths; probably even 16 bits would be.
 * However, a 32 bit length means the alignment will be a multiple of
 * 4, allowing us to stash the BRANCH flags in the bottom bits
 * of a pointer to a key.
 */
typedef struct {
	uint32_t len; // 32 bits are enough for key lengths; probably even 16 bits would be.
	trie_key_t chars[];
} tkey_t;

/*! \brief A trie node is a pair of words.
 *
 * Each word is type-punned, depending on whether this is a branch
 * node or a leaf node. We'll define some accessor functions to wrap
 * this up into something reasonably safe.
 *
 * We aren't using a union to avoid problems with strict aliasing, and
 * we aren't using bitfields because we want to control exactly which
 * bits in the word are used by each field (in particular the flags).
 *
 * Branch nodes are never allocated individually: they are always part
 * of either the root node or the twigs array of their parent branch.
 *
 * In a branch:
 *
 * `i` contains flags, bitmap, and index, explained in more detail below.
 *
 * `p` is a pointer to the "twigs", an array of child nodes.
 *
 * In a leaf:
 *
 * `i` is cast from a pointer to a tkey_t, with flags in the bottom bits.
 *
 * `p` is a trie_val_t.
 */
typedef struct node {
	word i;
	void *p;
} node_t;

struct trie {
	node_t root; // undefined when weight == 0, see empty_root()
	size_t weight;
	knot_mm_t mm;
};

/*! \brief size (in bits) of nibble (half-byte) indexes into keys
 *
 * The bottom bit is clear for the upper nibble, and set for the lower
 * nibble, big-endian style, since the tree has to be in lexicographic
 * order. The index increases from one branch node to the next as you
 * go deeper into the trie. All the keys below a branch are identical
 * up to the nibble identified by the branch. Indices have to be stored
 * because we skip any branch nodes that would have a single child.
 * (Consequently, the skipped parts of key have to be validated in a leaf.)
 *
 * (see also tkey_t.len above)
 */
#define TWIDTH_INDEX 33

/*! \brief exclusive limit on indexes */
#define TMAX_INDEX (BIG1 << TWIDTH_INDEX)

/*! \brief size (in bits) of branch bitmap
 *
 * The bitmap indicates which subtries are present. The present child
 * nodes are stored in the twigs array (with no holes between them).
 *
 * To simplify storing keys that are prefixes of each other, the
 * end-of-string position is treated as an extra nibble value, ordered
 * before all others. So there are 16 possible real nibble values,
 * plus one value for nibbles past the end of the key.
 */
#define TWIDTH_BMP 17

/*
 * We're constructing the layout of the branch `i` field in a careful
 * way to avoid mistakes, getting the compiler to calculate values
 * rather than typing them in by hand.
 */
enum {
	TSHIFT_BRANCH = 0,
	TSHIFT_BMP,
	TOP_BMP = TSHIFT_BMP + TWIDTH_BMP,
	TSHIFT_INDEX = TOP_BMP,
	TOP_INDEX = TSHIFT_INDEX + TWIDTH_INDEX,
};

typedef char static_assert_fields_fit_in_word
	[TOP_INDEX <= sizeof(word) * CHAR_BIT ? 1 : -1];

typedef char static_assert_bmp_fits
	[TOP_BMP <= sizeof(bitmap_t) * CHAR_BIT ? 1 : -1];

#define BIG1 ((word)1)
#define TMASK(width, shift) (((BIG1 << (width)) - BIG1) << (shift))

/*! \brief is this node a branch or a leaf? */
#define TFLAG_BRANCH (BIG1 << TSHIFT_BRANCH)

/*! \brief for extracting pointer to key */
#define TMASK_LEAF (~(word)TFLAG_BRANCH)

/*! \brief mask for extracting nibble index */
#define TMASK_INDEX TMASK(TWIDTH_INDEX, TSHIFT_INDEX)

/*! \brief mask for extracting bitmap */
#define TMASK_BMP TMASK(TWIDTH_BMP, TSHIFT_BMP)

/*! \brief bitmap entry for NOBYTE */
#define BMP_NOBYTE (BIG1 << TSHIFT_BMP)

/*! \brief Initialize a new leaf, copying the key, and returning failure code. */
static int mkleaf(node_t *leaf, const trie_key_t *key, uint32_t len, knot_mm_t *mm)
{
	tkey_t *lkey = mm_alloc(mm, sizeof(tkey_t) + len);
	if (unlikely(!lkey))
		return KNOT_ENOMEM;
	lkey->len = len;
	memcpy(lkey->chars, key, len);
	word i = (uintptr_t)lkey;
	assert((i & TFLAG_BRANCH) == 0);
	*leaf = (node_t){ .i = i, .p = NULL };
	return KNOT_EOK;
}

/*! \brief construct a branch node */
static node_t mkbranch(trie_index_t index, bitmap_t bmp, node_t *twigs)
{
	word i = TFLAG_BRANCH | bmp
		| (index << TSHIFT_INDEX);
	assert(index < TMAX_INDEX);
	assert((bmp & ~TMASK_BMP) == 0);
	return (node_t){ .i = i, .p = twigs };
}

/*! \brief Make an empty root node. */
static node_t empty_root(void)
{
	return mkbranch(TMAX_INDEX - 1, 0, NULL);
}

/*! \brief Propagate error codes. */
#define ERR_RETURN(x) \
	do { \
		int err_code_ = x; \
		if (unlikely(err_code_ != KNOT_EOK)) \
			return err_code_; \
	} while (false)


/*! \brief Test flags to determine type of this node. */
static bool isbranch(const node_t *t)
{
	return t->i & TFLAG_BRANCH;
}

/*! \brief Get the key stored in a leaf. */
static tkey_t *tkey(const node_t *t)
{
	assert(!isbranch(t));
	return (tkey_t *)(uintptr_t)(t->i & TMASK_LEAF);
}

/*! \brief Get pointer to the value stored in a leaf. */
static trie_val_t *tvalp(node_t *t)
{
	assert(!isbranch(t));
	return &t->p;
}

/*! \brief Only keep the lowest bit in the bitmap (least significant -> twigs[0]). */
static bitmap_t bitmap_lowest_bit(bitmap_t w)
{
	assert((w & ~TMASK_BMP) == 0);
	return (bitmap_t)1 << __builtin_ctz(w);
}

/*! \brief Given a branch node, return the index of the corresponding nibble in the key. */
static trie_index_t branch_index(const node_t *t)
{
	assert(isbranch(t));
	return (t->i & TMASK_INDEX) >> TSHIFT_INDEX;
}

/*! \brief Given a branch node, return the bitmap of present children. */
static bitmap_t branch_bmp(const node_t *t)
{
	assert(isbranch(t));
	return (t->i & TMASK_BMP);
}

/*!
 * \brief Count the children of a branch node.
 *
 * \TODO This implementation may be relatively slow on some HW.
 */
static uint branch_weight(const node_t *t)
{
	assert(isbranch(t));
	uint n = __builtin_popcount(branch_bmp(t));
	assert(n > 1 && n <= TWIDTH_BMP);
	return n;
}

/*! \brief Compute offset of an existing child in a branch node. */
static uint twigoff(const node_t *t, bitmap_t bit)
{
	assert(isbranch(t));
	assert(__builtin_popcount(bit) == 1);
	return __builtin_popcount(branch_bmp(t) & (bit - 1));
}

/*! \brief Extract a nibble from a key and turn it into a bitmask. */
static bitmap_t keybit(trie_index_t ni, const trie_key_t *key, uint32_t len)
{
	trie_index_t bytei = ni >> 1;

	if (bytei >= len)
		return BMP_NOBYTE;

	uint8_t ki = (uint8_t)key[bytei];
	uint nibble = (ni & 1) ? (ki & 0xf) : (ki >> 4);

	// skip one for BMP_NOBYTE nibbles after the end of the key
	return BIG1 << (nibble + 1 + TSHIFT_BMP);
}

/*! \brief Extract a nibble from a key and turn it into a bitmask. */
static bitmap_t twigbit(const node_t *t, const trie_key_t *key, uint32_t len)
{
	assert(isbranch(t));
	return keybit(branch_index(t), key, len);
}

/*! \brief Test if a branch node has a child indicated by a bitmask. */
static bool hastwig(const node_t *t, bitmap_t bit)
{
	assert(isbranch(t));
	assert((bit & ~TMASK_BMP) == 0);
	assert(__builtin_popcount(bit) == 1);
	return t->i & bit;
}

/*! \brief Get pointer to packed array of child nodes. */
static node_t* twigs(node_t *t)
{
	assert(isbranch(t));
	return t->p;
}

/*! \brief Get pointer to a particular child of a branch node. */
static node_t* twig(node_t *t, uint i)
{
	assert(i < branch_weight(t));
	return twigs(t) + i;
}

/*! \brief Get the position of a child node within its parent's twigs array. */
static uint twig_number(node_t *child, node_t *parent)
{
	// twig array index using pointer arithmetic
	ptrdiff_t num = child - twigs(parent);
	assert(num >= 0 && num < branch_weight(parent));
	return (uint)num;
}

/*! \brief Simple string comparator. */
static int key_cmp(const trie_key_t *k1, uint32_t k1_len,
		   const trie_key_t *k2, uint32_t k2_len)
{
	int ret = memcmp(k1, k2, MIN(k1_len, k2_len));
	if (ret != 0) {
		return ret;
	}

	/* Key string is equal, compare lengths. */
	if (k1_len == k2_len) {
		return 0;
	} else if (k1_len < k2_len) {
		return -1;
	} else {
		return 1;
	}
}

trie_t* trie_create(knot_mm_t *mm)
{
	trie_t *trie = mm_alloc(mm, sizeof(trie_t));
	if (trie != NULL) {
		trie->root = empty_root();
		trie->weight = 0;
		if (mm != NULL)
			trie->mm = *mm;
		else
			mm_ctx_init(&trie->mm);
	}
	return trie;
}

/*! \brief Free anything under the trie node, except for the passed pointer itself. */
static void clear_trie(node_t *trie, knot_mm_t *mm)
{
	if (!isbranch(trie)) {
		mm_free(mm, tkey(trie));
	} else {
		uint n = branch_weight(trie);
		for (uint i = 0; i < n; ++i)
			clear_trie(twig(trie, i), mm);
		mm_free(mm, twigs(trie));
	}
}

void trie_free(trie_t *tbl)
{
	if (tbl == NULL)
		return;
	if (tbl->weight)
		clear_trie(&tbl->root, &tbl->mm);
	mm_free(&tbl->mm, tbl);
}

void trie_clear(trie_t *tbl)
{
	if (kr_fails_assert(tbl))
		return;
	if (!tbl->weight)
		return;
	clear_trie(&tbl->root, &tbl->mm);
	tbl->root = empty_root();
	tbl->weight = 0;
}

size_t trie_weight(const trie_t *tbl)
{
	assert(tbl);
	return tbl->weight;
}

struct found {
	node_t *l;	/**< the found leaf (NULL if not found) */
	node_t *p;	/**< the leaf's parent (if exists) */
	bitmap_t b;	/**< bit-mask with a single bit marking l under p */
};

/** Search trie for an item with the given key (equality only). */
static struct found find_equal(trie_t *tbl, const trie_key_t *key, uint32_t len)
{
	assert(tbl);
	struct found ret0;
	memset(&ret0, 0, sizeof(ret0));
	if (!tbl->weight)
		return ret0;
	/* Current node and parent while descending (returned values basically). */
	node_t *t = &tbl->root;
	node_t *p = NULL;
	bitmap_t b = 0;
	while (isbranch(t)) {
		__builtin_prefetch(twigs(t));
		b = twigbit(t, key, len);
		if (!hastwig(t, b))
			return ret0;
		p = t;
		t = twig(t, twigoff(t, b));
	}
	tkey_t *lkey = tkey(t);
	if (key_cmp(key, len, lkey->chars, lkey->len) != 0)
		return ret0;
	return (struct found) {
		.l = t,
		.p = p,
		.b = b,
	};
}

trie_val_t* trie_get_try(trie_t *tbl, const trie_key_t *key, uint32_t len)
{
	struct found found = find_equal(tbl, key, len);
	return found.l ? tvalp(found.l) : NULL;
}

/** Find item with the first key (lexicographical order). */
static struct found find_first(trie_t *tbl)
{
	assert(tbl);
	if (!tbl->weight) {
		struct found ret0;
		memset(&ret0, 0, sizeof(ret0));
		return ret0;
	}
	/* Current node and parent while descending (returned values basically). */
	node_t *t = &tbl->root;
	node_t *p = NULL;
	while (isbranch(t)) {
		p = t;
		t = twig(p, 0);
	}
	return (struct found) {
		.l = t,
		.p = p,
		.b = p ? bitmap_lowest_bit(branch_bmp(p)) : 0,
	};
}

trie_val_t* trie_get_first(trie_t *tbl, trie_key_t **key, uint32_t *len)
{
	struct found found = find_first(tbl);
	if (!found.l)
		return NULL;
	if (key)
		*key = tkey(found.l)->chars;
	if (len)
		*len = tkey(found.l)->len;
	return tvalp(found.l);
}

/* Optimization: the approach isn't ideal, as e.g. walking through the prefix
 * is duplicated and we explicitly construct the wildcard key.  Still, it's close
 * to optimum which would be significantly more complicated and error-prone to write. */
trie_val_t* trie_get_try_wildcard(trie_t *tbl, const trie_key_t *key, uint32_t len)
{
	assert(tbl);
	if (!tbl->weight)
		return NULL;
	// Find leaf sharing the longest common prefix; see ns_find_branch() for explanation.
	node_t *t = &tbl->root;
	while (isbranch(t)) {
		__builtin_prefetch(twigs(t));
		bitmap_t b = twigbit(t, key, len);
		uint i = hastwig(t, b) ? twigoff(t, b) : 0;
		t = twig(t, i);
	}
	const tkey_t * const lcp_key = tkey(t);

	// Find the last matching zero byte or -1 (source of synthesis)
	int64_t i_lmz = -1; // signed type so -1 value is a distinct sentinel value
	for (uint32_t i = 0; i < len && i < lcp_key->len && key[i] == lcp_key->chars[i]; ++i) {
		if (key[i] == '\0' && i < len - 1) // do not count the terminating zero
			i_lmz = i;
		// Shortcut: we may have found an exact match.
		if (i == len - 1 && len == lcp_key->len)
			return tvalp(t);
	}
	if (len == 0) // The empty name needs separate handling.
		return lcp_key->len == 0 ? tvalp(t) : NULL;

	// Construct the key of the wildcard we need and look it up.
	const uint32_t wild_len = (uint32_t)(i_lmz + 3);
	trie_key_t wild_key[wild_len];
	memcpy(wild_key, key, wild_len - 2);
	wild_key[wild_len - 2] = '*';
	wild_key[wild_len - 1] = '\0'; // LF is always 0-terminated ATM
	return trie_get_try(tbl, wild_key, wild_len);
}

/*!
 * \brief Find longest-matching prefix leaf with '\0'-delimited boundary check.
 *
 * Uses a blind descent to locate a leaf sharing a common prefix with key,
 * then verifies full prefix equality and a '\0' label/separator boundary when
 * the stored key is shorter than the query.
 */
const trie_key_t *trie_find_prefix_match(const trie_t *tbl, const char *key, uint32_t len)
{
	assert(tbl);
	if (!tbl->weight)
		return NULL;

	// Perform the blind descent to find the closest LCP leaf
	const node_t *t = &tbl->root;
	while (isbranch(t)) {
		__builtin_prefetch(twigs(t));
		bitmap_t b = twigbit(t, key, len);
		uint i = hastwig(t, b) ? twigoff(t, b) : 0;
		t = twig(t, i);
	}
	const tkey_t * const lcp_key = tkey(t);

	// The stored key cannot be longer than the query if it's a prefix
	if (lcp_key->len > len || len == 0)
		return NULL;

	// Verify byte-for-byte match up to the stored key's length
	if (memcmp(lcp_key->chars, key, lcp_key->len) != 0)
		return NULL;

	// If the stored key is shorter than the query, the character immediately
	// following it in the query MUST be a '\0' separator.
	// This prevents "examples.com" from falsely matching a query for "example.com".
	if (lcp_key->len < len && key[lcp_key->len] != '\0')
		return NULL;

	return lcp_key->chars; // Returns the pointer to the matched parent/exact key!
}

/*! \brief Delete leaf t with parent p; b is the bit for t under p.
 * Optionally return the deleted value via val.  The function can't fail. */
static int del_found(trie_t *tbl, struct found found, trie_val_t *val)
{
	node_t *t = found.l;
	node_t * const p = found.p;

	if (!t)
		return KNOT_ENOENT;
	mm_free(&tbl->mm, tkey(t));
	if (val != NULL)
		*val = *tvalp(t); // we return trie_val_t directly when deleting
	--tbl->weight;
	if (unlikely(!p)) { // whole trie was a single leaf
		assert(tbl->weight == 0);
		tbl->root = empty_root();
		return KNOT_EOK;
	}
	// remove leaf t as child of p
	node_t *tp = twigs(p);
	uint ci = twig_number(t, p);
	uint cc = branch_weight(p); // child count
	assert(ci >= 0 && ci < cc);

	if (cc == 2) {
		// collapse binary node p: move the other child to the parent
		*p = tp[1 - ci]; // it might be a leaf or branch
		mm_free(&tbl->mm, tp);
		return KNOT_EOK;
	}
	memmove(tp + ci, tp + ci + 1, sizeof(node_t) * (cc - ci - 1));
	node_t *newt = mm_realloc(&tbl->mm, tp, sizeof(node_t) * (cc - 1),
	                          sizeof(node_t) * cc);
	// We can ignore mm_realloc failure because an oversized twig
	// array is OK - only beware that next time the prev_size
	// passed to mm_realloc will not be correct; TODO?
	*p = mkbranch(branch_index(p), branch_bmp(p) & ~found.b,
	              likely(newt != NULL) ? newt : tp);
	return KNOT_EOK;
}

int trie_del(trie_t *tbl, const trie_key_t *key, uint32_t len, trie_val_t *val)
{
	struct found found = find_equal(tbl, key, len);
	return del_found(tbl, found, val);
}

int trie_del_first(trie_t *tbl, trie_key_t *key, uint32_t *len, trie_val_t *val)
{
	struct found found = find_first(tbl);
	if (!found.l)
		return KNOT_ENOENT;
	if (key) {
		if (!len)
			return KNOT_EINVAL;
		if (*len < tkey(found.l)->len)
			return kr_error(ENOSPC);
		memcpy(key, tkey(found.l)->chars, tkey(found.l)->len);
	}
	if (len) { // makes sense even with key == NULL
		*len = tkey(found.l)->len;
	}
	return del_found(tbl, found, val);
}

/*!
 * \brief Stack of nodes, storing a path down a trie.
 *
 * The structure also serves directly as the public trie_it_t type,
 * in which case it always points to the current leaf, unless we've finished
 * (i.e. it->len == 0).
 * stack[0] is always a valid pointer to the root -> ns_gettrie()
 */
typedef struct trie_it {
	node_t* *stack; /*!< The stack; malloc is used directly instead of mm. */
	uint32_t len;   /*!< Current length of the stack. */
	uint32_t alen;  /*!< Allocated/available length of the stack. */
	/*! \brief Initial storage for \a stack; it should fit in most use cases. */
	node_t* stack_init[60];
} nstack_t;

/*! \brief Create a node stack containing just the root (or empty). */
static void ns_init(nstack_t *ns, trie_t *tbl)
{
	assert(tbl);
	ns->stack = ns->stack_init;
	ns->alen = sizeof(ns->stack_init) / sizeof(ns->stack_init[0]);
	// Keep &tbl->root in stack[0] even when empty (len == 0).
	ns->stack[0] = &tbl->root;
	ns->len = (tbl->weight > 0);
}

static inline trie_t * ns_gettrie(nstack_t *ns)
{
	assert(ns && ns->stack && ns->stack[0]);
	return (struct trie *)ns->stack[0];
}

/*! \brief Free inside of the stack, i.e. not the passed pointer itself. */
static void ns_cleanup(nstack_t *ns)
{
	if (kr_fails_assert(ns && ns->stack))
		return;
	if (likely(ns->stack == ns->stack_init))
		return;
	free(ns->stack);
	#ifndef NDEBUG
		ns->stack = NULL;
		ns->alen = 0;
	#endif
}

/*! \brief Allocate more space for the stack. */
static int ns_longer_alloc(nstack_t *ns)
{
	ns->alen *= 2;
	size_t new_size = ns->alen * sizeof(node_t *);
	node_t **st;
	if (ns->stack == ns->stack_init) {
		st = malloc(new_size);
		if (st != NULL)
			memcpy(st, ns->stack, ns->len * sizeof(node_t *));
	} else {
		st = realloc(ns->stack, new_size);
		if (st == NULL) {
			free(ns->stack); // left behind by realloc, callers bail out
			ns->stack = NULL;
		}
	}
	if (st == NULL)
		return KNOT_ENOMEM;
	ns->stack = st;
	return KNOT_EOK;
}

/*! \brief Ensure the node stack can be extended by one. */
static inline int ns_longer(nstack_t *ns)
{
	// get a longer stack if needed
	if (likely(ns->len < ns->alen))
		return KNOT_EOK;
	return ns_longer_alloc(ns); // hand-split the part suitable for inlining
}

/*!
 * \brief Find the "branching point" as if searching for a key.
 *
 *  The whole path to the point is kept on the passed stack;
 *  always at least the root will remain on the top of it.
 *  Beware: the precise semantics of this function is rather tricky.
 *  The top of the stack will contain: the corresponding leaf if exact
 *  match is found; or the immediate node below a
 *  branching-point-on-edge or the branching-point itself.
 *
 *  \param idiff  Set the index of first differing nibble, or TMAX_INDEX for an exact match
 *  \param tbit   Set the bit of the closest leaf's nibble at index idiff
 *  \param kbit   Set the bit of the key's nibble at index idiff
 *
 *  \return KNOT_EOK or KNOT_ENOMEM.
 */
static int ns_find_branch(nstack_t *ns, const trie_key_t *key, uint32_t len,
                          trie_index_t *idiff, bitmap_t *tbit, bitmap_t *kbit)
{
	assert(ns && ns->len && idiff);
	// First find some leaf with longest matching prefix.
	while (isbranch(ns->stack[ns->len - 1])) {
		ERR_RETURN(ns_longer(ns));
		node_t *t = ns->stack[ns->len - 1];
		__builtin_prefetch(twigs(t));
		bitmap_t b = twigbit(t, key, len);
		// Even if our key is missing from this branch we need to
		// keep iterating down to a leaf. It doesn't matter which
		// twig we choose since the keys are all the same up to this
		// index. Note that blindly using twigoff(t, b) can cause
		// an out-of-bounds index if it equals twigmax(t).
		uint i = hastwig(t, b) ? twigoff(t, b) : 0;
		ns->stack[ns->len++] = twig(t, i);
	}
	tkey_t *lkey = tkey(ns->stack[ns->len - 1]);
	// Find index of the first char that differs.
	size_t bytei = 0;
	uint32_t klen = lkey->len;
	for (bytei = 0; bytei < MIN(len, klen); bytei++) {
		if (key[bytei] != lkey->chars[bytei])
			break;
	}
	// Find which half-byte has matched.
	trie_index_t index = bytei << 1;
	if (bytei == len && len == klen) { // found equivalent key
		index = TMAX_INDEX;
		goto success;
	}
	if (likely(bytei < MIN(len, klen))) {
		uint8_t k2 = (uint8_t)lkey->chars[bytei];
		uint8_t k1 = (uint8_t)key[bytei];
		if (((k1 ^ k2) & 0xf0) == 0)
			index += 1;
	}
	// now go up the trie from the current leaf
	node_t *t;
	do {
		if (unlikely(ns->len == 1))
			goto success; // only the root stays on the stack
		t = ns->stack[ns->len - 2];
		if (branch_index(t) < index)
			goto success;
		--ns->len;
	} while (true);
success:
	#ifndef NDEBUG // invariants on successful return
		assert(ns->len);
		if (isbranch(ns->stack[ns->len - 1])) {
			t = ns->stack[ns->len - 1];
			assert(branch_index(t) >= index);
		}
		if (ns->len > 1) {
			t = ns->stack[ns->len - 2];
			assert(branch_index(t) < index || index == TMAX_INDEX);
		}
	#endif
	*idiff = index;
	*tbit = keybit(index, lkey->chars, lkey->len);
	*kbit = keybit(index, key, len);
	return KNOT_EOK;
}

/*!
 * \brief Advance the node stack to the last leaf in the subtree.
 *
 * \return KNOT_EOK or KNOT_ENOMEM.
 */
static int ns_last_leaf(nstack_t *ns)
{
	assert(ns);
	do {
		ERR_RETURN(ns_longer(ns));
		node_t *t = ns->stack[ns->len - 1];
		if (!isbranch(t))
			return KNOT_EOK;
		uint lasti = branch_weight(t) - 1;
		assert(lasti >= 0);
		ns->stack[ns->len++] = twig(t, lasti);
	} while (true);
}

/*!
 * \brief Advance the node stack to the first leaf in the subtree.
 *
 * \return KNOT_EOK or KNOT_ENOMEM.
 */
static int ns_first_leaf(nstack_t *ns)
{
	assert(ns && ns->len);
	do {
		ERR_RETURN(ns_longer(ns));
		node_t *t = ns->stack[ns->len - 1];
		if (!isbranch(t))
			return KNOT_EOK;
		ns->stack[ns->len++] = twig(t, 0);
	} while (true);
}

/*!
 * \brief Advance the node stack to the leaf that is previous to the current node.
 *
 * \note Prefix leaf under the current node DOES count (if present; perhaps questionable).
 * \return KNOT_EOK on success, KNOT_ENOENT on not-found, or possibly KNOT_ENOMEM.
 */
static int ns_prev_leaf(nstack_t *ns)
{
	assert(ns && ns->len > 0);

	node_t *t = ns->stack[ns->len - 1];
	// Beware: BMP_NOBYTE child is ordered *before* its parent.
	if (isbranch(t) && hastwig(t, BMP_NOBYTE)) {
		ERR_RETURN(ns_longer(ns));
		ns->stack[ns->len++] = twig(t, 0);
		return KNOT_EOK;
	}

	for (; ns->len >= 2; --ns->len) {
		t = ns->stack[ns->len - 1];
		node_t *p = ns->stack[ns->len - 2];
		uint ci = twig_number(t, p);
		assert(ci >= 0 && ci <= 16);
		if (ci == 0) // we've got to go up again
			continue;
		// t isn't the first child -> go down the previous one
		ns->stack[ns->len - 1] = twig(p, ci - 1);
		return ns_last_leaf(ns);
	}
	return KNOT_ENOENT; // root without empty key has no previous leaf
}

/*!
 * \brief Advance the node stack to the leaf that is successor to the current node.
 *
 * \param skip_prefixed skip any nodes whose key is a prefix of the current one.
 *     If false, prefix leaf or anything else under the current node DOES count.
 * \return KNOT_EOK on success, KNOT_ENOENT on not-found, or possibly KNOT_ENOMEM.
 */
static int ns_next_leaf(nstack_t *ns, const bool skip_prefixed)
{
	assert(ns && ns->len > 0);

	node_t *t = ns->stack[ns->len - 1];
	if (!skip_prefixed && isbranch(t))
		return ns_first_leaf(ns);
	for (; ns->len >= 2; --ns->len) {
		t = ns->stack[ns->len - 1];
		node_t *p = ns->stack[ns->len - 2];
		uint ci = twig_number(t, p);
		if (skip_prefixed && ci == 0 && hastwig(t, BMP_NOBYTE)) {
			// Keys in the subtree of p are suffixes of the key of t,
			// so we've got to go one level higher
			// (this can't happen more than once)
			continue;
		}
		uint cc = branch_weight(p);
		assert(ci + 1 <= cc);
		if (ci + 1 == cc) {
			// t is the last child of p, so we need to keep climbing
			continue;
		}
		// go down the next child of p
		ns->stack[ns->len - 1] = twig(p, ci + 1);
		return ns_first_leaf(ns);
	}
	return KNOT_ENOENT; // not found, as no more parent is available
}

/*! \brief Advance the node stack to leaf with longest prefix of the current key. */
static int ns_prefix(nstack_t *ns)
{
	assert(ns && ns->len > 0);
	const node_t *start = ns->stack[ns->len - 1];
	// Walk up the trie until we find a BMP_NOBYTE child.
	while (--ns->len > 0) {
		node_t *p = ns->stack[ns->len - 1];
		if (!hastwig(p, BMP_NOBYTE))
			continue;
		node_t *end = twig(p, 0);
		// In case we started in a BMP_NOBYTE leaf, the first step up
		// did NOT shorten the key and we would get back into the same
		// node again.
		if (end == start)
			continue;
		ns->stack[ns->len++] = end;
		return KNOT_EOK;
	}
	return KNOT_ENOENT; // not found, as no more parent is available
}

/*! \brief less-or-equal search.
 *
 * \return KNOT_EOK for exact match, 1 for previous, KNOT_ENOENT for not-found,
 *         or KNOT_E*.
 */
static int ns_get_leq(nstack_t *ns, const trie_key_t *key, uint32_t len)
{
	// First find the key with longest-matching prefix
	trie_index_t idiff;
	bitmap_t tbit, kbit;
	ERR_RETURN(ns_find_branch(ns, key, len, &idiff, &tbit, &kbit));
	node_t *t = ns->stack[ns->len - 1];
	if (idiff == TMAX_INDEX) // found exact match
		return KNOT_EOK;
	// Get t: the last node on matching path
	bitmap_t b;
	if (isbranch(t) && branch_index(t) == idiff) {
		// t is OK
		b = kbit;
	} else {
		// the top of the stack was the first unmatched node -> step up
		if (ns->len == 1) {
			// root was unmatched already
			if (kbit < tbit)
				return KNOT_ENOENT;
			ERR_RETURN(ns_last_leaf(ns));
			return 1;
		}
		--ns->len;
		t = ns->stack[ns->len - 1];
		b = twigbit(t, key, len);
	}
	// Now we re-do the first "non-matching" step in the trie
	// but try the previous child if key was less (it may not exist)
	int i = hastwig(t, b)
		? (int)twigoff(t, b) - (kbit < tbit)
		: (int)twigoff(t, b) - 1 /* twigoff returns successor when !hastwig */;
	if (i >= 0) {
		ERR_RETURN(ns_longer(ns));
		ns->stack[ns->len++] = twig(t, i);
		ERR_RETURN(ns_last_leaf(ns));
	} else {
		ERR_RETURN(ns_prev_leaf(ns));
	}
	return 1;
}

int trie_get_leq(trie_t *tbl, const trie_key_t *key, uint32_t len, trie_val_t **val)
{
	assert(tbl && val);
	if (tbl->weight == 0) {
		if (val) *val = NULL;
		return KNOT_ENOENT;
	}
	// We try to do without malloc.
	nstack_t ns_local;
	ns_init(&ns_local, tbl);
	nstack_t *ns = &ns_local;

	int ret = ns_get_leq(ns, key, len);
	if (ret == KNOT_EOK || ret == 1) {
		assert(!isbranch(ns->stack[ns->len - 1]));
		if (val) *val = tvalp(ns->stack[ns->len - 1]);
	} else {
		if (val) *val = NULL;
	}
	ns_cleanup(ns);
	return ret;
}

int trie_it_get_leq(trie_it_t *it, const trie_key_t *key, uint32_t len)
{
	assert(it && it->stack[0] && it->alen);
	const trie_t *tbl = ns_gettrie(it);
	if (tbl->weight == 0) {
		it->len = 0;
		return KNOT_ENOENT;
	}
	it->len = 1;
	int ret = ns_get_leq(it, key, len);
	if (ret == KNOT_EOK || ret == 1) {
		assert(trie_it_key(it, NULL));
	} else {
		it->len = 0;
	}
	return ret;
}

trie_val_t* trie_get_ins(trie_t *tbl, const trie_key_t *key, uint32_t len)
{
	if (kr_fails_assert(tbl))
		return NULL;
	// First leaf in an empty tbl?
	if (unlikely(!tbl->weight)) {
		if (unlikely(mkleaf(&tbl->root, key, len, &tbl->mm)))
			return NULL;
		++tbl->weight;
		return tvalp(&tbl->root);
	}
	{ // Intentionally un-indented; until end of function, to bound cleanup attr.
	// Find the branching-point
	__attribute__((cleanup(ns_cleanup)))
		nstack_t ns_local;
	ns_init(&ns_local, tbl);
	nstack_t *ns = &ns_local;
	trie_index_t idiff;
	bitmap_t tbit, kbit;
	if (unlikely(ns_find_branch(ns, key, len, &idiff, &tbit, &kbit)))
		return NULL;
	node_t *t = ns->stack[ns->len - 1];
	if (idiff == TMAX_INDEX) // the same key was already present
		return tvalp(t);
	node_t leaf, *leafp;
	if (unlikely(mkleaf(&leaf, key, len, &tbl->mm)))
		return NULL;

	if (isbranch(t) && branch_index(t) == idiff) {
		// The node t needs a new leaf child.
		assert(!hastwig(t, kbit));
		// new child position and original child count
		uint s = twigoff(t, kbit);
		uint m = branch_weight(t);
		node_t *nt = mm_realloc(&tbl->mm, twigs(t),
				sizeof(node_t) * (m + 1), sizeof(node_t) * m);
		if (unlikely(!nt))
			goto err_leaf;
		memmove(nt + s + 1, nt + s, sizeof(node_t) * (m - s));
		leafp = nt + s;
		*t = mkbranch(idiff, branch_bmp(t) | kbit, nt);
	} else {
		// We need to insert a new binary branch with leaf at *t.
		// Note: it works the same for the case where we insert above root t.
		#ifndef NDEBUG
			if (ns->len > 1) {
				node_t *pt = ns->stack[ns->len - 2];
				assert(hastwig(pt, twigbit(pt, key, len)));
			}
		#endif
		node_t *nt = mm_alloc(&tbl->mm, sizeof(node_t) * 2);
		if (unlikely(!nt))
			goto err_leaf;
		node_t t2 = *t; // Save before overwriting t.
		*t = mkbranch(idiff, tbit | kbit, nt);
		*twig(t, twigoff(t, tbit)) = t2;
		leafp = twig(t, twigoff(t, kbit));
	};
	*leafp = leaf;
	++tbl->weight;
	return tvalp(leafp);
err_leaf:
	mm_free(&tbl->mm, tkey(&leaf));
	return NULL;
	}
}

/*! \brief Apply a function to every trie_val_t*, in order; a recursive solution. */
static int apply_nodes(node_t *t, int (*f)(trie_val_t *, void *), void *d)
{
	assert(t);
	if (!isbranch(t))
		return f(tvalp(t), d);
	uint n = branch_weight(t);
	for (uint i = 0; i < n; ++i)
		ERR_RETURN(apply_nodes(twig(t, i), f, d));
	return KNOT_EOK;
}

int trie_apply(trie_t *tbl, int (*f)(trie_val_t *, void *), void *d)
{
	assert(tbl && f);
	if (!tbl->weight)
		return KNOT_EOK;
	return apply_nodes(&tbl->root, f, d);
}

/*! \brief Apply a function to every key + trie_val_t*, in order; a recursive solution. */
static int apply_trie_with_key(node_t *t, int (*f)(const trie_key_t *, uint32_t, trie_val_t *, void *), void *d)
{
	assert(t);
	if (!isbranch(t))
		return f(tkey(t)->chars, tkey(t)->len, tvalp(t), d);
	uint n = branch_weight(t);
	for (uint i = 0; i < n; ++i)
		ERR_RETURN(apply_trie_with_key(twig(t, i), f, d));
	return KNOT_EOK;
}

int trie_apply_with_key(trie_t *tbl, int (*f)(const trie_key_t *, uint32_t, trie_val_t *, void *), void *d)
{
	assert(tbl && f);
	if (!tbl->weight)
		return KNOT_EOK;
	return apply_trie_with_key(&tbl->root, f, d);
}

/* These are all thin wrappers around static Tns* functions. */
trie_it_t* trie_it_begin(trie_t *tbl)
{
	if (kr_fails_assert(tbl))
		return NULL;
	trie_it_t *it = malloc(sizeof(nstack_t));
	if (!it)
		return NULL;
	ns_init(it, tbl);
	if (it->len == 0) // empty tbl
		return it;
	if (ns_first_leaf(it)) {
		ns_cleanup(it);
		free(it);
		return NULL;
	}
	return it;
}

bool trie_it_finished(trie_it_t *it)
{
	assert(it);
	return it->len == 0;
}

void trie_it_free(trie_it_t *it)
{
	if (!it)
		return;
	ns_cleanup(it);
	free(it);
}

trie_it_t *trie_it_clone(const trie_it_t *it)
{
	if (!it) // TODO: or should that be an assertion?
		return NULL;
	trie_it_t *it2 = malloc(sizeof(nstack_t));
	if (!it2)
		return NULL;
	it2->len = it->len;
	it2->alen = it->alen; // we _might_ change it in the rare malloc case, but...
	if (likely(it->stack == it->stack_init)) {
		it2->stack = it2->stack_init;
		assert(it->alen == sizeof(it->stack_init) / sizeof(it->stack_init[0]));
	} else {
		it2->stack = malloc(it2->alen * sizeof(it2->stack[0]));
		if (!it2->stack) {
			free(it2);
			return NULL;
		}
	}
	memcpy(it2->stack, it->stack, it->len * sizeof(it->stack[0]));
	return it2;
}

const trie_key_t* trie_it_key(trie_it_t *it, size_t *len)
{
	assert(it && it->len);
	node_t *t = it->stack[it->len - 1];
	assert(!isbranch(t));
	tkey_t *key = tkey(t);
	if (len)
		*len = key->len;
	return key->chars;
}

trie_val_t* trie_it_val(trie_it_t *it)
{
	assert(it && it->len);
	node_t *t = it->stack[it->len - 1];
	assert(!isbranch(t));
	return tvalp(t);
}

void trie_it_next(trie_it_t *it)
{
	assert(it && it->len);
	if (ns_next_leaf(it, false) != KNOT_EOK)
		it->len = 0;
}

void trie_it_next_loop(trie_it_t *it)
{
	assert(it && it->len);
	int ret = ns_next_leaf(it, false);
	if (ret == KNOT_ENOENT) {
		it->len = 1;
		ret = ns_first_leaf(it);
	}
	if (ret)
		it->len = 0;
}

void trie_it_next_nosuffix(trie_it_t *it)
{
	assert(it && it->len);
	if (ns_next_leaf(it, true) != KNOT_EOK)
		it->len = 0;
}

void trie_it_prev(trie_it_t *it)
{
	assert(it && it->len);
	if (ns_prev_leaf(it) != KNOT_EOK)
		it->len = 0;
}

void trie_it_prev_loop(trie_it_t *it)
{
	assert(it && it->len);
	int ret = ns_prev_leaf(it);
	if (ret == KNOT_ENOENT) {
		it->len = 1;
		ret = ns_last_leaf(it);
	}
	if (ret)
		it->len = 0;
}

void trie_it_parent(trie_it_t *it)
{
	assert(it && it->len);
	if (ns_prefix(it))
		it->len = 0;
}

void trie_it_del(trie_it_t *it)
{
	assert(it && it->len);
	if (it->len == 0)
		return;
	struct found found = {
		.l = it->stack[it->len - 1],
		.p = NULL,
		.b = 0, // del_found() needs to know which bit to zero in the bitmap
	};
	assert(!isbranch(found.l));
	if (it->len > 1) { // deleting the root
		found.p = it->stack[it->len - 2];
		assert(isbranch(found.p));
		size_t len;
		const trie_key_t *key = trie_it_key(it, &len);
		found.b = twigbit(found.p, key, len);
	}
	// We could trie_it_{next,prev,...}(it) now, in case we wanted that semantics.
	it->len = 0;
	del_found(ns_gettrie(it), found, NULL);
}
