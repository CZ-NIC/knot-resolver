/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
    Copyright (C) 2018 Tony Finch <dot@dotat.at>

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

typedef unsigned char byte;
typedef unsigned int uint;
typedef uint64_t index_t; /*!< nibble index into a key */
typedef uint64_t word; /*!< A type-punned word */
typedef uint bitmap_t; /*!< Bit-maps, using the range of 1<<0 to 1<<16 (inclusive). */

typedef char static_assert_pointer_fits_in_word
	[sizeof(word) >= sizeof(uintptr_t) ? 1 : -1];

#define KEYLENBITS 31

/*! \brief trie keys have lengths
 *
 * 32 bits are enough for key lengths; probably even 16 bits would be.
 * However, a 32 bit length means the alignment will be a multiple of
 * 4, allowing us to stash the COW and BRANCH flags in the bottom bits
 * of a pointer to a key.
 *
 * We need to steal a couple of bits from the length to keep the COW
 * state of key allocations.
 */
typedef struct {
	uint32_t cow:1, len:KEYLENBITS;
	char chars[];
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
 * up to the nibble identified by the branch.
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
	TSHIFT_COW,
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

/*! \brief copy-on-write flag, used in both leaves and branches */
#define TFLAG_COW (BIG1 << TSHIFT_COW)

/*! \brief for extracting pointer to key */
#define TMASK_LEAF (~(word)(TFLAG_BRANCH | TFLAG_COW))

/*! \brief mask for extracting nibble index */
#define TMASK_INDEX TMASK(TWIDTH_INDEX,  TSHIFT_INDEX)

/*! \brief mask for extracting bitmap */
#define TMASK_BMP TMASK(TWIDTH_BMP,  TSHIFT_BMP)

/*! \brief bitmap entry for NOBYTE */
#define BMP_NOBYTE (BIG1 << TSHIFT_BMP)

/*! \brief Initialize a new leaf, copying the key, and returning failure code. */
static int mkleaf(node_t *leaf, const char *key, uint32_t len, knot_mm_t *mm)
{
	if (unlikely((word)len > (BIG1 << KEYLENBITS)))
		return KNOT_ENOMEM;
	tkey_t *lkey = mm_alloc(mm, sizeof(tkey_t) + len);
	if (unlikely(!lkey))
		return KNOT_ENOMEM;
	lkey->cow = 0;
	lkey->len = len;
	memcpy(lkey->chars, key, len);
	word i = (uintptr_t)lkey;
	assert((i & TFLAG_BRANCH) == 0);
	*leaf = (node_t){ .i = i, .p = NULL };
	return KNOT_EOK;
}

/*! \brief construct a branch node */
static node_t mkbranch(index_t index, bitmap_t bmp, node_t *twigs)
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
	return mkbranch(TMAX_INDEX-1, 0, NULL);
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

static tkey_t *tkey(const node_t *t)
{
	assert(!isbranch(t));
	return (tkey_t *)(uintptr_t)(t->i & TMASK_LEAF);
}

static trie_val_t *tvalp(node_t *t)
{
	assert(!isbranch(t));
	return &t->p;
}

/*! \brief Given a branch node, return the index of the corresponding nibble in the key. */
static index_t branch_index(const node_t *t)
{
	assert(isbranch(t));
	return (t->i & TMASK_INDEX) >> TSHIFT_INDEX;
}

static bitmap_t branch_bmp(const node_t *t)
{
	assert(isbranch(t));
	return (t->i & TMASK_BMP);
}

/*!
 * \brief Count the number of set bits.
 *
 * \TODO This implementation may be relatively slow on some HW.
 */
static uint branch_weight(const node_t *t)
{
	assert(isbranch(t));
	uint n = __builtin_popcount(t->i & TMASK_BMP);
	assert(n > 1 && n <= TWIDTH_BMP);
	return n;
}

/*! \brief Compute offset of an existing child in a branch node. */
static uint twigoff(const node_t *t, bitmap_t bit)
{
	assert(isbranch(t));
	assert(__builtin_popcount(bit) == 1);
	return __builtin_popcount(t->i & TMASK_BMP & (bit - 1));
}

/*! \brief Extract a nibble from a key and turn it into a bitmask. */
static bitmap_t keybit(index_t ni, const char *key, uint32_t len)
{
	index_t bytei = ni >> 1;

	if (bytei >= len)
		return BMP_NOBYTE;

	byte ki = (byte)key[bytei];
	uint nibble = (ni & 1) ? (ki & 0xf) : (ki >> 4);

	// skip one for NOBYTE nibbles after the end of the key
	return BIG1 << (nibble + 1 + TSHIFT_BMP);
}

/*! \brief Extract a nibble from a key and turn it into a bitmask. */
static bitmap_t twigbit(const node_t *t, const char *key, uint32_t len)
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

/*! \brief Get twig number of a child node FIXME */
static uint twig_number(node_t *child, node_t *parent)
{
	// twig array index using pointer arithmetic
	ptrdiff_t num = child - twigs(parent);
	assert(num >= 0 && num < branch_weight(parent));
	return (uint)num;
}

/*! \brief Simple string comparator. */
static int key_cmp(const char *k1, uint32_t k1_len, const char *k2, uint32_t k2_len)
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
	assert(tbl);
	if (!tbl->weight)
		return;
	clear_trie(&tbl->root, &tbl->mm);
	tbl->root = empty_root();
	tbl->weight = 0;
}

static bool dup_trie(node_t *copy, const node_t *orig, trie_dup_cb dup_cb, knot_mm_t *mm)
{
	if (isbranch(orig)) {
		uint n = branch_weight(orig);
		node_t *cotw = mm_alloc(mm, n * sizeof(*cotw));
		if (cotw == NULL) {
			return NULL;
		}
		const node_t *ortw = twigs((node_t *)orig);
		for (uint i = 0; i < n; ++i) {
			if (!dup_trie(cotw + i, ortw + i, dup_cb, mm)) {
				while (i-- > 0) {
					clear_trie(cotw + i, mm);
				}
				mm_free(mm, cotw);
				return false;
			}
		}
		*copy = mkbranch(branch_index(orig), branch_bmp(orig), cotw);
	} else {
		tkey_t *key = tkey(orig);
		if (mkleaf(copy, key->chars, key->len, mm) != KNOT_EOK) {
			return false;
		}
		if ((copy->p = dup_cb(orig->p, mm)) == NULL) {
			mm_free(mm, tkey(copy));
			return false;
		}
	}
	return true;
}

trie_t* trie_dup(const trie_t *orig, trie_dup_cb dup_cb, knot_mm_t *mm)
{
	if (orig == NULL) {
		return NULL;
	}
	trie_t *copy = mm_alloc(mm, sizeof(*copy));
	if (copy == NULL) {
		return NULL;
	}
	copy->weight = orig->weight;
	if (mm != NULL) {
		copy->mm = *mm;
	} else {
		mm_ctx_init(&copy->mm);
	}
	if (copy->weight) {
		if (!dup_trie(&copy->root, &orig->root, dup_cb, mm)) {
			mm_free(mm, copy);
			return NULL;
		}
	}
	return copy;
}

size_t trie_weight(const trie_t *tbl)
{
	assert(tbl);
	return tbl->weight;
}

trie_val_t* trie_get_try(trie_t *tbl, const char *key, uint32_t len)
{
	assert(tbl);
	if (!tbl->weight)
		return NULL;
	node_t *t = &tbl->root;
	while (isbranch(t)) {
		__builtin_prefetch(twigs(t));
		bitmap_t b = twigbit(t, key, len);
		if (!hastwig(t, b))
			return NULL;
		t = twig(t, twigoff(t, b));
	}
	tkey_t *lkey = tkey(t);
	if (key_cmp(key, len, lkey->chars, lkey->len) != 0)
		return NULL;
	return tvalp(t);
}

/*! \brief Delete leaf t with parent p; b is the bit for t under p.
 * Optionally return the deleted value via val.  The function can't fail. */
static void del_found(trie_t *tbl, node_t *t, node_t *p, bitmap_t b, trie_val_t *val)
{
	assert(!tkey(t)->cow);
	mm_free(&tbl->mm, tkey(t));
	if (val != NULL)
		*val = *tvalp(t); // we return trie_val_t directly when deleting
	--tbl->weight;
	if (unlikely(!p)) { // whole trie was a single leaf
		assert(tbl->weight == 0);
		tbl->root = empty_root();
		return;
	}
	// remove leaf t as child of p
	node_t *tp = twigs(p);
	uint ci = twig_number(t, p);
	uint cc = branch_weight(p); // child count

	if (cc == 2) {
		// collapse binary node p: move the other child to the parent
		*p = tp[1 - ci];
		mm_free(&tbl->mm, tp);
		return;
	}
	memmove(tp + ci, tp + ci + 1, sizeof(node_t) * (cc - ci - 1));
	p->i &= ~b;
	node_t *newt = mm_realloc(&tbl->mm, tp, sizeof(node_t) * (cc - 1),
				  sizeof(node_t) * cc);
	if (likely(newt != NULL))
		p->p = newt;
	// We can ignore mm_realloc failure because an oversized twig
	// array is OK - only beware that next time the prev_size
	// passed to mm_realloc will not be correct; TODO?
}

int trie_del(trie_t *tbl, const char *key, uint32_t len, trie_val_t *val)
{
	assert(tbl);
	if (!tbl->weight)
		return KNOT_ENOENT;
	node_t *t = &tbl->root; // current and parent node
	node_t *p = NULL;
	bitmap_t b = 0;
	while (isbranch(t)) {
		__builtin_prefetch(twigs(t));
		b = twigbit(t, key, len);
		if (!hastwig(t, b))
			return KNOT_ENOENT;
		p = t;
		t = twig(t, twigoff(t, b));
	}
	tkey_t *lkey = tkey(t);
	if (key_cmp(key, len, lkey->chars, lkey->len) != 0)
		return KNOT_ENOENT;
	del_found(tbl, t, p, b, val);
	return KNOT_EOK;
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
	node_t* stack_init[250];
} nstack_t;

/*! \brief Create a node stack containing just the root (or empty). */
static void ns_init(nstack_t *ns, trie_t *tbl)
{
	assert(tbl);
	ns->stack = ns->stack_init;
	ns->alen = sizeof(ns->stack_init) / sizeof(ns->stack_init[0]);
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
	assert(ns && ns->stack);
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
 *  \param tbit  Set the bit of the closest leaf's nibble at index idiff
 *  \param kbit  Set the bit of the key's nibble at index idiff
 *
 *  \return KNOT_EOK or KNOT_ENOMEM.
 */
static int ns_find_branch(nstack_t *ns, const char *key, uint32_t len,
                          index_t *idiff, bitmap_t *tbit, bitmap_t *kbit)
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
	tkey_t *lkey = tkey(ns->stack[ns->len-1]);
	// Find index of the first char that differs.
	size_t bytei = 0;
	uint32_t klen = lkey->len;
	for (bytei = 0; bytei < MIN(len,klen); bytei++) {
		if (key[bytei] != lkey->chars[bytei])
			break;
	}
	// Find which half-byte has matched.
	index_t index = bytei << 1;
	if (bytei == len && len == lkey->len) { // found equivalent key
		index = TMAX_INDEX;
		goto success;
	}
	if (likely(bytei < MIN(len,klen))) {
		byte k2 = (byte)lkey->chars[bytei];
		byte k1 = (byte)key[bytei];
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
	if (hastwig(t, BMP_NOBYTE)) {
		ERR_RETURN(ns_longer(ns));
		ns->stack[ns->len++] = twig(t, 0);
		return KNOT_EOK;
	}

	for (; ns->len >= 2; --ns->len) {
		t = ns->stack[ns->len - 1];
		node_t *p = ns->stack[ns->len - 2];
		uint ci = twig_number(t, p);
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
static int ns_next_leaf(nstack_t *ns, const bool skip_pefixed)
{
	assert(ns && ns->len > 0);

	node_t *t = ns->stack[ns->len - 1];
	if (!skip_pefixed && isbranch(t))
		return ns_first_leaf(ns);
	for (; ns->len >= 2; --ns->len) {
		t = ns->stack[ns->len - 1];
		node_t *p = ns->stack[ns->len - 2];
		uint ci = twig_number(t, p);
		if (skip_pefixed && ci == 0 && hastwig(t, BMP_NOBYTE)) {
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
	// Simply walk up the trie until we find a BMP_NOBYTE child (our result).
	while (--ns->len > 0) {
		node_t *p = ns->stack[ns->len - 1];
		if (hastwig(p, BMP_NOBYTE)) {
			ns->stack[ns->len++] = twig(p, 0);
			return KNOT_EOK;
		}
	}
	return KNOT_ENOENT; // not found, as no more parent is available
}

/*! \brief less-or-equal search.
 *
 * \return KNOT_EOK for exact match, 1 for previous, KNOT_ENOENT for not-found,
 *         or KNOT_E*.
 */
static int ns_get_leq(nstack_t *ns, const char *key, uint32_t len)
{
	// First find the key with longest-matching prefix
	index_t idiff;
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

int trie_get_leq(trie_t *tbl, const char *key, uint32_t len, trie_val_t **val)
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

int trie_it_get_leq(trie_it_t *it, const char *key, uint32_t len)
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

/* see below */
static int cow_pushdown(trie_cow_t *cow, nstack_t *ns);

/*! \brief implementation of trie_get_ins() and trie_get_cow() */
static trie_val_t* cow_get_ins(trie_cow_t *cow, trie_t *tbl,
			       const char *key, uint32_t len)
{
	assert(tbl);
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
	index_t idiff;
	bitmap_t tbit, kbit;
	if (unlikely(ns_find_branch(ns, key, len, &idiff, &tbit, &kbit)))
		return NULL;
	if (unlikely(cow && cow_pushdown(cow, ns) != KNOT_EOK))
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

trie_val_t* trie_get_ins(trie_t *tbl, const char *key, uint32_t len)
{
	return cow_get_ins(NULL, tbl, key, len);
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

/* These are all thin wrappers around static Tns* functions. */
trie_it_t* trie_it_begin(trie_t *tbl)
{
	assert(tbl);
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

const char* trie_it_key(trie_it_t *it, size_t *len)
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
	node_t *t = it->stack[it->len - 1];
	assert(!isbranch(t));
	bitmap_t b; // del_found() needs to know which bit to zero in the bitmap
	node_t *p;
	if (it->len == 1) { // deleting the root
		p = NULL;
		b = 0; // unused
	} else {
		p = it->stack[it->len - 2];
		assert(isbranch(p));
		size_t len;
		const char *key = trie_it_key(it, &len);
		b = twigbit(p, key, len);
	}
	// We could trie_it_{next,prev,...}(it) now, in case we wanted that semantics.
	it->len = 0;
	del_found(ns_gettrie(it), t, p, b, NULL);
}


/*!\file
 *
 * \section About copy-on-write
 *
 * In these notes I'll use the term "object" to refer to either the
 * twig array of a branch, or the application's data that is referred
 * to by a leaf's trie_val_t pointer. Note that for COW we don't care
 * about trie node_t structs themselves, but the objects that they
 * point to.
 *
 * \subsection COW states
 *
 * During a COW transaction an object can be in one of three states:
 * shared, only in the old trie, or only in the new trie. When a
 * transaction is rolled back, the only-new objects are freed; when a
 * transaction is committed the new trie takes the place of the old
 * one and only-old objects are freed.
 *
 * \subsection branch marks and regions
 *
 * A branch object can be marked by setting the COW flag in the first
 * element of its twig array. Marked branches partition the trie into
 * regions; an object's state depends on its region.
 *
 * The unmarked branch objects between a trie's root and the marked
 * branches (excluding the marked branches themselves) is exclusively
 * owned: either old-only (if you started from the old root) or
 * new-only (if you started from the new root).
 *
 * Marked branch objects, and all objects reachable from marked branch
 * objects, are in the shared region accessible from both old and new
 * roots. All branch objects below a marked branch must be unmarked.
 * (That is, there is at most one marked branch object on any path
 * from the root of a trie.)
 *
 * Branch nodes in the new-only region can be modified in place, in
 * the same way as an original qp trie. Branch nodes in the old-only
 * or shared regions must not be modified.
 *
 * \subsection app object states
 *
 * The app objects reachable from the new-only and old-only regions
 * explicitly record their state in a way determined by the
 * application. (These app objects are reachable from the old and new
 * roots by traversing only unmarked branch objects.)
 *
 * The app objects reachable from marked branch objects are implicitly
 * shared, but their state field has an indeterminate value. If an app
 * object was previously touched by a rolled-back transaction it may
 * be marked shared or old-only; if it was previously touched by a
 * committed transaction it may be marked shared or new-only.
 *
 * \subsection key states
 *
 * The memory allocated for tkey_t objects also needs to track its
 * sharing state. They have a "cow" flag to mark when they are shared.
 * Keys are relatively lazily copied (to make them exclusive) when
 * their leaf node is touched by a COW mutation.
 *
 * [An alternative technique might be to copy them more eagerly, in
 * cow_pushdown(), which would avoid the need for a flag bit at the
 * cost of more allocator churn in a transaction.]
 *
 * \subsection outside COW
 *
 * When a COW transaction is not in progress, there are no marked
 * branch objects, so everything is exclusively owned. When a COW
 * transaction is finished (committed or rolled back), the branch
 * marks are removed. Since they are in the shared region, this branch
 * cleanup is visible to both old and new tries.
 *
 * However the state of app objects is not clean between COW
 * transactions. When a COW transaction is committed, we traverse the
 * old-only region to find old-only app objects that should be freed
 * (and vice versa for rollback). In general, there will be app
 * objects that are only reachable from the new-only region, and that
 * have a mixture of shared and new states.
 */

/*! \brief Trie copy-on-write state */
struct trie_cow {
	trie_t *old;
	trie_t *new;
	trie_cb *mark_shared;
	void *d;
};

/*! \brief is this a marked branch object */
static bool cow_marked(node_t *t)
{
	return isbranch(t) && (twigs(t)->i & TFLAG_COW);
}

/*! \brief is this a leaf with a marked key */
static bool cow_key(node_t *t)
{
	return !isbranch(t) && tkey(t)->cow;
}

/*! \brief remove mark from a branch object */
static void clear_cow(node_t *t)
{
	assert(isbranch(t));
	twigs(t)->i &= ~TFLAG_COW;
}

/*! \brief mark a node as shared
 *
 * For branches this marks the twig array (in COW terminology, the
 * branch object); for leaves it uses the callback to mark the app
 * object.
 */
static void mark_cow(trie_cow_t *cow, node_t *t)
{
	if (isbranch(t)) {
		node_t *object = twigs(t);
		object->i |= TFLAG_COW;
	} else {
		tkey_t *lkey = tkey(t);
		trie_val_t *valp = tvalp(t);
		lkey->cow = 1;
		cow->mark_shared(*valp, lkey->chars, lkey->len, cow->d);
	}
}

/*! \brief push exclusive COW region down one node */
static int cow_pushdown_one(trie_cow_t *cow, node_t *t)
{
	uint cc = branch_weight(t);
	node_t *nt = mm_alloc(&cow->new->mm, sizeof(node_t) * cc);
	if (nt == NULL)
		return KNOT_ENOMEM;
	/* mark all the children */
	for (uint ci = 0; ci < cc; ++ci)
		mark_cow(cow, twig(t, ci));
	/* this node must be unmarked in both old and new versions */
	clear_cow(t);
	t->p = memcpy(nt, twigs(t), sizeof(node_t) * cc);
	return KNOT_EOK;
}

/*! \brief push exclusive COW region to cover a whole node stack */
static int cow_pushdown(trie_cow_t *cow, nstack_t *ns)
{
	node_t *new_twigs = NULL;
	node_t *old_twigs = NULL;
	for (uint i = 0; i < ns->len; i++) {
		/* if we did a pushdown on the previous iteration, we
		   need to update this stack entry so it points into
		   the parent's new twigs instead of the old ones */
		if (new_twigs != old_twigs)
			ns->stack[i] = new_twigs + (ns->stack[i] - old_twigs);
		if (cow_marked(ns->stack[i])) {
			old_twigs = twigs(ns->stack[i]);
			if (cow_pushdown_one(cow, ns->stack[i]))
				return KNOT_ENOMEM;
			new_twigs = twigs(ns->stack[i]);
		} else {
			new_twigs = NULL;
			old_twigs = NULL;
			/* ensure key is exclusively owned */
			if (cow_key(ns->stack[i])) {
				node_t oleaf = *ns->stack[i];
				tkey_t *okey = tkey(&oleaf);
				if(mkleaf(ns->stack[i], okey->chars, okey->len,
					  &cow->new->mm))
					return KNOT_ENOMEM;
				ns->stack[i]->p = oleaf.p;
				okey->cow = 0;
			}
		}
	}
	return KNOT_EOK;
}

trie_cow_t* trie_cow(trie_t *old, trie_cb *mark_shared, void *d)
{
	knot_mm_t *mm = &old->mm;
	trie_t *new = mm_alloc(mm, sizeof(trie_t));
	trie_cow_t *cow = mm_alloc(mm, sizeof(trie_cow_t));
	if (new == NULL || cow == NULL) {
		mm_free(mm, new);
		mm_free(mm, cow);
		return NULL;
	}
	new->mm = old->mm;
	new->root = old->root;
	new->weight = old->weight;
	cow->old = old;
	cow->new = new;
	cow->mark_shared = mark_shared;
	cow->d = d;
	if (old->weight)
		mark_cow(cow, &old->root);
	return cow;
}

trie_t* trie_cow_new(trie_cow_t *cow)
{
	assert(cow != NULL);
	return cow->new;
}

trie_val_t* trie_get_cow(trie_cow_t *cow, const char *key, uint32_t len)
{
	return cow_get_ins(cow, cow->new, key, len);
}

int trie_del_cow(trie_cow_t *cow, const char *key, uint32_t len, trie_val_t *val)
{
	trie_t *tbl = cow->new;
	if (unlikely(!tbl->weight))
		return KNOT_ENOENT;
	{ // Intentionally un-indented; until end of function, to bound cleanup attr.
	// Find the branching-point
	__attribute__((cleanup(ns_cleanup)))
		nstack_t ns_local;
	ns_init(&ns_local, tbl);
	nstack_t *ns = &ns_local;
	index_t idiff;
	bitmap_t tbit, kbit;
	ERR_RETURN(ns_find_branch(ns, key, len, &idiff, &tbit, &kbit));
	if (idiff != TMAX_INDEX)
		return KNOT_ENOENT;
	ERR_RETURN(cow_pushdown(cow, ns));
	node_t *t = ns->stack[ns->len - 1];
	node_t *p = ns->len >= 2 ? ns->stack[ns->len - 2] : NULL;
	del_found(tbl, t, p, p ? twigbit(p, key, len) : 0, val);
	}
	return KNOT_EOK;
}

/*! \brief clean up after a COW transaction, recursively */
static void cow_cleanup(trie_cow_t *cow, node_t *t, trie_cb *cb, void *d)
{
	if (cow_marked(t)) {
		// we have hit the shared region, so just reset the mark
		clear_cow(t);
		return;
	} else if (isbranch(t)) {
		// traverse and free the exclusive region
		uint cc = branch_weight(t);
		for (uint ci = 0; ci < cc; ++ci)
			cow_cleanup(cow, twig(t, ci), cb, d);
		mm_free(&cow->new->mm, twigs(t));
		return;
	} else {
		// application must decide how to clean up its values
		tkey_t *lkey = tkey(t);
		trie_val_t *valp = tvalp(t);
		cb(*valp, lkey->chars, lkey->len, d);
		// clean up exclusively-owned keys
		if (lkey->cow)
			lkey->cow = 0;
		else
			mm_free(&cow->new->mm, lkey);
		return;
	}
}

trie_t* trie_cow_commit(trie_cow_t *cow, trie_cb *cb, void *d)
{
	trie_t *ret = cow->new;
	if (cow->old->weight)
		cow_cleanup(cow, &cow->old->root, cb, d);
	mm_free(&ret->mm, cow->old);
	mm_free(&ret->mm, cow);
	return ret;
}

trie_t* trie_cow_rollback(trie_cow_t *cow, trie_cb *cb, void *d)
{
	trie_t *ret = cow->old;
	if (cow->new->weight)
		cow_cleanup(cow, &cow->new->root, cb, d);
	mm_free(&ret->mm, cow->new);
	mm_free(&ret->mm, cow);
	return ret;
}
