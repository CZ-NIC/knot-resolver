/*  Copyright (C) 2016-2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later

    The code originated from https://github.com/fanf2/qp/blob/master/qp.c
    at revision 5f6d93753.
 */

#include <stdlib.h>
#include <string.h>

#include "lib/generic/trie.h"
#include "lib/utils.h"
#include "contrib/ucw/lib.h"

#if defined(__i386) || defined(__x86_64) || defined(_M_IX86) \
	|| (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN) \
		&& __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

	/*!
	 * \brief Use a pointer alignment hack to save memory.
	 *
	 * When on, isbranch() relies on the fact that in leaf_t the first pointer
	 * is aligned on multiple of 4 bytes and that the flags bitfield is
	 * overlaid over the lowest two bits of that pointer.
	 * Neither is really guaranteed by the C standards; the second part should
	 * be OK with x86_64 ABI and most likely any other little-endian platform.
	 * It would be possible to manipulate the right bits portably, but it would
	 * complicate the code nontrivially. C++ doesn't even guarantee type-punning.
	 * In debug mode we check this works OK when creating a new trie instance.
	 */
	#define FLAGS_HACK 1
#else
	#define FLAGS_HACK 0
#endif

typedef unsigned char byte;
#ifndef uint
typedef unsigned int uint;
#define uint uint
#endif
typedef uint bitmap_t; /*! Bit-maps, using the range of 1<<0 to 1<<16 (inclusive). */

typedef struct {
	uint32_t len; // 32 bits are enough for key lengths; probably even 16 bits would be.
	char chars[];
} tkey_t;

/*! \brief Leaf of trie. */
typedef struct {
	#if !FLAGS_HACK
		byte flags;
	#endif
	tkey_t *key; /*!< The pointer must be aligned to 4-byte multiples! */
	trie_val_t val;
} leaf_t;

/*! \brief A trie node is either leaf_t or branch_t. */
typedef union node node_t;

/*!
 * \brief Branch node of trie.
 *
 * - The flags distinguish whether the node is a leaf_t (0), or a branch
 *   testing the more-important nibble (1) or the less-important one (2).
 * - It stores the index of the byte that the node tests.  The combined
 *   value (index*4 + flags) increases in branch nodes as you go deeper
 *   into the trie.  All the keys below a branch are identical up to the
 *   nibble identified by the branch.  Indices have to be stored because
 *   we skip any branch nodes that would have a single child.
 *   (Consequently, the skipped parts of key have to be validated in a leaf.)
 * - The bitmap indicates which subtries are present.  The present child nodes
 *   are stored in the twigs array (with no holes between them).
 * - To simplify storing keys that are prefixes of each other, the end-of-string
 *   position is treated as another nibble value, ordered before all others.
 *   That affects the bitmap and twigs fields.
 *
 * \note The branch nodes are never allocated individually, but they are
 *   always part of either the root node or the twigs array of the parent.
 */
typedef struct {
	#if FLAGS_HACK
		uint32_t flags  : 2,
		         bitmap : 17; /*!< The first bitmap bit is for end-of-string child. */
	#else
		byte flags;
		uint32_t bitmap;
	#endif
	uint32_t index;
	node_t *twigs;
} branch_t;

union node {
	leaf_t leaf;
	branch_t branch;
};

struct trie {
	node_t root; // undefined when weight == 0, see empty_root()
	size_t weight;
	knot_mm_t mm;
};

/*! \brief Make the root node empty (debug-only). */
static inline void empty_root(node_t *root) {
#ifndef NDEBUG
	*root = (node_t){ .branch = {
		.flags = 3, // invalid value that fits
		.bitmap = 0,
		.index = -1,
		.twigs = NULL
	} };
#endif
}

/*! \brief Check that unportable code works OK (debug-only). */
static void assert_portability(void) {
#if FLAGS_HACK
	kr_require(((union node){ .leaf = {
			.key = (tkey_t *)(((uint8_t *)NULL) + 1),
			.val = NULL
		} }).branch.flags == 1);
#endif
}

/*! \brief Propagate error codes. */
#define ERR_RETURN(x) \
	do { \
		int err_code_ = x; \
		if (unlikely(err_code_ != KNOT_EOK)) \
			return err_code_; \
	} while (false)

/*!
 * \brief Count the number of set bits.
 *
 * \TODO This implementation may be relatively slow on some HW.
 */
static uint bitmap_weight(bitmap_t w)
{
	kr_require((w & ~((1 << 17) - 1)) == 0); // using the least-important 17 bits
	return __builtin_popcount(w);
}

/*! \brief Only keep the lowest bit in the bitmap (least significant -> twigs[0]). */
static bitmap_t bitmap_lowest_bit(bitmap_t w)
{
	kr_require((w & ~((1 << 17) - 1)) == 0); // using the least-important 17 bits
	return 1 << __builtin_ctz(w);
}

/*! \brief Test flags to determine type of this node. */
static bool isbranch(const node_t *t)
{
	uint f = t->branch.flags;
	kr_require(f <= 2);
	return f != 0;
}

/*! \brief Make a bitmask for testing a branch bitmap. */
static bitmap_t nibbit(byte k, uint flags)
{
	uint shift = (2 - flags) << 2;
	uint nibble = (k >> shift) & 0xf;
	return 1 << (nibble + 1/*because of prefix keys*/);
}

/*! \brief Extract a nibble from a key and turn it into a bitmask. */
static bitmap_t twigbit(const node_t *t, const char *key, uint32_t len)
{
	kr_require(isbranch(t));
	uint i = t->branch.index;

	if (i >= len)
		return 1 << 0; // leaf position

	return nibbit((byte)key[i], t->branch.flags);
}

/*! \brief Test if a branch node has a child indicated by a bitmask. */
static bool hastwig(const node_t *t, bitmap_t bit)
{
	kr_require(isbranch(t));
	return t->branch.bitmap & bit;
}

/*! \brief Compute offset of an existing child in a branch node. */
static uint twigoff(const node_t *t, bitmap_t b)
{
	kr_require(isbranch(t));
	return bitmap_weight(t->branch.bitmap & (b - 1));
}

/*! \brief Get pointer to a particular child of a branch node. */
static node_t* twig(node_t *t, uint i)
{
	kr_require(isbranch(t));
	return &t->branch.twigs[i];
}

/*!
 * \brief For a branch nod, compute offset of a child and child count.
 *
 * Having this separate might be meaningful for performance optimization.
 */
#define TWIGOFFMAX(off, max, t, b) do {			\
		(off) = twigoff((t), (b));		\
		(max) = bitmap_weight((t)->branch.bitmap);\
	} while(0)

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
	assert_portability();
	trie_t *trie = mm_alloc(mm, sizeof(trie_t));
	if (trie != NULL) {
		empty_root(&trie->root);
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
		mm_free(mm, trie->leaf.key);
	} else {
		branch_t *b = &trie->branch;
		int len = bitmap_weight(b->bitmap);
		for (int i = 0; i < len; ++i)
			clear_trie(b->twigs + i, mm);
		mm_free(mm, b->twigs);
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
	if (!kr_assume(tbl))
		return;
	if (!tbl->weight)
		return;
	clear_trie(&tbl->root, &tbl->mm);
	empty_root(&tbl->root);
	tbl->weight = 0;
}

size_t trie_weight(const trie_t *tbl)
{
	kr_require(tbl);
	return tbl->weight;
}

struct found {
	leaf_t *l;	/**< the found leaf (NULL if not found) */
	branch_t *p;	/**< the leaf's parent (if exists) */
	bitmap_t b;	/**< bit-mask with a single bit marking l under p */
};
/** Search trie for an item with the given key (equality only). */
static struct found find_equal(trie_t *tbl, const char *key, uint32_t len)
{
	kr_require(tbl);
	struct found ret0;
	memset(&ret0, 0, sizeof(ret0));
	if (!tbl->weight)
		return ret0;
	/* Current node and parent while descending (returned values basically). */
	node_t *t = &tbl->root;
	branch_t *p = NULL;
	bitmap_t b = 0;
	while (isbranch(t)) {
		__builtin_prefetch(t->branch.twigs);
		b = twigbit(t, key, len);
		if (!hastwig(t, b))
			return ret0;
		p = &t->branch;
		t = twig(t, twigoff(t, b));
	}
	if (key_cmp(key, len, t->leaf.key->chars, t->leaf.key->len) != 0)
		return ret0;
	return (struct found) {
		.l = &t->leaf,
		.p = p,
		.b = b,
	};
}
/** Find item with the first key (lexicographical order). */
static struct found find_first(trie_t *tbl)
{
	kr_require(tbl);
	if (!tbl->weight) {
		struct found ret0;
		memset(&ret0, 0, sizeof(ret0));
		return ret0;
	}
	/* Current node and parent while descending (returned values basically). */
	node_t *t = &tbl->root;
	branch_t *p = NULL;
	while (isbranch(t)) {
		p = &t->branch;
		t = &p->twigs[0];
	}
	return (struct found) {
		.l = &t->leaf,
		.p = p,
		.b = p ? bitmap_lowest_bit(p->bitmap) : 0,
	};
}

trie_val_t* trie_get_try(trie_t *tbl, const char *key, uint32_t len)
{
	struct found found = find_equal(tbl, key, len);
	return found.l ? &found.l->val : NULL;
}

trie_val_t* trie_get_first(trie_t *tbl, char **key, uint32_t *len)
{
	struct found found = find_first(tbl);
	if (!found.l)
		return NULL;
	if (key)
		*key = found.l->key->chars;
	if (len)
		*len = found.l->key->len;
	return &found.l->val;
}

/** Delete the found element (if any) and return value (unless NULL is passed) */
static int del_found(trie_t *tbl, struct found found, trie_val_t *val)
{
	if (!found.l)
		return KNOT_ENOENT;
	mm_free(&tbl->mm, found.l->key);
	if (val != NULL)
		*val = found.l->val; // we return trie_val_t directly when deleting
	--tbl->weight;
	branch_t * const p = found.p; // short-hand
	if (unlikely(!p)) { // whole trie was a single leaf
		kr_require(tbl->weight == 0);
		empty_root(&tbl->root);
		return KNOT_EOK;
	}
	// remove leaf t as child of p; get child index via pointer arithmetic
	int ci = ((union node *)found.l) - p->twigs,
	    cc = bitmap_weight(p->bitmap); // child count
	kr_require(ci >= 0 && ci < cc);

	if (cc == 2) { // collapse binary node p: move the other child to this node
		node_t *twigs = p->twigs;
		(*(union node *)p) = twigs[1 - ci]; // it might be a leaf or branch
		mm_free(&tbl->mm, twigs);
		return KNOT_EOK;
	}
	memmove(p->twigs + ci, p->twigs + ci + 1, sizeof(node_t) * (cc - ci - 1));
	p->bitmap &= ~found.b;
	node_t *twigs = mm_realloc(&tbl->mm, p->twigs, sizeof(node_t) * (cc - 1),
	                           sizeof(node_t) * cc);
	if (likely(twigs != NULL))
		p->twigs = twigs;
		/* We can ignore mm_realloc failure, only beware that next time
		 * the prev_size passed to it wouldn't be correct; TODO? */
	return KNOT_EOK;
}

int trie_del(trie_t *tbl, const char *key, uint32_t len, trie_val_t *val)
{
	struct found found = find_equal(tbl, key, len);
	return del_found(tbl, found, val);
}

int trie_del_first(trie_t *tbl, char *key, uint32_t *len, trie_val_t *val)
{
	struct found found = find_first(tbl);
	if (!found.l)
		return KNOT_ENOENT;
	if (key) {
		if (!len)
			return KNOT_EINVAL;
		if (*len < found.l->key->len)
			return kr_error(ENOSPC);
		memcpy(key, found.l->key->chars, found.l->key->len);
	}
	if (len) { // makes sense even with key == NULL
		*len = found.l->key->len;
	}
	return del_found(tbl, found, val);
}

/*!
 * \brief Stack of nodes, storing a path down a trie.
 *
 * The structure also serves directly as the public trie_it_t type,
 * in which case it always points to the current leaf, unless we've finished
 * (i.e. it->len == 0).
 */
typedef struct trie_it {
	node_t* *stack; /*!< The stack; malloc is used directly instead of mm. */
	uint32_t len;   /*!< Current length of the stack. */
	uint32_t alen;  /*!< Allocated/available length of the stack. */
	/*! \brief Initial storage for \a stack; it should fit in many use cases. */
	node_t* stack_init[60];
} nstack_t;

/*! \brief Create a node stack containing just the root (or empty). */
static void ns_init(nstack_t *ns, trie_t *tbl)
{
	if (!kr_assume(tbl))
		return;
	ns->stack = ns->stack_init;
	ns->alen = sizeof(ns->stack_init) / sizeof(ns->stack_init[0]);
	if (tbl->weight) {
		ns->len = 1;
		ns->stack[0] = &tbl->root;
	} else {
		ns->len = 0;
	}
}

/*! \brief Free inside of the stack, i.e. not the passed pointer itself. */
static void ns_cleanup(nstack_t *ns)
{
	if (!kr_assume(ns && ns->stack))
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
	size_t new_size = sizeof(nstack_t) + ns->alen * sizeof(node_t *);
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
 *  The top of the stack will contain: the corresponding leaf if exact match is found;
 *  or the immediate node below a branching-point-on-edge or the branching-point itself.
 *
 *  \param info   Set position of the point of first mismatch (in index and flags).
 *  \param first  Set the value of the first non-matching character (from trie),
 *                optionally; end-of-string character has value -256 (that's why it's int).
 *                Note: the character is converted to *unsigned* char (i.e. 0..255),
 *                as that's the ordering used in the trie.
 *
 *  \return KNOT_EOK or KNOT_ENOMEM.
 */
static int ns_find_branch(nstack_t *ns, const char *key, uint32_t len,
                          branch_t *info, int *first)
{
	kr_require(ns && ns->len && info);
	// First find some leaf with longest matching prefix.
	while (isbranch(ns->stack[ns->len - 1])) {
		ERR_RETURN(ns_longer(ns));
		node_t *t = ns->stack[ns->len - 1];
		__builtin_prefetch(t->branch.twigs);
		bitmap_t b = twigbit(t, key, len);
		// Even if our key is missing from this branch we need to
		// keep iterating down to a leaf. It doesn't matter which
		// twig we choose since the keys are all the same up to this
		// index. Note that blindly using twigoff(t, b) can cause
		// an out-of-bounds index if it equals twigmax(t).
		uint i = hastwig(t, b) ? twigoff(t, b) : 0;
		ns->stack[ns->len++] = twig(t, i);
	}
	tkey_t *lkey = ns->stack[ns->len-1]->leaf.key;
	// Find index of the first char that differs.
	uint32_t index = 0;
	while (index < MIN(len,lkey->len)) {
		if (key[index] != lkey->chars[index])
			break;
		else
			++index;
	}
	info->index = index;
	if (first)
		*first = lkey->len > index ? (unsigned char)lkey->chars[index] : -256;
	// Find flags: which half-byte has matched.
	uint flags;
	if (index == len && len == lkey->len) { // found equivalent key
		info->flags = flags = 0;
		goto success;
	}
	if (likely(index < MIN(len,lkey->len))) {
		byte k2 = (byte)lkey->chars[index];
		byte k1 = (byte)key[index];
		flags = ((k1 ^ k2) & 0xf0) ? 1 : 2;
	} else { // one is prefix of another
		flags = 1;
	}
	info->flags = flags;
	// now go up the trie from the current leaf
	branch_t *t;
	do {
		if (unlikely(ns->len == 1))
			goto success; // only the root stays on the stack
		t = (branch_t*)ns->stack[ns->len - 2];
		if (t->index < index || (t->index == index && t->flags < flags))
			goto success;
		--ns->len;
	} while (true);
success:
	#ifndef NDEBUG // invariants on successful return
		kr_require(ns->len);
		if (isbranch(ns->stack[ns->len - 1])) {
			t = &ns->stack[ns->len - 1]->branch;
			kr_require(t->index > index || (t->index == index && t->flags >= flags));
		}
		if (ns->len > 1) {
			t = &ns->stack[ns->len - 2]->branch;
			kr_require(t->index < index || (t->index == index
			       && (t->flags < flags || (t->flags == 1 && flags == 0))));
		}
	#endif
	return KNOT_EOK;
}

/*!
 * \brief Advance the node stack to the last leaf in the subtree.
 *
 * \return KNOT_EOK or KNOT_ENOMEM.
 */
static int ns_last_leaf(nstack_t *ns)
{
	kr_require(ns);
	do {
		ERR_RETURN(ns_longer(ns));
		node_t *t = ns->stack[ns->len - 1];
		if (!isbranch(t))
			return KNOT_EOK;
		int lasti = bitmap_weight(t->branch.bitmap) - 1;
		kr_require(lasti >= 0);
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
	kr_require(ns && ns->len);
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
	kr_require(ns && ns->len > 0);

	node_t *t = ns->stack[ns->len - 1];
	if (hastwig(t, 1 << 0)) { // the prefix leaf
		t = twig(t, 0);
		ERR_RETURN(ns_longer(ns));
		ns->stack[ns->len++] = t;
		return KNOT_EOK;
	}

	do {
		if (ns->len < 2)
			return KNOT_ENOENT; // root without empty key has no previous leaf
		t = ns->stack[ns->len - 1];
		node_t *p = ns->stack[ns->len - 2];
		int pindex = t - p->branch.twigs; // index in parent via pointer arithmetic
		kr_require(pindex >= 0 && pindex <= 16);
		if (pindex > 0) { // t isn't the first child -> go down the previous one
			ns->stack[ns->len - 1] = twig(p, pindex - 1);
			return ns_last_leaf(ns);
		}
		// we've got to go up again
		--ns->len;
	} while (true);
}

/*!
 * \brief Advance the node stack to the leaf that is successor to the current node.
 *
 * \note Prefix leaf or anything else under the current node DOES count.
 * \return KNOT_EOK on success, KNOT_ENOENT on not-found, or possibly KNOT_ENOMEM.
 */
static int ns_next_leaf(nstack_t *ns)
{
	kr_require(ns && ns->len > 0);

	node_t *t = ns->stack[ns->len - 1];
	if (isbranch(t))
		return ns_first_leaf(ns);
	do {
		if (ns->len < 2)
			return KNOT_ENOENT; // not found, as no more parent is available
		t = ns->stack[ns->len - 1];
		node_t *p = ns->stack[ns->len - 2];
		int pindex = t - p->branch.twigs; // index in parent via pointer arithmetic
		kr_require(pindex >= 0 && pindex <= 16);
		int pcount = bitmap_weight(p->branch.bitmap);
		if (pindex + 1 < pcount) { // t isn't the last child -> go down the next one
			ns->stack[ns->len - 1] = twig(p, pindex + 1);
			return ns_first_leaf(ns);
		}
		// we've got to go up again
		--ns->len;
	} while (true);
}

int trie_get_leq(trie_t *tbl, const char *key, uint32_t len, trie_val_t **val)
{
	kr_require(tbl && val);
	*val = NULL; // so on failure we can just return;
	if (tbl->weight == 0)
		return KNOT_ENOENT;
	{ // Intentionally un-indented; until end of function, to bound cleanup attr.
	// First find a key with longest-matching prefix
	__attribute__((cleanup(ns_cleanup)))
		nstack_t ns_local;
	ns_init(&ns_local, tbl);
	nstack_t *ns = &ns_local;
	branch_t bp;
	int un_leaf; // first unmatched character in the leaf
	ERR_RETURN(ns_find_branch(ns, key, len, &bp, &un_leaf));
	int un_key = bp.index < len ? (unsigned char)key[bp.index] : -256;
	node_t *t = ns->stack[ns->len - 1];
	if (bp.flags == 0) { // found exact match
		*val = &t->leaf.val;
		return KNOT_EOK;
	}
	// Get t: the last node on matching path
	if (isbranch(t) && t->branch.index == bp.index && t->branch.flags == bp.flags) {
		// t is OK
	} else {
		// the top of the stack was the first unmatched node -> step up
		if (ns->len == 1) {
			// root was unmatched already
			if (un_key < un_leaf)
				return KNOT_ENOENT;
			ERR_RETURN(ns_last_leaf(ns));
			goto success;
		}
		--ns->len;
		t = ns->stack[ns->len - 1];
	}
	// Now we re-do the first "non-matching" step in the trie
	// but try the previous child if key was less (it may not exist)
	bitmap_t b = twigbit(t, key, len);
	int i = hastwig(t, b)
		? twigoff(t, b) - (un_key < un_leaf)
		: twigoff(t, b) - 1 /*twigoff returns successor when !hastwig*/;
	if (i >= 0) {
		ERR_RETURN(ns_longer(ns));
		ns->stack[ns->len++] = twig(t, i);
		ERR_RETURN(ns_last_leaf(ns));
	} else {
		ERR_RETURN(ns_prev_leaf(ns));
	}
success:
	kr_require(!isbranch(ns->stack[ns->len - 1]));
	*val = &ns->stack[ns->len - 1]->leaf.val;
	return 1;
	}
}

/*! \brief Initialize a new leaf, copying the key, and returning failure code. */
static int mk_leaf(node_t *leaf, const char *key, uint32_t len, knot_mm_t *mm)
{
	tkey_t *k = mm_alloc(mm, sizeof(tkey_t) + len);
	#if FLAGS_HACK
		kr_require(((uintptr_t)k) % 4 == 0); // we need an aligned pointer
	#endif
	if (unlikely(!k))
		return KNOT_ENOMEM;
	k->len = len;
	memcpy(k->chars, key, len);
	leaf->leaf = (leaf_t){
		#if !FLAGS_HACK
			.flags = 0,
		#endif
		.val = NULL,
		.key = k
	};
	return KNOT_EOK;
}

trie_val_t* trie_get_ins(trie_t *tbl, const char *key, uint32_t len)
{
	if (!kr_assume(tbl))
		return NULL;
	// First leaf in an empty tbl?
	if (unlikely(!tbl->weight)) {
		if (unlikely(mk_leaf(&tbl->root, key, len, &tbl->mm)))
			return NULL;
		++tbl->weight;
		return &tbl->root.leaf.val;
	}
	{ // Intentionally un-indented; until end of function, to bound cleanup attr.
	// Find the branching-point
	__attribute__((cleanup(ns_cleanup)))
		nstack_t ns_local;
	ns_init(&ns_local, tbl);
	nstack_t *ns = &ns_local;
	branch_t bp; // branch-point: index and flags signifying the longest common prefix
	int k2; // the first unmatched character in the leaf
	if (unlikely(ns_find_branch(ns, key, len, &bp, &k2)))
		return NULL;
	node_t *t = ns->stack[ns->len - 1];
	if (bp.flags == 0) // the same key was already present
		return &t->leaf.val;
	node_t leaf;
	if (unlikely(mk_leaf(&leaf, key, len, &tbl->mm)))
		return NULL;

	if (isbranch(t) && bp.index == t->branch.index && bp.flags == t->branch.flags) {
		// The node t needs a new leaf child.
		bitmap_t b1 = twigbit(t, key, len);
		kr_require(!hastwig(t, b1));
		uint s, m; TWIGOFFMAX(s, m, t, b1); // new child position and original child count
		node_t *twigs = mm_realloc(&tbl->mm, t->branch.twigs,
				sizeof(node_t) * (m + 1), sizeof(node_t) * m);
		if (unlikely(!twigs))
			goto err_leaf;
		memmove(twigs + s + 1, twigs + s, sizeof(node_t) * (m - s));
		twigs[s] = leaf;
		t->branch.twigs = twigs;
		t->branch.bitmap |= b1;
		++tbl->weight;
		return &twigs[s].leaf.val;
	} else {
		// We need to insert a new binary branch with leaf at *t.
		// Note: it works the same for the case where we insert above root t.
		#ifndef NDEBUG
			if (ns->len > 1) {
				node_t *pt = ns->stack[ns->len - 2];
				kr_require(hastwig(pt, twigbit(pt, key, len)));
			}
		#endif
		node_t *twigs = mm_alloc(&tbl->mm, sizeof(node_t) * 2);
		if (unlikely(!twigs))
			goto err_leaf;
		node_t t2 = *t; // Save before overwriting t.
		t->branch.flags = bp.flags;
		t->branch.index = bp.index;
		t->branch.twigs = twigs;
		bitmap_t b1 = twigbit(t, key, len);
		bitmap_t b2 = unlikely(k2 == -256) ? (1 << 0) : nibbit(k2, bp.flags);
		t->branch.bitmap = b1 | b2;
		*twig(t, twigoff(t, b1)) = leaf;
		*twig(t, twigoff(t, b2)) = t2;
		++tbl->weight;
		return &twig(t, twigoff(t, b1))->leaf.val;
	};
err_leaf:
	mm_free(&tbl->mm, leaf.leaf.key);
	return NULL;
	}
}

/*! \brief Apply a function to every trie_val_t*, in order; a recursive solution. */
static int apply_trie(node_t *t, int (*f)(trie_val_t *, void *), void *d)
{
	kr_require(t);
	if (!isbranch(t))
		return f(&t->leaf.val, d);
	int child_count = bitmap_weight(t->branch.bitmap);
	for (int i = 0; i < child_count; ++i)
		ERR_RETURN(apply_trie(twig(t, i), f, d));
	return KNOT_EOK;
}

int trie_apply(trie_t *tbl, int (*f)(trie_val_t *, void *), void *d)
{
	kr_require(tbl && f);
	if (!tbl->weight)
		return KNOT_EOK;
	return apply_trie(&tbl->root, f, d);
}

/* These are all thin wrappers around static Tns* functions. */
trie_it_t* trie_it_begin(trie_t *tbl)
{
	if (!kr_assume(tbl))
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

void trie_it_next(trie_it_t *it)
{
	kr_require(it && it->len);
	if (ns_next_leaf(it) != KNOT_EOK)
		it->len = 0;
}

bool trie_it_finished(trie_it_t *it)
{
	kr_require(it);
	return it->len == 0;
}

void trie_it_free(trie_it_t *it)
{
	if (!it)
		return;
	ns_cleanup(it);
	free(it);
}

const char* trie_it_key(trie_it_t *it, size_t *len)
{
	kr_require(it && it->len);
	node_t *t = it->stack[it->len - 1];
	kr_require(!isbranch(t));
	tkey_t *key = t->leaf.key;
	if (len)
		*len = key->len;
	return key->chars;
}

trie_val_t* trie_it_val(trie_it_t *it)
{
	kr_require(it && it->len);
	node_t *t = it->stack[it->len - 1];
	kr_require(!isbranch(t));
	return &t->leaf.val;
}
