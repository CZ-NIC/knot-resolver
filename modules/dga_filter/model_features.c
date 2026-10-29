/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file dga_features.c
 * @brief Maps the private DGA model container, computes the
 *        (n-gram + lexical + bigram) feature vector and evaluates the
 *        RandomForest directly from the mapped file.
 *
 * Container format version 3:
 *
 *   header (20 bytes)
 *     0   char[4]   magic "DGA1"
 *     4   u32       format version (3)
 *     8   u32       n_cv (number of CountVectorizer columns)
 *     12  u64       forest_len
 *   payload
 *     forest                                      forest_len
 *       u32 n_trees, u32 n_nodes
 *       u32 roots[n_trees]
 *       node[n_nodes], 16 bytes each:
 *         i32 feature  (-1 = leaf)
 *         f32 value    (split threshold, or P(dga) for a leaf)
 *         i32 left, i32 right  (absolute node indices)
 *     vocab: n_cv grams in column order, each     3 * n_cv
 *            3 ASCII bytes, NUL-padded
 *     bigram: f64[2] defaults, f64[2][128][128]   262160
 *
 * Alert class "dga" = class index 0, column order
 * CountVectorizer | 5 lexical | 2 bigram scores. The alert threshold is NOT
 * in the container.
 *
 * The forest is read straight from the file mapping, so it is shared page
 * cache between all processes that map the same file.
 */

#include "model_features.h"

#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the forest is used directly from the mapping, little-endian host required"
#endif

// Hardcoded model parameters
#define MAGIC "DGA1"
#define FORMAT_VERSION 3u
#define HEADER_SIZE 20u
#define FOREST_HEAD_SIZE 8u
#define GRAM_BYTES 3u
#define N_LEXICAL 5u
#define N_CLASSES 2u
#define ALPHABET 128u
#define BIGRAM_BYTES ((uint64_t)(N_CLASSES + N_CLASSES * ALPHABET * ALPHABET) * 8u)

#define MAX_CONTAINER_BYTES ((size_t)1 << 27) // 128 MiB sanity cap

struct forest_node {
	int32_t feature;
	float value;
	int32_t left;
	int32_t right;
};
_Static_assert(sizeof(struct forest_node) == 16, "unexpected node padding");

struct vocab_entry {
	uint32_t key; // b0 << 16 | b1 << 8 | b2, b2 == 0 for 2-grams
	uint32_t idx;
};

static struct {
	void *map;                       // whole container, read-only mapped file
	size_t map_len;
	const struct forest_node *nodes; // points into mapped file
	const uint32_t *roots;           // points into mapped file
	uint32_t n_trees;
	uint32_t n_nodes;
	struct vocab_entry *vocab;       // allocated
	uint32_t num_cv_columns;
	double bigram_default[N_CLASSES];
	double *bigram_log_probs;        // [N_CLASSES][ALPHABET][ALPHABET], allocated
	int is_loaded;
} model_state;

struct input_context {
	const char *domain_name;
	size_t domain_len;
	float *features;
};

// custom little-endian 4-byte reader
static uint32_t read_u32_le(const unsigned char *ptr)
{
	return (uint32_t)ptr[0] | (uint32_t)ptr[1] << 8 | (uint32_t)ptr[2] << 16 | (uint32_t)ptr[3] << 24;
}

// custom little-endian 8-byte reader
static uint64_t read_u64_le(const unsigned char *ptr)
{
	return (uint64_t)read_u32_le(ptr) | (uint64_t)read_u32_le(ptr + 4) << 32;
}

// custom little-endian 8-byte double reader
static double read_f64_le(const unsigned char *ptr)
{
	uint64_t raw_bits = read_u64_le(ptr);
	double value;
	memcpy(&value, &raw_bits, sizeof(value));
	return value;
}

static int vocab_compare(const void *a, const void *b)
{
	uint32_t key_a = ((const struct vocab_entry *)a)->key;
	uint32_t key_b = ((const struct vocab_entry *)b)->key;
	return (key_a > key_b) - (key_a < key_b);
}

static int vocab_lookup(uint32_t key)
{
	const struct vocab_entry *result = bsearch(&(struct vocab_entry){ .key = key },
			model_state.vocab, model_state.num_cv_columns, sizeof(*model_state.vocab), vocab_compare);
	return result ? (int)result->idx : -1;
}

static int is_vowel(char c)
{
	return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y';
}

static void construct_ngram_features(const struct input_context *ctx)
{
	for (size_t i = 0; i + 2 <= ctx->domain_len; i++) {
		uint32_t bigram_key = (uint32_t)(unsigned char)ctx->domain_name[i] << 16
			| (uint32_t)(unsigned char)ctx->domain_name[i + 1] << 8;
		int idx2 = vocab_lookup(bigram_key);
		if (idx2 >= 0)
			ctx->features[idx2] += 1.0f;
		if (i + 3 <= ctx->domain_len) {
			int idx3 = vocab_lookup(bigram_key | (unsigned char)ctx->domain_name[i + 2]);
			if (idx3 >= 0)
				ctx->features[idx3] += 1.0f;
		}
	}
}

static void construct_lexical_features(const struct input_context *ctx)
{
	if (ctx->domain_len == 0)
		return;

	int char_counts[128] = {0};
	int digits = 0, vowels = 0, current_consonant_run = 0, max_consonant_run = 0;
	for (size_t i = 0; i < ctx->domain_len; i++) {
		unsigned char ch = (unsigned char)ctx->domain_name[i];
		char_counts[ch]++;
		if (ch >= '0' && ch <= '9')
			digits++;
		if (is_vowel(ctx->domain_name[i]))
			vowels++;
		if (isalpha(ch) && !is_vowel(ctx->domain_name[i])) {
			if (++current_consonant_run > max_consonant_run)
				max_consonant_run = current_consonant_run;
		} else {
			current_consonant_run = 0;
		}
	}
	double entropy = 0.0;
	for (int ch = 0; ch < 128; ch++) {
		if (char_counts[ch]) {
			double prob = (double)char_counts[ch] / (double)ctx->domain_len;
			entropy -= prob * log2(prob);
		}
	}
	float *lexical_out = ctx->features + model_state.num_cv_columns;
	lexical_out[0] = (float)ctx->domain_len;
	lexical_out[1] = (float)((double)digits / (double)ctx->domain_len);
	lexical_out[2] = (float)((double)vowels / (double)ctx->domain_len);
	lexical_out[3] = (float)entropy;
	lexical_out[4] = (float)max_consonant_run;
}

static void construct_bigram_features(const struct input_context *ctx)
{
	for (unsigned class_idx = 0; class_idx < N_CLASSES; class_idx++) {
		double avg_log_prob = model_state.bigram_default[class_idx];
		if (ctx->domain_len >= 2) {
			double log_prob_sum = 0.0;
			const double (*table)[ALPHABET] =
				(const double (*)[ALPHABET])(model_state.bigram_log_probs + (size_t)class_idx * ALPHABET * ALPHABET);
			for (size_t i = 0; i + 1 < ctx->domain_len; i++)
				log_prob_sum += table[(unsigned char)ctx->domain_name[i]][(unsigned char)ctx->domain_name[i + 1]];
			avg_log_prob = log_prob_sum / (double)(ctx->domain_len - 1);
		}
		ctx->features[model_state.num_cv_columns + N_LEXICAL + class_idx] = (float)avg_log_prob;
	}
}

int build_features(const char *domain_name, float *out_features)
{
	if (!model_state.is_loaded)
		return -1;

	size_t domain_len = strlen(domain_name);
	for (size_t i = 0; i < domain_len; i++) {
		if ((unsigned char)domain_name[i] >= 128)
			return -1;
	}
	memset(out_features, 0, DGA_N_FEATURES * sizeof(float));

	struct input_context in_ctx = {
		.domain_name = domain_name,
		.domain_len = domain_len,
		.features = out_features,
	};

	construct_ngram_features(&in_ctx);
	construct_lexical_features(&in_ctx);
	construct_bigram_features(&in_ctx);

	return 0;
}

static float forest_predict_dga(const float *x)
{
	const struct forest_node *nodes = model_state.nodes;
	double sum = 0.0;

	for (uint32_t t = 0; t < model_state.n_trees; t++) {
		const struct forest_node *n = &nodes[model_state.roots[t]];
		// terminates: validate_forest() guarantees children have a greater index than their parent
		while (n->feature >= 0)
			n = &nodes[x[n->feature] <= n->value ? n->left : n->right];
		sum += n->value;
	}
	return (float)(sum / (double)model_state.n_trees);
}

float dga_predict(const char *domain_name)
{
	static float features[DGA_N_FEATURES];

	if (!model_state.is_loaded)
		return -1.0f;
	if (build_features(domain_name, features) != 0)
		return -1.0f;
	return forest_predict_dga(features);
}

static int validate_forest(const struct forest_node *nodes, uint32_t n_nodes,
		const uint32_t *roots, uint32_t n_trees)
{
	for (uint32_t t = 0; t < n_trees; t++) {
		if (roots[t] >= n_nodes)
			return -1;
		if (t > 0 && roots[t] <= roots[t - 1])
			return -1;
	}

	for (uint32_t i = 0; i < n_nodes; i++) {
		const struct forest_node *n = &nodes[i];
		if (n->feature == -1) {
			// leaf: probability (also rejects NaN)
			if (!(n->value >= 0.0f && n->value <= 1.0f))
				return -1;
			continue;
		}
		if (n->feature < 0 || (uint32_t)n->feature >= DGA_N_FEATURES)
			return -1;
		if (isnan(n->value))
			return -1;
		if ((int64_t)n->left <= (int64_t)i || (int64_t)n->right <= (int64_t)i
		    || (int64_t)n->left >= (int64_t)n_nodes || (int64_t)n->right >= (int64_t)n_nodes)
			return -1;
	}
	return 0;
}

void dga_model_unload(void)
{
	free(model_state.vocab);
	free(model_state.bigram_log_probs);
	if (model_state.map)
		munmap(model_state.map, model_state.map_len);
	memset(&model_state, 0, sizeof(model_state));
}

static int map_model_file(const char *path, void **out_map, size_t *out_size)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	struct stat st;
	if (fstat(fd, &st) != 0 || st.st_size < (off_t)HEADER_SIZE
	    || (unsigned long long)st.st_size > MAX_CONTAINER_BYTES) {
		close(fd);
		return -1;
	}
	size_t size = (size_t)st.st_size;

	void *map = mmap(NULL, size, PROT_READ, (MAP_PRIVATE | MAP_POPULATE), fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return -1;

	(void)madvise(map, size, MADV_RANDOM);  // should help with performance: tree walks are random access

	*out_map = map;
	*out_size = size;
	return 0;
}

static int load_random_forest(const unsigned char *forest_ptr, uint64_t forest_len)
{
	uint32_t n_trees = read_u32_le(forest_ptr);
	uint32_t n_nodes = read_u32_le(forest_ptr + 4);
	if (n_trees == 0 || n_nodes < n_trees)
		return -1;
	if ((uint64_t)FOREST_HEAD_SIZE + 4ull * n_trees + 16ull * n_nodes != forest_len)
		return -1;

	const uint32_t *roots = (const uint32_t *)(forest_ptr + FOREST_HEAD_SIZE);
	const struct forest_node *nodes =
		(const struct forest_node *)(forest_ptr + FOREST_HEAD_SIZE + 4ull * n_trees);
	if (validate_forest(nodes, n_nodes, roots, n_trees) != 0)
		return -1;

	model_state.roots = roots;
	model_state.nodes = nodes;
	model_state.n_trees = n_trees;
	model_state.n_nodes = n_nodes;
	return 0;
}

static int load_vocab(const unsigned char *vocab_ptr, uint32_t num_cv)
{
	model_state.vocab = calloc(num_cv, sizeof(*model_state.vocab));
	if (!model_state.vocab)
		return -1;
	for (uint32_t i = 0; i < num_cv; i++) {
		const unsigned char *row_ptr = vocab_ptr + (size_t)GRAM_BYTES * i;
		if (row_ptr[0] == 0 || row_ptr[0] >= 128 || row_ptr[1] == 0 || row_ptr[1] >= 128 || row_ptr[2] >= 128)
			return -1;
		model_state.vocab[i].key = (uint32_t)row_ptr[0] << 16 | (uint32_t)row_ptr[1] << 8 | row_ptr[2];
		model_state.vocab[i].idx = i;
	}
	qsort(model_state.vocab, num_cv, sizeof(*model_state.vocab), vocab_compare);
	for (uint32_t i = 1; i < num_cv; i++) {
		if (model_state.vocab[i - 1].key == model_state.vocab[i].key)
			return -1;
	}
	model_state.num_cv_columns = num_cv;
	return 0;
}

static int load_bigram_lang_score(const unsigned char *bigram_ptr)
{
	for (unsigned class_idx = 0; class_idx < N_CLASSES; class_idx++)
		model_state.bigram_default[class_idx] = read_f64_le(bigram_ptr + 8 * class_idx);
	bigram_ptr += 8 * N_CLASSES;

	model_state.bigram_log_probs = malloc((size_t)N_CLASSES * ALPHABET * ALPHABET * sizeof(double));
	if (!model_state.bigram_log_probs)
		return -1;
	for (size_t i = 0; i < (size_t)N_CLASSES * ALPHABET * ALPHABET; i++)
		model_state.bigram_log_probs[i] = read_f64_le(bigram_ptr + 8 * i);
	return 0;
}

int dga_model_load(const char *path)
{
	dga_model_unload();

	void *map = NULL;
	size_t size = 0;
	if (map_model_file(path, &map, &size) != 0)
		return -1;

	model_state.map = map;
	model_state.map_len = size;

	const unsigned char *buffer = map;

	if (memcmp(buffer, MAGIC, 4) != 0 || read_u32_le(buffer + 4) != FORMAT_VERSION)
		goto fail;
	uint32_t num_cv = read_u32_le(buffer + 8);
	uint64_t forest_len = read_u64_le(buffer + 12);

	if (num_cv == 0 || (uint64_t)num_cv + N_LEXICAL + N_CLASSES != (uint64_t)DGA_N_FEATURES)
		goto fail;
	if (forest_len < FOREST_HEAD_SIZE || forest_len > size)
		goto fail;
	uint64_t expected_size = HEADER_SIZE + forest_len + (uint64_t)GRAM_BYTES * num_cv + BIGRAM_BYTES;
	if (expected_size != (uint64_t)size)
		goto fail;

	const unsigned char *forest_ptr = buffer + HEADER_SIZE;
	const unsigned char *vocab_ptr = forest_ptr + forest_len;
	const unsigned char *bigram_ptr = vocab_ptr + (size_t)GRAM_BYTES * num_cv;

	if (load_random_forest(forest_ptr, forest_len) != 0)
		goto fail;

	if (load_vocab(vocab_ptr, num_cv) != 0)
		goto fail;

	if (load_bigram_lang_score(bigram_ptr) != 0)
		goto fail;

	model_state.is_loaded = 1;
	return 0;

fail:
	dga_model_unload();
	return -1;
}
