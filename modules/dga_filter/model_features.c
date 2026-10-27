/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file dga_features.c
 * @brief Loads the private DGA model container and computes the
 *        (n-gram + lexical + bigram) feature vector fed to the RandomForest.
 *
 * Container format version 2:
 *
 *   header (20 bytes)
 *     0   char[4]   magic "DGA1"
 *     4   u32       format version (currently 2)
 *     8   u32       n_cv (number of CountVectorizer columns)
 *     12  u64       onnx_len
 *   payload
 *     onnx bytes                                  onnx_len
 *     vocab: n_cv grams in column order, each     3 * n_cv
 *            3 ASCII bytes, NUL-padded
 *     bigram: f64[2] defaults, f64[2][128][128]   262160
 *
 * Everything else is pinned by the format version and hardcoded here:
 * classes ["dga", "legit"] (alert class = index 0), column order
 * CountVectorizer | 5 lexical | 2 bigram scores, 2..3-gram char analyzer,
 * 7-bit (128 values) ASCII bigram alphabet, ONNX input "features" / output
 * "probabilities". The alert threshold is NOT in the container.
 */

#include "model_features.h"

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Hardcoded model parameters
#define MAGIC "DGA1"
#define FORMAT_VERSION 2u
#define HEADER_SIZE 20u
#define GRAM_BYTES 3u
#define N_LEXICAL 5u
#define N_CLASSES 2u
#define ALPHABET 128u
#define BIGRAM_BYTES ((uint64_t)(N_CLASSES + N_CLASSES * ALPHABET * ALPHABET) * 8u) // prepended by defaults (first N_CLASSES)

#define MAX_CONTAINER_BYTES ((size_t)1 << 29) /* 512 MiB sanity cap */

struct vocab_entry {
	uint32_t key; /* b0 << 16 | b1 << 8 | b2, b2 == 0 for 2-grams */
	uint32_t idx;
};

static struct {
	unsigned char *container_blob; /* whole container; ONNX bytes point into it */
	struct vocab_entry *vocab;
	uint32_t num_cv_columns;
	double bigram_default[N_CLASSES];
	double *bigram_log_probs; /* [N_CLASSES][ALPHABET][ALPHABET] */
	int is_loaded;
} model_state;

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

	/* 1) char 2..3-gram counts. */
	for (size_t i = 0; i + 2 <= domain_len; i++) {
		uint32_t bigram_key = (uint32_t)(unsigned char)domain_name[i] << 16
			| (uint32_t)(unsigned char)domain_name[i + 1] << 8;
		int idx2 = vocab_lookup(bigram_key);
		if (idx2 >= 0)
			out_features[idx2] += 1.0f;
		if (i + 3 <= domain_len) {
			int idx3 = vocab_lookup(bigram_key | (unsigned char)domain_name[i + 2]);
			if (idx3 >= 0)
				out_features[idx3] += 1.0f;
		}
	}

	/* 2) lexical: length, digit_ratio, vowel_ratio, entropy, longest_consonant_run */
	float *lexical_out = out_features + model_state.num_cv_columns;
	if (domain_len > 0) {
		int char_counts[128] = {0};
		int digits = 0, vowels = 0, current_consonant_run = 0, max_consonant_run = 0;
		for (size_t i = 0; i < domain_len; i++) {
			unsigned char ch = (unsigned char)domain_name[i];
			char_counts[ch]++;
			if (ch >= '0' && ch <= '9')
				digits++;
			if (is_vowel(domain_name[i]))
				vowels++;
			if (isalpha(ch) && !is_vowel(domain_name[i])) {
				if (++current_consonant_run > max_consonant_run)
					max_consonant_run = current_consonant_run;
			} else {
				current_consonant_run = 0;
			}
		}
		double entropy = 0.0;
		for (int ch = 0; ch < 128; ch++) {
			if (char_counts[ch]) {
				double prob = (double)char_counts[ch] / (double)domain_len;
				entropy -= prob * log2(prob);
			}
		}
		lexical_out[0] = (float)domain_len;
		lexical_out[1] = (float)((double)digits / (double)domain_len);
		lexical_out[2] = (float)((double)vowels / (double)domain_len);
		lexical_out[3] = (float)entropy;
		lexical_out[4] = (float)max_consonant_run;
	}

	/* 3) per-class bigram average log-likelihood */
	for (unsigned class_idx = 0; class_idx < N_CLASSES; class_idx++) {
		double avg_log_prob = model_state.bigram_default[class_idx];
		if (domain_len >= 2) {
			double log_prob_sum = 0.0;
			const double (*table)[ALPHABET] =
				(const double (*)[ALPHABET])(model_state.bigram_log_probs + (size_t)class_idx * ALPHABET * ALPHABET);
			for (size_t i = 0; i + 1 < domain_len; i++)
				log_prob_sum += table[(unsigned char)domain_name[i]][(unsigned char)domain_name[i + 1]];
			avg_log_prob = log_prob_sum / (double)(domain_len - 1);
		}
		out_features[model_state.num_cv_columns + N_LEXICAL + class_idx] = (float)avg_log_prob;
	}

	return 0;
}

static int read_file(const char *path, unsigned char **buffer_out, size_t *len_out)
{
	FILE *file = fopen(path, "rb");
	if (!file)
		return -1;
	unsigned char *buffer = NULL;
	long file_size;
	if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) < 0
	|| (unsigned long)file_size > MAX_CONTAINER_BYTES || fseek(file, 0, SEEK_SET) != 0)
		goto fail;
	buffer = malloc(file_size ? (size_t)file_size : 1);
	if (!buffer || fread(buffer, 1, (size_t)file_size, file) != (size_t)file_size)
		goto fail;
	fclose(file);
	*buffer_out = buffer;
	*len_out = (size_t)file_size;
	return 0;
fail:
	free(buffer);
	fclose(file);
	return -1;
}

void dga_features_unload(void)
{
	free(model_state.container_blob);
	free(model_state.vocab);
	free(model_state.bigram_log_probs);
	memset(&model_state, 0, sizeof(model_state));
}

int dga_features_load(const char *path, const unsigned char **onnx_data, size_t *onnx_len)
{
	dga_features_unload();

	unsigned char *buffer = NULL;
	size_t size = 0;
	if (read_file(path, &buffer, &size) != 0)
		return -1;
	model_state.container_blob = buffer;

	if (size < HEADER_SIZE || memcmp(buffer, MAGIC, 4) != 0 || read_u32_le(buffer + 4) != FORMAT_VERSION)
		goto fail;
	uint32_t num_cv = read_u32_le(buffer + 8);
	uint64_t onnx_len_field = read_u64_le(buffer + 12);

	if (num_cv == 0 || (uint64_t)num_cv + N_LEXICAL + N_CLASSES != (uint64_t)DGA_N_FEATURES)
		goto fail;
	if (onnx_len_field == 0 || onnx_len_field > size)
		goto fail;
	uint64_t expected_size = HEADER_SIZE + onnx_len_field + (uint64_t)GRAM_BYTES * num_cv + BIGRAM_BYTES;
	if (expected_size != (uint64_t)size)
		goto fail;

	const unsigned char *onnx_ptr = buffer + HEADER_SIZE;
	const unsigned char *vocab_ptr = onnx_ptr + onnx_len_field;
	const unsigned char *bigram_ptr = vocab_ptr + (size_t)GRAM_BYTES * num_cv;

	model_state.vocab = calloc(num_cv, sizeof(*model_state.vocab));
	if (!model_state.vocab)
		goto fail;
	for (uint32_t i = 0; i < num_cv; i++) {
		const unsigned char *row_ptr = vocab_ptr + (size_t)GRAM_BYTES * i;
		if (row_ptr[0] == 0 || row_ptr[0] >= 128 || row_ptr[1] == 0 || row_ptr[1] >= 128 || row_ptr[2] >= 128)
			goto fail;
		model_state.vocab[i].key = (uint32_t)row_ptr[0] << 16 | (uint32_t)row_ptr[1] << 8 | row_ptr[2];
		model_state.vocab[i].idx = i;
	}
	qsort(model_state.vocab, num_cv, sizeof(*model_state.vocab), vocab_compare);
	for (uint32_t i = 1; i < num_cv; i++) {
		if (model_state.vocab[i - 1].key == model_state.vocab[i].key)
			goto fail;
	}
	model_state.num_cv_columns = num_cv;

	for (unsigned class_idx = 0; class_idx < N_CLASSES; class_idx++)
		model_state.bigram_default[class_idx] = read_f64_le(bigram_ptr + 8 * class_idx);
	bigram_ptr += 8 * N_CLASSES;
	model_state.bigram_log_probs = malloc((size_t)N_CLASSES * ALPHABET * ALPHABET * sizeof(double));
	if (!model_state.bigram_log_probs)
		goto fail;
	for (size_t i = 0; i < (size_t)N_CLASSES * ALPHABET * ALPHABET; i++)
		model_state.bigram_log_probs[i] = read_f64_le(bigram_ptr + 8 * i);

	model_state.is_loaded = 1;
	*onnx_data = onnx_ptr;
	*onnx_len = (size_t)onnx_len_field;
	return 0;

fail:
	dga_features_unload();
	return -1;
}
