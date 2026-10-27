#pragma once
/*  Copyright (C) CZ.NIC, z.s.p.o. <knot-resolver@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file model_features.h
 * @brief Header file for private DGA model container loading and feature vector extraction.
 */

#include <stddef.h>
#include <stdint.h>

/**
 * 5000 vocab size + 5 lexical + 2 bigram scores. It is checked during load.
 */
#define DGA_N_FEATURES 5007

/**
 * Loads and validates the private DGA model container binary blob.
 * 
 * @param path          Path to the container file (e.g. resolver.dgamodel)
 * @param onnx_data     Output pointer set to the internal embedded ONNX byte buffer
 * @param onnx_len      Output pointer set to the length of the embedded ONNX bytes
 * @return              0 on success, -1 on failure.
 */
int dga_features_load(const char *path, const unsigned char **onnx_data, size_t *onnx_len);

/**
 * Unloads the container, freeing all allocated memory and resetting state.
 */
void dga_features_unload(void);

/**
 * Computes the complete feature vector (CountVectorizer + Lexical + Bigram) 
 * for a given domain stem name (creates and input vector for inference from string).
 * 
 * @param domain_name   Lowercased domain string (SLD)
 * @param out_features  Pre-allocated array of size DGA_N_FEATURES to populate
 * @return              0 on success, -1 on failure.
 */
int build_features(const char *domain_name, float *out_features);