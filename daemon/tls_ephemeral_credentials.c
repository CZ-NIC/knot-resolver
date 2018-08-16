/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 * Copyright (C) 2016-2017 CZ.NIC, z.s.p.o.
 *
 * Initial Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <sys/file.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "daemon/worker.h"
#include "daemon/tls.h"

#define EPHEMERAL_PRIVKEY_FILENAME "ephemeral_key.pem"
#define INVALID_HOSTNAME "dns-over-tls.invalid"
#define EPHEMERAL_CERT_EXPIRATION_SECONDS 60*60*24*90

/* This is an attempt to grab an exclusive, advisory, non-blocking
 * lock based on a filename.  At the moment it's POSIX-only, but it
 * should be abstract enough of an interface to make an implementation
 * for non-posix systems if anyone cares. */
typedef int lock;
static bool _lock_is_invalid(lock lock)
{
	return lock == -1;
}
/* a blocking lock on a given filename */
static lock _lock_filename(const char *fname)
{
	lock lockfd = open(fname, O_RDONLY|O_CREAT, 0400);
	if (lockfd == -1)
		return lockfd;
	/* this should be a non-blocking lock */
	if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
		close(lockfd);
		return -1;
	}
	return lockfd; /* for cleanup later */
}
static void _lock_unlock(lock *lock, const char *fname)
{
	if (lock && !_lock_is_invalid(*lock)) {
		flock(*lock, LOCK_UN);
		close(*lock);
		*lock = -1;
		unlink(fname); /* ignore errors */
	}
}

static EVP_PKEY *get_ephemeral_privkey ()
{
	EVP_PKEY *privkey = NULL;
	lock lock;
	int datafd = -1;

	/* Take a lock to ensure that two daemons started concurrently
	 * with a shared cache don't both create the same privkey: */
	lock = _lock_filename(EPHEMERAL_PRIVKEY_FILENAME ".lock");
	if (_lock_is_invalid(lock)) {
		kr_log_error("[tls] unable to lock lockfile " EPHEMERAL_PRIVKEY_FILENAME ".lock\n");
		goto done;
	}

	privkey = EVP_PKEY_new();
	if (privkey == NULL) {
		kr_log_error("[tls] EVP_PKEY_new() failed");
		goto done;
	}

	/* read from cache file (we assume that we've chdir'ed
	 * already, so we're just looking for the file in the
	 * cachedir. */
	datafd = open(EPHEMERAL_PRIVKEY_FILENAME, O_RDONLY);
	if (datafd != -1) {
		struct stat stat;
		if (fstat(datafd, &stat)) {
			kr_log_error("[tls] unable to stat ephemeral private key " EPHEMERAL_PRIVKEY_FILENAME "\n");
			goto bad_data;
		}
		FILE *datastream = fdopen(datafd, "r");
		if (PEM_read_PrivateKey(datastream, &privkey, NULL, NULL)) {
			fclose(datastream);
			goto done;
		} else {
			kr_log_error("[tls] PEM_read_PrivateKey() failed\n");
			fclose(datastream);
			/* goto bad_data; */
		}

		bad_data:
			close(datafd);
			datafd = -1;
	}
	if (datafd == -1) {
		/* if loading failed, then generate ... */
		EC_KEY * eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

		if (eckey == NULL) {
			kr_log_error("[tls] EC_KEY_new() failed\n");
			EVP_PKEY_free(privkey);
			goto done;
		}

		if (!EC_KEY_generate_key_fips(eckey)) {
			kr_log_error("[tls] EC_KEY_generate_key_fips() failed\n");
			EC_KEY_free(eckey);
			EVP_PKEY_free(privkey);
			goto done;
		}

		if (!EVP_PKEY_assign_EC_KEY(privkey, eckey)) {
			kr_log_error("[tls] EC_PKEY_assign_EC_KEY() failed\n");
			EC_KEY_free(eckey);
			EVP_PKEY_free(privkey);
			goto done;
		}

		/* ... and save */
		kr_log_info("[tls] Stashing ephemeral private key in " EPHEMERAL_PRIVKEY_FILENAME "\n");
		FILE *datastream = fopen(EPHEMERAL_PRIVKEY_FILENAME, "w");
		/* not encrypted on disk! */
		if (!PEM_write_PrivateKey(datastream, privkey, NULL, NULL, 0, 0, NULL)) {
			kr_log_error("[tls] PEM_write_PrivateKey failed, not storing\n");
		}
		fclose(datastream);
	}
done:
	_lock_unlock(&lock, EPHEMERAL_PRIVKEY_FILENAME ".lock");
	if (datafd != -1) {
		close(datafd);
	}
	return privkey;
}

static X509 *get_ephemeral_cert(EVP_PKEY *pkey, char *servicename, time_t invalid_before, time_t valid_until)
{
	X509 *cert = X509_new();
	int success;
	/* need a random buffer of bytes */
	uint8_t serial[16];
	RAND_bytes(serial, sizeof(serial));
	/* clear the left-most bit to avoid signedness confusion: */
	serial[0] &= 0x8f;
	ASN1_TIME *asn1_invalid_before = ASN1_TIME_new();
	ASN1_TIME *asn1_valid_until = ASN1_TIME_new();
	ASN1_INTEGER *asn1_serial = ASN1_INTEGER_new();
	BIGNUM *bn_serial = BN_new();
	GENERAL_NAME *gen_san = GENERAL_NAME_new();
	GENERAL_NAMES *gens_san = sk_GENERAL_NAME_new_null();
	ASN1_IA5STRING *ia5_san = ASN1_IA5STRING_new();
	X509_NAME *x509_dn = X509_NAME_new();

	ASN1_TIME_set(asn1_valid_until, valid_until);
	ASN1_TIME_set(asn1_invalid_before, invalid_before);
	BN_bin2bn(serial, sizeof(serial), bn_serial);
	BN_to_ASN1_INTEGER(bn_serial, asn1_serial);

	assert(cert && asn1_invalid_before && asn1_valid_until && asn1_serial && bn_serial && gen_san && gens_san && ia5_san && x509_dn);

#define gtx(fn, ...)							  \
	if (!(success = fn ( __VA_ARGS__ ))) {		  \
		kr_log_error("[tls] " #fn "() failed\n"); \
		goto done; }

	gtx(X509_set_notBefore, cert, asn1_invalid_before);
	cert->ex_flags &= ~EXFLAG_CA;
	gtx(X509_set_notAfter, cert, asn1_valid_until);
	gtx(X509_set_pubkey, cert, pkey);
	cert->ex_flags |= EXFLAG_XKUSAGE;
	cert->ex_xkusage |= X509_PURPOSE_SSL_CLIENT;
	cert->ex_xkusage |= X509_PURPOSE_SSL_SERVER;
	cert->ex_flags |= EXFLAG_KUSAGE;
	cert->ex_kusage |= KU_DIGITAL_SIGNATURE;
	gtx(X509_set_serialNumber, cert, asn1_serial);
	gtx(ASN1_STRING_set, ia5_san, servicename, -1);
	GENERAL_NAME_set0_value(gen_san, GEN_DNS, ia5_san);
	gtx(sk_GENERAL_NAME_push, gens_san, gen_san);
	gtx(X509_add1_ext_i2d, cert, NID_subject_alt_name, gens_san, 0, 0);
	gtx(X509_NAME_add_entry_by_NID, x509_dn, NID_commonName, MBSTRING_ASC, (unsigned char *)servicename, -1, -1, 0);
	gtx(X509_set_subject_name, cert, x509_dn);
	gtx(X509_set_version, cert, 3);
	gtx(X509_sign, cert, pkey, EVP_sha256()); /* self-sign, since it doesn't look like we can just stub-sign */
#undef gtx

done:
	ASN1_TIME_free(asn1_invalid_before);
	ASN1_TIME_free(asn1_valid_until);
	ASN1_INTEGER_free(asn1_serial);
	BN_free(bn_serial);
	X509_NAME_free(x509_dn);
	GENERAL_NAMES_free(gens_san);

	if (success) {
		return cert;
	}

	ASN1_IA5STRING_free(ia5_san);
	GENERAL_NAME_free(gen_san);
	X509_free(cert);
	return NULL;
}

struct tls_credentials *tls_get_ephemeral_credentials(struct engine *engine)
{
	struct tls_credentials *creds = NULL;
	EVP_PKEY *privkey = NULL;
	X509 *cert = NULL;
	time_t now = time(NULL);

	creds = calloc(1, sizeof(*creds));
	if (!creds) {
		kr_log_error("[tls] failed to allocate memory for ephemeral credentials\n");
		return NULL;
	}

	creds->valid_until = now + EPHEMERAL_CERT_EXPIRATION_SECONDS;
	creds->ephemeral_servicename = strdup(engine_get_hostname(engine));
	if (creds->ephemeral_servicename == NULL) {
		kr_log_error("[tls] could not get server's hostname, using '" INVALID_HOSTNAME "' instead\n");
		if ((creds->ephemeral_servicename = strdup(INVALID_HOSTNAME)) == NULL) {
			kr_log_error("[tls] failed to allocate memory for ephemeral credentials\n");
			goto failure;
		}
	}
	if ((privkey = get_ephemeral_privkey()) == NULL) {
		kr_log_error("[tls] get_ephemeral_privkey() failed\n");
		goto failure;
	}
	if ((cert = get_ephemeral_cert(privkey, creds->ephemeral_servicename, now - 60*15, creds->valid_until)) == NULL) {
		kr_log_error("[tls] get_ephemeral_cert() failed\n");
		goto failure;
	}

	STACK_OF(X509) *chain = sk_X509_new_null();
	if (sk_X509_push(chain, cert) < 1) {
		kr_log_error("[tls] failed to push certificate to certificate stack\n");
		goto failure;
	}

	creds->tls_key = privkey;
	creds->tls_cert_chain = chain;

	return creds;
 failure:
	EVP_PKEY_free(privkey);
	X509_free(cert);
	tls_credentials_free(creds);
	return NULL;
}
