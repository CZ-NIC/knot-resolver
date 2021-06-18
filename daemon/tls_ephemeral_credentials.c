/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 * Copyright (C) 2016-2017 CZ.NIC, z.s.p.o.
 * 
 * Initial Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <sys/file.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

#include "daemon/worker.h"
#include "daemon/tls.h"

#define EPHEMERAL_PRIVKEY_FILENAME "ephemeral_key.pem"
#define INVALID_HOSTNAME "dns-over-tls.invalid"
#define EPHEMERAL_CERT_EXPIRATION_SECONDS (60*60*24*90)

/* This is an attempt to grab an exclusive, advisory, non-blocking
 * lock based on a filename.  At the moment it's POSIX-only, but it
 * should be abstract enough of an interface to make an implementation
 * for non-posix systems if anyone cares. */
typedef int lock_t;
static bool _lock_is_invalid(lock_t lock)
{
	return lock == -1;
}
/* a blocking lock on a given filename */
static lock_t _lock_filename(const char *fname)
{
	lock_t lockfd = open(fname, O_RDONLY|O_CREAT, 0400);
	if (lockfd == -1)
		return lockfd;
	/* this should be a non-blocking lock */
	if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
		close(lockfd);
		return -1;
	}
	return lockfd; /* for cleanup later */
}
static void _lock_unlock(lock_t *lock, const char *fname)
{
	if (lock && !_lock_is_invalid(*lock)) {
		flock(*lock, LOCK_UN);
		close(*lock);
		*lock = -1;
		unlink(fname); /* ignore errors */
	}
}

static gnutls_x509_privkey_t get_ephemeral_privkey ()
{
	gnutls_x509_privkey_t privkey = NULL;
	int err;
	gnutls_datum_t data = { .data = NULL, .size = 0 };
	lock_t lock;
	int datafd = -1;

	/* Take a lock to ensure that two daemons started concurrently
	 * with a shared cache don't both create the same privkey: */
	lock = _lock_filename(EPHEMERAL_PRIVKEY_FILENAME ".lock");
	if (_lock_is_invalid(lock)) {
		kr_log_error(LOG_GRP_TLS, "unable to lock lockfile " EPHEMERAL_PRIVKEY_FILENAME ".lock\n");
		goto done;
	}
	
	if ((err = gnutls_x509_privkey_init (&privkey)) < 0) {
		kr_log_error(LOG_GRP_TLS, "gnutls_x509_privkey_init() failed: %d (%s)\n",
			     err, gnutls_strerror_name(err));
		goto done;
	}

	/* read from cache file (we assume that we've chdir'ed
	 * already, so we're just looking for the file in the
	 * cachedir. */
	datafd = open(EPHEMERAL_PRIVKEY_FILENAME, O_RDONLY);
	if (datafd != -1) {
		struct stat stat;
		ssize_t bytes_read;
		if (fstat(datafd, &stat)) {
			kr_log_error(LOG_GRP_TLS, "unable to stat ephemeral private key " EPHEMERAL_PRIVKEY_FILENAME "\n");
			goto bad_data;
		}
		data.data = gnutls_malloc(stat.st_size);
		if (data.data == NULL) {
			kr_log_error(LOG_GRP_TLS, "unable to allocate memory for reading ephemeral private key\n");
			goto bad_data;
		}
		data.size = stat.st_size;
		bytes_read = read(datafd, data.data, stat.st_size);
		if (bytes_read != stat.st_size) {
			kr_log_error(LOG_GRP_TLS, "unable to read ephemeral private key\n");
			goto bad_data;
		}
		if ((err = gnutls_x509_privkey_import (privkey, &data, GNUTLS_X509_FMT_PEM)) < 0) {
			kr_log_error(LOG_GRP_TLS, "gnutls_x509_privkey_import() failed: %d (%s)\n",
				     err, gnutls_strerror_name(err));
			/* goto bad_data; */
		bad_data:
			close(datafd);
			datafd = -1;
		}
		if (data.data != NULL) {
			gnutls_free(data.data);
			data.data = NULL;
		}
	}
	if (datafd == -1) {
		/* if loading failed, then generate ... */
#if GNUTLS_VERSION_NUMBER >= 0x030500
		if ((err = gnutls_x509_privkey_generate(privkey, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0)) < 0) {
#else
		if ((err = gnutls_x509_privkey_generate(privkey, GNUTLS_PK_RSA, gnutls_sec_param_to_pk_bits(GNUTLS_PK_RSA, GNUTLS_SEC_PARAM_MEDIUM), 0)) < 0) {
#endif
			kr_log_error(LOG_GRP_TLS, "gnutls_x509_privkey_init() failed: %d (%s)\n",
				     err, gnutls_strerror_name(err));
			gnutls_x509_privkey_deinit(privkey);
			goto done;
		}
		/* ... and save */
		kr_log_info(LOG_GRP_TLS, "Stashing ephemeral private key in " EPHEMERAL_PRIVKEY_FILENAME "\n");
		if ((err = gnutls_x509_privkey_export2(privkey, GNUTLS_X509_FMT_PEM, &data)) < 0) {
			kr_log_error(LOG_GRP_TLS, "gnutls_x509_privkey_export2() failed: %d (%s), not storing\n",
				     err, gnutls_strerror_name(err));
		} else {
			datafd = open(EPHEMERAL_PRIVKEY_FILENAME, O_WRONLY|O_CREAT, 0600);
			if (datafd == -1) {
				kr_log_error(LOG_GRP_TLS, "failed to open " EPHEMERAL_PRIVKEY_FILENAME " to store the ephemeral key\n");
			} else {
				ssize_t bytes_written;
				bytes_written = write(datafd, data.data, data.size);
				if (bytes_written != data.size)
					kr_log_error(LOG_GRP_TLS, "failed to write %d octets to "
						     EPHEMERAL_PRIVKEY_FILENAME
						     " (%zd written)\n",
						     data.size, bytes_written);
			}
		}
	}
 done:
	_lock_unlock(&lock, EPHEMERAL_PRIVKEY_FILENAME ".lock");
	if (datafd != -1) {
		close(datafd);
	}
	if (data.data != NULL) {
		gnutls_free(data.data);
	}
	return privkey;
}

static gnutls_x509_crt_t get_ephemeral_cert(gnutls_x509_privkey_t privkey, const char *servicename, time_t invalid_before, time_t valid_until)
{
	gnutls_x509_crt_t cert = NULL;
	int err;
	/* need a random buffer of bytes */
	uint8_t serial[16];
	gnutls_rnd(GNUTLS_RND_NONCE, serial, sizeof(serial));
	/* clear the left-most bit to avoid signedness confusion: */
	serial[0] &= 0x8f;
	size_t namelen = strlen(servicename);

#define gtx(fn, ...)							\
	if ((err = fn ( __VA_ARGS__ )) != GNUTLS_E_SUCCESS) {		\
		kr_log_error(LOG_GRP_TLS, #fn "() failed: %d (%s)\n",	\
			     err, gnutls_strerror_name(err));		\
		goto bad; }

	gtx(gnutls_x509_crt_init, &cert);
	gtx(gnutls_x509_crt_set_activation_time, cert, invalid_before);
	gtx(gnutls_x509_crt_set_ca_status, cert, 0);
	gtx(gnutls_x509_crt_set_expiration_time, cert, valid_until);
	gtx(gnutls_x509_crt_set_key, cert, privkey);
	gtx(gnutls_x509_crt_set_key_purpose_oid, cert, GNUTLS_KP_TLS_WWW_CLIENT, 0);
	gtx(gnutls_x509_crt_set_key_purpose_oid, cert, GNUTLS_KP_TLS_WWW_SERVER, 0);
	gtx(gnutls_x509_crt_set_key_usage, cert, GNUTLS_KEY_DIGITAL_SIGNATURE);
	gtx(gnutls_x509_crt_set_serial, cert, serial, sizeof(serial));
	gtx(gnutls_x509_crt_set_subject_alt_name, cert, GNUTLS_SAN_DNSNAME, servicename, namelen, GNUTLS_FSAN_SET);
	gtx(gnutls_x509_crt_set_dn_by_oid,cert, GNUTLS_OID_X520_COMMON_NAME, 0, servicename, namelen);
	gtx(gnutls_x509_crt_set_version, cert, 3);
	gtx(gnutls_x509_crt_sign2,cert, cert, privkey, GNUTLS_DIG_SHA256, 0); /* self-sign, since it doesn't look like we can just stub-sign */
#undef gtx

	return cert;
bad:
	gnutls_x509_crt_deinit(cert);
	return NULL;
}

struct tls_credentials * tls_get_ephemeral_credentials(struct engine *engine)
{
	struct tls_credentials *creds = NULL;
	gnutls_x509_privkey_t privkey = NULL;
	gnutls_x509_crt_t cert = NULL;
	int err;
	time_t now = time(NULL);

	creds = calloc(1, sizeof(*creds));
	if (!creds) {
		kr_log_error(LOG_GRP_TLS, "failed to allocate memory for ephemeral credentials\n");
		return NULL;
	}
	if ((err = gnutls_certificate_allocate_credentials(&(creds->credentials))) < 0) {
		kr_log_error(LOG_GRP_TLS, "failed to allocate memory for ephemeral credentials\n");
		goto failure;
	}

	creds->valid_until = now + EPHEMERAL_CERT_EXPIRATION_SECONDS;
	creds->ephemeral_servicename = strdup(engine_get_hostname(engine));
	if (creds->ephemeral_servicename == NULL) {
		kr_log_error(LOG_GRP_TLS, "could not get server's hostname, using '" INVALID_HOSTNAME "' instead\n");
		if ((creds->ephemeral_servicename = strdup(INVALID_HOSTNAME)) == NULL) {
			kr_log_error(LOG_GRP_TLS, "failed to allocate memory for ephemeral credentials\n");
			goto failure;
		}
	}		
	if ((privkey = get_ephemeral_privkey()) == NULL) {
		goto failure;
	}
	if ((cert = get_ephemeral_cert(privkey, creds->ephemeral_servicename, now - 60*15, creds->valid_until)) == NULL) {
		goto failure;
	}
	if ((err = gnutls_certificate_set_x509_key(creds->credentials, &cert, 1, privkey)) < 0) {
		kr_log_error(LOG_GRP_TLS, "failed to set up ephemeral credentials\n");
		goto failure;
	}
	gnutls_x509_privkey_deinit(privkey);
	gnutls_x509_crt_deinit(cert);
	return creds;
 failure:
	gnutls_x509_privkey_deinit(privkey);
	gnutls_x509_crt_deinit(cert);
	tls_credentials_free(creds);
	return NULL;
}
