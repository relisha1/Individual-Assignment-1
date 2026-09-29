/*
 * openssl_compat.h
 * ------------------------------------------------------------------
 * Minimal hand-written prototypes for the small subset of OpenSSL's
 * libcrypto that this project uses (SHA-256 and ECDSA over P-256).
 *
 * Why this file exists:
 *   The build environment ships the OpenSSL *runtime* library
 *   (libcrypto.so.3) but not the "libssl-dev" package that normally
 *   provides <openssl/sha.h> and <openssl/ec.h>. Rather than vendor
 *   the entire OpenSSL header tree, we declare exactly the functions
 *   we call. The ABI (calling convention, argument types) is stable
 *   across OpenSSL 1.1/3.0 for these legacy-but-still-exported calls,
 *   so this compiles and links cleanly against libcrypto.so(.3).
 *
 * On a normal developer machine with `libssl-dev` installed you can
 * simply replace the includes of this header in main.c with:
 *      #include <openssl/sha.h>
 *      #include <openssl/ec.h>
 *      #include <openssl/ecdsa.h>
 *      #include <openssl/obj_mac.h>
 * and everything else in this project is unchanged.
 * ------------------------------------------------------------------
 */
#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- SHA-256 (openssl/sha.h) ---- */
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
#define SHA256_DIGEST_LENGTH 32

/* ---- Elliptic-curve key object (openssl/ec.h) ---- */
typedef struct ec_key_st EC_KEY;

EC_KEY *EC_KEY_new_by_curve_name(int nid);
int     EC_KEY_generate_key(EC_KEY *key);
void    EC_KEY_free(EC_KEY *key);

/* NIST P-256 curve id (openssl/obj_mac.h) */
#define NID_X9_62_prime256v1 415

/* ---- ECDSA signing / verification (openssl/ecdsa.h) ---- */
int ECDSA_sign(int type,
               const unsigned char *dgst, int dgstlen,
               unsigned char *sig, unsigned int *siglen,
               EC_KEY *eckey);

int ECDSA_verify(int type,
                  const unsigned char *dgst, int dgstlen,
                  const unsigned char *sig, int siglen,
                  EC_KEY *eckey);

int ECDSA_size(const EC_KEY *key);

/* ---- DER (de)serialisation, used to persist the library's keypair ---- */
EC_KEY *d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len);
int     i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_COMPAT_H */
