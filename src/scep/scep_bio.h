/*
 * SCEP - Bio Handling Routines
 */

#include "scep.h"
#include "scep_sigattr.h"
#include "scep_pk7.h"

#include <openssl/asn1_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>

/* Load/write a PKCS7 ISSUER and SERIAL from bio */
PKCS7_ISSUER_AND_SERIAL	*d2i_PKCS7_ias_bio( PKCS7_ISSUER_AND_SERIAL **ias,
	       	BIO *bio);
int i2d_PKCS7_ias_bio(BIO *bio, PKCS7_ISSUER_AND_SERIAL *ias);

/* Load a SCEP_MSG from bio */
SCEP_MSG *PEM_SCEP_MSG_bio( BIO *bio );
SCEP_MSG *d2i_SCEP_MSG_bio (BIO *bio );

/* Text Printing for a SCEP_MSG */
int SCEP_MSG_print( BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey, X509 *cert );

/* Convert PKCS7 structure to Base64 format */
int B64_write_PKCS7(BIO *bio, PKCS7 *p7);
int B64_write_bio_SCEP_MSG(BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey );
int PEM_write_bio_SCEP_MSG(BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey);
int i2d_SCEP_MSG_bio( BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey );

