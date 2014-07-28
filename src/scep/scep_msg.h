/*
 * SCEP - Message building and handling functions
 */

#include "scep.h"
#include "scep_sigattr.h"
#include "scep_bio.h"
#include "scep_asn1.h"

/* Function Prototypes */
SCEP_MSG *SCEP_MSG_new( int messageType, X509 *cert, EVP_PKEY *pkey,
	X509 *recip_cert, SCEP_MSG *inMsg, X509_REQ *req, X509 *issued_cert,
	SCEP_ISSUER_AND_SUBJECT *cert_info, PKCS7_ISSUER_AND_SERIAL *p7_ias,
	X509_CRL *crl, X509 *cacert, EVP_CIPHER cipher);

int SCEP_MSG_free( SCEP_MSG *msg );

/* Encrypt/Decrypt data within a SCEP_MSG if any */
int SCEP_MSG_encrypt( SCEP_MSG *msg, X509 *recip_cert, EVP_CIPHER cipher );
unsigned char *SCEP_MSG_decrypt( SCEP_MSG *msg, EVP_PKEY *pkey, X509 *cert,
	long *len );

/* NONCE conversion */
char *SCEP_MSG_nonce2hex ( SCEP_MSG *msg, char *nonceAttr );
char *SCEP_MSG_recipient_nonce2hex ( SCEP_MSG *msg );
char *SCEP_MSG_sender_nonce2hex ( SCEP_MSG *msg );

/* get transid */
char *SCEP_MSG_transid ( SCEP_MSG *msg );

/* Decrypt MACROS for different messageType(s) */
#define SCEP_MSG_decrypt_PKCSREQ(bp,pk,c,l) (X509_REQ *)SCEP_MSG_decrypt(bp,pk,c,l)
#define SCEP_MSG_decrypt_CERTREP(bp,pk,c,l) (X509_CRL *)SCEP_MSG_decrypt(bp,pk,c,l)

extern int debug;
