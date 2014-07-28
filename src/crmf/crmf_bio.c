/* CMS Support for LibPKI 
 * (c) 2008 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <openca/crmf_asn1.h>
#include <openca/crmf_bio.h>
#include <openssl/pem.h>

/* DER <-> INTERNAL Macros */
CRMF_REQ *d2i_CRMF_REQ_bio ( BIO *bp, CRMF_REQ *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (CRMF_REQ *) ASN1_d2i_bio(
			(char *(*)(void))CRMF_REQ_new, 
			(char *(*)(void **, const unsigned char **, long))d2i_CRMF_REQ, 
			bp, (unsigned char **) &p);
#else
	return (CRMF_REQ *) ASN1_d2i_bio(
			(void *(*)(void))CRMF_REQ_new, 
			(void *(*)(void **, const unsigned char **, long))d2i_CRMF_REQ, 
			bp, (void **) &p);
#endif
}

int i2d_CRMF_REQ_bio(BIO *bp, CRMF_REQ *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(CRMF_REQ *, unsigned char **)) i2d_CRMF_REQ, bp, (unsigned char *) o);
#else
	return ASN1_i2d_bio( (i2d_of_void *) i2d_CRMF_REQ, bp, (unsigned char *) o);
#endif
}


/* PEM <-> INTERNAL Macros */
CRMF_REQ *PEM_read_bio_CRMF_REQ( BIO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (CRMF_REQ *) PEM_ASN1_read_bio( (char *(*)()) d2i_CRMF_REQ, 
				PEM_STRING_CRMF_REQ, bp, NULL, NULL, NULL);
#else
	return (CRMF_REQ *) PEM_ASN1_read_bio( (void *(*)()) d2i_CRMF_REQ, 
				PEM_STRING_CRMF_REQ, bp, NULL, NULL, NULL);
#endif
}


int PEM_write_bio_CRMF_REQ( BIO *bp, CRMF_REQ *o ) {
	return PEM_ASN1_write_bio ( (int (*)())i2d_CRMF_REQ, 
			PEM_STRING_CRMF_REQ, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}

