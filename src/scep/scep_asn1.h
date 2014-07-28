/*
 * SCEP REQUEST
 */

#include "scep.h"

#include <openssl/asn1_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>

DECLARE_ASN1_FUNCTIONS(SCEP_ISSUER_AND_SUBJECT)

/* New Issuer and Subject structure */
SCEP_ISSUER_AND_SUBJECT	*SCEP_ISSUER_AND_SUBJECT_new(void);

/* Free Issuer and Subject */
void SCEP_ISSUER_AND_SUBJECT_free(SCEP_ISSUER_AND_SUBJECT *ias);
