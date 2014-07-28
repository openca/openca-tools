/* SCEP ASN.1 implementation
 * (c) 2003 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the OpenCA License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include "scep_asn1.h"
 
ASN1_SEQUENCE(SCEP_ISSUER_AND_SUBJECT) = {
        ASN1_SIMPLE(SCEP_ISSUER_AND_SUBJECT, issuer, X509_NAME),
        ASN1_SIMPLE(SCEP_ISSUER_AND_SUBJECT, subject, X509_NAME)
} ASN1_SEQUENCE_END(SCEP_ISSUER_AND_SUBJECT)
 
IMPLEMENT_ASN1_FUNCTIONS(SCEP_ISSUER_AND_SUBJECT)

