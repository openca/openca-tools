/*
 * SCEP - Message building and handling functions
 */

#include "scep.h"
#include "scep_asn1.h"

PKCS7* i2pk7_SCEP_MSG ( SCEP_MSG *msg, EVP_PKEY *pkey );

