/*
 * OpenCA SCEP MSG attributes handling routines
 * (c) 2002 by Massimiliano Pala and OpenCA Group
 *
 * Thanks to the OpenSCEP project for help and suggestions.
 *
 */

#include "scep.h"

X509_ATTRIBUTE *SCEP_get_attr_by_name( STACK_OF(X509_ATTRIBUTE) *attrs,
		char *attrname );
unsigned char *SCEP_get_octect_attr_by_name (STACK_OF(X509_ATTRIBUTE) *attrs,
		char *attrname, int *attr_len);
char *SCEP_get_string_attr_by_name (STACK_OF(X509_ATTRIBUTE) *attrs,
		char *attrname);

int SCEP_add_attr_by_name( STACK_OF(X509_ATTRIBUTE) *sk, char *attrname,
		void *value, long len );
