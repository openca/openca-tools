/*
 * OpenCA SCEP -- signed attributes handling routines
 * (c) 2002 by Massimiliano Pala and OpenCA Group
 *
 * Thanks goes to OpenSCEP project for help and suggestions,
 * in particular to:
 * 
 * Dr. Andreas Mueller, Beratung und Entwicklung
 *
 */

#include "scep.h"
#include "scep_sigattr.h"

#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/*
 * read an attribute of type string
 */

static int debug=0;

X509_ATTRIBUTE *SCEP_get_attr_by_name( STACK_OF(X509_ATTRIBUTE) *attrs,
		char *attrname ) {

	ASN1_OBJECT *asn1_obj = NULL;
	X509_ATTRIBUTE	*attr = NULL;

	char *data = NULL;
	int i, length, found;
	
	/* find the object we by name					*/
	asn1_obj = OBJ_nid2obj(OBJ_sn2nid(attrname));

	/* retrieve the stack of signed attributes			*/
	if ( (attrs == NULL) || (sk_X509_ATTRIBUTE_num(attrs) < 1)){
		return NULL;
	}

	found = 0;

	/* scan all attributes for the one we are looking for		*/
	for (i = 0; i < sk_X509_ATTRIBUTE_num(attrs); i++) {
		attr = sk_X509_ATTRIBUTE_value(attrs, i);
		if (OBJ_cmp(attr->object, asn1_obj) == 0) {
			found = 1;
			break;
		}
	}

	if( found ) 
		return attr;
	else
		return NULL;
}

unsigned char *SCEP_get_octect_attr_by_name (STACK_OF(X509_ATTRIBUTE) *attrs,
		char *attrname, int *attr_len) {

	ASN1_OCTET_STRING *asn1;
	unsigned char *data = NULL;
	ASN1_TYPE *asn1_type = NULL;
	X509_ATTRIBUTE *attr = NULL;

	int len = 0;

	if( ((attr = SCEP_get_attr_by_name( attrs, attrname )) == NULL) ||
		(asn1_type = sk_ASN1_TYPE_value(attr->value.set,0)) == NULL) {
		return NULL;
	}

	if ((attr->value.set == NULL ) || 
			(sk_ASN1_TYPE_num(attr->value.set) == 0)) {
			goto err;
	}

	asn1_type = sk_ASN1_TYPE_value(attr->value.set, 0);
	if (ASN1_TYPE_get(asn1_type) != V_ASN1_OCTET_STRING) {
		goto err;
	}

	/* Now we copy the value of the asn1 octect string value to the
	 * returning data pointer */
	len = ASN1_STRING_length(asn1_type->value.octet_string);
	data = (unsigned char *)malloc(len);
	memcpy(data, ASN1_STRING_data(asn1_type->value.octet_string),
			len);

	if( attr_len ) *attr_len = len;

	/* return the data						*/
	return data;
err:
	return NULL;
}

char *SCEP_get_string_attr_by_name (STACK_OF(X509_ATTRIBUTE) *attrs,
		char *attrname){

	ASN1_TYPE *asn1_type = NULL;
	X509_ATTRIBUTE	*attr = NULL;

	char *data = NULL;
	int i, length;
	
	if((attr = SCEP_get_attr_by_name( attrs, attrname )) == NULL) {
		return NULL;
	}

	if ((asn1_type = sk_ASN1_TYPE_value(attr->value.set,0)) == NULL) {
		return NULL;
	}

	if (ASN1_TYPE_get(asn1_type) != V_ASN1_PRINTABLESTRING) {
		goto err;
	}


	/* error return, or attribute not found				*/
	/* unpack the ASN1_STRING into a C-String (0-terminated)	*/
	length = ASN1_STRING_length(asn1_type->value.asn1_string);
	data = (char *)malloc(length + 1);
	memcpy(data, ASN1_STRING_data(asn1_type->value.asn1_string),
			length);
	data[length] = '\0';

	/* return the data						*/
	return data;
err:
	// ERR_print_errors(stderr);
	return NULL;
}

int SCEP_set_messageType( SCEP_MSG *msg, int msgtype ) {
	char buf[256];

	// memset( buf, '\x0', sizeof(buf) );
	sprintf(buf, "%d\x0", msgtype);
	msg->messageType = msgtype;

	return SCEP_add_attr_by_name( msg->attrs, 
				MESSAGE_TYPE_OID_STRING, buf, strlen(buf));
}

int SCEP_set_pkiStatus( SCEP_MSG *msg, int status ) {
	char buf[256];

	if( !msg ) return 0;
	//sprintf( buf, "%s\x0", SCEP_status2str(status));
	sprintf( buf, "%d\x0", status );
	return SCEP_add_attr_by_name( msg->attrs,
			PKI_STATUS_OID_STRING, buf, strlen(buf));
}

int SCEP_set_failInfo( SCEP_MSG *msg, int info ) {
	char buf[256];

	if( !msg ) return 0;
	//sprintf( buf, "%s\x0", SCEP_failure2str(info));
	sprintf( buf, "%d\x0", info );
	return SCEP_add_attr_by_name( msg->attrs,
			FAIL_INFO_OID_STRING, buf, strlen(buf));
}

int SCEP_set_senderNonce_new( SCEP_MSG *msg) {
	return SCEP_set_senderNonce( msg, NULL, 0 );
}

int SCEP_set_senderNonce( SCEP_MSG *msg, void *data, long len ) {
	
	if( !msg ) return 0;

	if( !data ) {
		/* If no data is given, a random nonce is
		 * generated */
		len = NONCE_SIZE;
		data = (void *) OPENSSL_malloc( NONCE_SIZE );
		RAND_bytes(data, NONCE_SIZE);
	}

	return SCEP_add_attr_by_name( msg->attrs,
			SENDER_NONCE_OID_STRING, data, len );
}

int SCEP_set_recipientNonce_new (SCEP_MSG *msg) {
	return SCEP_set_recipientNonce( msg, NULL, 0);
}

int SCEP_set_recipientNonce( SCEP_MSG *msg, void *data, long len ) {
	
	if( !msg ) return 0;

	if( !data ) {
		/* If no data is given, a random nonce is
		 * generated */
		len = NONCE_SIZE;
		data = (void *) OPENSSL_malloc( NONCE_SIZE );
		RAND_bytes(data, NONCE_SIZE);
	}


	return SCEP_add_attr_by_name( msg->attrs,
			RECIPIENT_NONCE_OID_STRING, data, len );
}

int SCEP_set_transId_new ( SCEP_MSG *msg ) {
	return SCEP_set_transId( msg, NULL, 0 );
}

int SCEP_set_transId( SCEP_MSG *msg, unsigned char *data, long len ) {
	
	char *text_data = NULL;
	int i;

	if( !msg ) return 0;

	if( !data ) {
		/* If no data is given, a random nonce is
		 * generated */
		len = TRANS_ID_SIZE;
		data = (void *) OPENSSL_malloc( len );
		RAND_bytes(data, len);
	}

	text_data = (char *) OPENSSL_malloc ( len * 2);

	/* Write data as Hex numbers */
	// not working like intended!!!
	//for( i=0; i < len; i++ ) {
	//	sprintf( &text_data[i*2], "%2.2X", data[i] );
	//}
	
	
	i = SCEP_add_attr_by_name( msg->attrs,
	//		TRANS_ID_OID_STRING, text_data, len * 2 );
			TRANS_ID_OID_STRING, data, len);
	
	if( text_data ) OPENSSL_free (text_data);
}

int SCEP_add_attr_by_name( STACK_OF(X509_ATTRIBUTE) *sk, char *attrname,
		void *value, long len ) {

	int attr_type, nid;

	if( !sk ) return 0;

	nid = OBJ_sn2nid(attrname);
	attr_type = SCEP_str2attribute( attrname );

	// printf( "%s:%d: nid=%d name=%s attr_type=%d value=%s\n", 
	// 	__FILE__, __LINE__, nid, attrname, attr_type, value );

	switch (attr_type) {
		case SCEP_MESSAGE_TYPE_ATTRIBUTE :
			attr_type = V_ASN1_PRINTABLESTRING;
                        break;
		case SCEP_PKI_STATUS_ATTRIBUTE :
			attr_type = V_ASN1_PRINTABLESTRING;
			break;
		case SCEP_FAIL_INFO_ATTRIBUTE :
			attr_type = V_ASN1_PRINTABLESTRING;
                        break;
		case SCEP_TRANS_ID_ATTRIBUTE :
			attr_type = V_ASN1_PRINTABLESTRING;
                        break;
		case SCEP_EXTENSION_REQ_ATTRIBUTE :
			// to be changed
			attr_type = 0;
			break;
		case SCEP_PROXY_AUTHENTICATOR_ATTRIBUTE :
			attr_type = V_ASN1_PRINTABLESTRING;
			break;
		case SCEP_SENDER_NONCE_ATTRIBUTE :
			attr_type = V_ASN1_OCTET_STRING;
			break;
		case SCEP_RECIPIENT_NONCE_ATTRIBUTE :
			attr_type = V_ASN1_OCTET_STRING;
			break;
		default:
			return 0;
	}

	return SCEP_add_attr_by_nid ( sk, nid, attr_type, value, len );
}

int SCEP_add_attr_by_nid(STACK_OF(X509_ATTRIBUTE) *sk, int nid, int atrtype,
		void *value, long len) {

	X509_ATTRIBUTE *attr = NULL;
	ASN1_STRING *asn1_str = NULL;
	int found = -1;
	int i;

	for (i=0; i<sk_X509_ATTRIBUTE_num(sk); i++) {
		attr=sk_X509_ATTRIBUTE_value(sk,i);
		if (OBJ_obj2nid(attr->object) == nid) {
			X509_ATTRIBUTE_free(attr);
			found = i;
			break;
		}
	}

	/* Create the attribute */
	asn1_str = ASN1_STRING_new();
	ASN1_STRING_set(asn1_str, value, len);
	attr = X509_ATTRIBUTE_create(nid, atrtype, asn1_str);

	if( !attr ) {
		ASN1_STRING_free(asn1_str);
		return 0;
	}

	/* Set or push the attribute */
	if ( found >= 0 ) {
		sk_X509_ATTRIBUTE_set(sk,found,attr);
	} else {
		sk_X509_ATTRIBUTE_push(sk,attr);
	}

	return(1);
}

