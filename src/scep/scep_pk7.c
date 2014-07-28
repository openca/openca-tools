/*
 * SCEP PKCS7 conversion routines
 */

#include "scep_pk7.h"
#include "scep_msg.h"

/* Converts a SCEP_MSG to a PKCS7 structure */
PKCS7* i2pk7_SCEP_MSG ( SCEP_MSG *msg, EVP_PKEY *pkey ) {

	BIO *bio = NULL;
	PKCS7 *p7 = NULL;
	PKCS7_SIGNER_INFO *si = NULL;

	STACK_OF(X509) *sk_others = NULL;
	X509 *x509 = NULL;

	int i = 0;
	long data_len = 0;
	unsigned char *data = NULL;

	BIO *debug_bio = NULL;

        if ((debug_bio = BIO_new( BIO_s_file() )) != NULL)
        	BIO_set_fp( debug_bio, stderr, BIO_NOCLOSE|BIO_FP_TEXT );

	if( !msg || !msg->signer_cert || !pkey )
		return NULL;
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   message complete\n", __FILE__, __LINE__);

	/* Create the new p7 structure and set to signed */
	if((p7 = PKCS7_new()) == NULL ) goto err;
	if(!PKCS7_set_type(p7, NID_pkcs7_signed)) goto err;
	if(!PKCS7_content_new(p7, NID_pkcs7_data)) goto err;
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   pkcs#7 container ready\n", __FILE__, __LINE__);

	/* Add the signer certificate */
	PKCS7_add_certificate( p7, msg->signer_cert );
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   signer certificate added\n", __FILE__, __LINE__);

	/* The p7 has to be signed, initialize the signature */
        if( (si = PKCS7_add_signature( p7, msg->signer_cert,
                        pkey, EVP_md5())) == NULL )
                goto err;
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   signature added\n", __FILE__, __LINE__);

	switch( msg->messageType ) {
		case MSG_CERTREP:
			/* Add other certificates, could be the CA cert,
			 * and or the full CAChain of certificates */
			sk_others = msg->sk_others;
			if( sk_others ) {
				for(i = 0; i<sk_X509_num(sk_others); i++) {
					x509 = sk_X509_value( sk_others, i );
					PKCS7_add_certificate( p7, x509 );
				}
			}
			/* Adds the issued certificate for the client */
/*			if( msg->env_data.content.issued_cert ) {
				PKCS7_add_certificate( p7,
					msg->env_data.content.issued_cert );
			}
*/		case MSG_GETCERT:
			/* If a request for a general certificate, then
			 * the cacert should be present, if it is a req
			 * for its own certificate, the self signed cert
			 * should be included */
			/*
			if( msg->env_data.cacert ) {
				PKCS7_add_certificate( p7,
					msg->env_data.cacert );
			} else if ( msg->env_data.content.self_signed_cert ) {
				PKCS7_add_certificate( p7,
					msg->env_data.content.self_signed_cert );
			}
			*/
		case MSG_V2REQUEST:
		case MSG_PKCSREQ:
		case MSG_GETCERTINITIAL:
		case MSG_GETCRL:
			break;
	}
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   msgtype specific operations finished\n", __FILE__, __LINE__);

	if( (bio = BIO_new( BIO_s_mem())) == NULL)
		goto err;
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   new memory bio created\n", __FILE__, __LINE__);

	/* If it exists the msg->env_data.p7env then we add to the p7
	 * data in DER */

	ERR_print_errors_fp(stderr);
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   errors flushed\n", __FILE__, __LINE__);

	if( (msg->env_data.p7env != NULL) && (i2d_PKCS7_bio( bio, msg->env_data.p7env ) > 0) ) {
		ERR_print_errors_fp(stderr);
		BIO_flush( bio );
		BIO_set_flags( bio, BIO_FLAGS_MEM_RDONLY );
		data_len = BIO_get_mem_data( bio, &data );
	}
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   output PKCS#7\n", __FILE__, __LINE__);
	ERR_print_errors_fp(stderr);
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   errors printed\n", __FILE__, __LINE__);
	
	/* Add signed attributes */
	PKCS7_set_signed_attributes( si, msg->attrs );

	PKCS7_add_signed_attribute( si, NID_pkcs9_contentType,
			V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info]   added signed attributes\n", __FILE__, __LINE__);

	 /* Add data to the p7 file */
        if( (bio = PKCS7_dataInit( p7, NULL )) == NULL )
                goto err;

        if( data_len > 0 ) 
                BIO_write( bio, data, data_len );
	ERR_print_errors_fp(stderr);
	
	/* Finalize signature */
	PKCS7_dataFinal( p7, bio );
	
	return p7;

err:
	if( bio ) BIO_free(bio);
	if( p7 ) PKCS7_free(p7);
	return (NULL);
}

