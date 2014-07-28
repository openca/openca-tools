/*
 * SCEP MESSAGE handling routines
 */

#include "scep_msg.h"

/* Allocate the SCEP_MSG empty structures */
SCEP_MSG *SCEP_MSG_new_null( void ) {

	SCEP_MSG *msg = NULL;
	PKCS7_SIGNER_INFO *si = NULL;

	/* Allocate memory */
	msg = (SCEP_MSG *) malloc ( sizeof(SCEP_MSG) );

	/* Signer Data */
	msg->sk_signer_info = NULL;
	msg->sk_others = NULL;
	msg->signer_ias = NULL;
	msg->signer_cert = NULL;
	msg->attrs = sk_X509_ATTRIBUTE_new_null();

	/* Enveloped Data */
	msg->env_data.NID_p7data = NID_pkcs7_signedAndEnveloped;
	msg->env_data.p7env = NULL;

	/* Enveloped Data Recipient */
	msg->env_data.recip_info.sk_recip_info = NULL;
	msg->env_data.recip_info.sk_recip_certs = NULL;
	msg->env_data.recip_info.ias = NULL;

	/* Enveloped Data CRL */
	msg->env_data.crl = NULL;

	/* Algorithm and signer info */
	msg->sk_signer_info = sk_PKCS7_SIGNER_INFO_new_null();

	return (msg);
err:
	if( msg ) OPENSSL_free (msg);
	return(NULL);
}

/* Allocate the SCEP_MSG structures */
SCEP_MSG *SCEP_MSG_new( int messageType, X509 *cert, EVP_PKEY *pkey,
		X509 *recip_cert, SCEP_MSG *inMsg, X509_REQ *req,
		X509 *issued_cert, SCEP_ISSUER_AND_SUBJECT *cert_info,
		PKCS7_ISSUER_AND_SERIAL *ias, X509_CRL *crl, X509 *cacert,
		EVP_CIPHER cipher ) {

	SCEP_MSG *msg = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	EVP_MD *dgst=NULL;

	unsigned char *raw_data = NULL;
	int envelope = 0;
	long raw_len = 0;

	BIO *debug_bio = NULL;
	BIO *p7ebio = NULL;
	BIO *inbio = NULL;

	char buf[256];

        if ((debug_bio=BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(debug_bio,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	//if( !cert || !pkey || !recip_cert )
	if( !cert || !pkey )
		return NULL;

	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info] Generating New SCEP-Message...\n", __FILE__, __LINE__);

	/* Allocate memory and initialize structures */
	if((msg = SCEP_MSG_new_null()) == NULL) return NULL;
	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info] Allocate memory\n", __FILE__, __LINE__);
	
	/* Signed Infos */
	dgst = (EVP_MD *) EVP_get_digestbyname("md5");
	if( (si = PKCS7_SIGNER_INFO_new()) == NULL ) goto err;
	if(!PKCS7_SIGNER_INFO_set(si, cert, pkey, dgst)) goto err;
	sk_PKCS7_SIGNER_INFO_push( msg->sk_signer_info, si );
	msg->signer_ias = si->issuer_and_serial;

	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info] signer infos set\n", __FILE__, __LINE__);

	/* If pkey, let's add to the message structure to ease
	 * message encryption (enveloped data content creation) */
	SCEP_MSG_set_pkey ( msg, pkey );
	// msg->signer_pkey = pkey;

	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info] encryption key set\n", __FILE__, __LINE__);

	/* If not explicit, we guess the certificate to be present
	 * in the passed inMsg structure, if any. Otherwise ERROR! */
	if( !recip_cert && inMsg ) recip_cert = inMsg->signer_cert;

	/* Set the messageType */
	SCEP_set_messageType ( msg, messageType );

	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info] message type set\n", __FILE__, __LINE__);
	switch( messageType ) {
		case MSG_CERTREP:
			if (debug)
		        	BIO_printf( debug_bio, "%s:%d: [Debug Info] Actions for CERTREP\n", __FILE__, __LINE__);
			msg->env_data.NID_p7data = NID_pkcs7_signed;
                        msg->env_data.p7 = PKCS7_new();
                        PKCS7_set_type( msg->env_data.p7, NID_pkcs7_signed );
                        PKCS7_content_new( msg->env_data.p7, NID_pkcs7_data );
			if( issued_cert ) {
				if (debug)
					BIO_printf( debug_bio, 
						"%s:%d: creating inner degenerated PKCS7... \n", 
						__FILE__, __LINE__);
				/* Adds issued certificate */
				PKCS7_add_certificate( msg->env_data.p7, issued_cert );
//				PKCS7_add_certificate( msg->env_data.p7, cert );
				envelope = 1;
				if (debug)
					BIO_printf( debug_bio, "%s:%d: done \n", __FILE__, __LINE__);
			} else if( crl ) {
				if (debug)
					BIO_printf( debug_bio, 
						"%s:%d: Adding CRL ... \n", 
						__FILE__, __LINE__);
				/* Adds crl */
				PKCS7_add_crl( msg->env_data.p7, crl );
				envelope = 1;
				if (debug)
				        BIO_printf( debug_bio, "%s:%d: done \n", __FILE__, __LINE__);
				
			} 
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
			break;
		case MSG_PKCSREQ:
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info] Actions for PKCSREQ\n", __FILE__, __LINE__);
			/* The inner pkcs7 structure is signed
			 * and enveloped and the data is to be
			 * the X509_REQ passed */
			msg->env_data.NID_p7data = 
			 	NID_pkcs7_signedAndEnveloped;

			if( req ) { 
				msg->env_data.content.req = req;

				/* Ask for the data p7 to be generated and
				 * encrypted */
				envelope = 1;
			}
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
			break;
		case MSG_GETCRL:
			if (debug)
			{
				BIO_printf( debug_bio, "%s:%d: [Debug Info] Actions for GETCRL\n", __FILE__, __LINE__);
				BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
			}
			break;
		case MSG_GETCERT:
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info] Actions for GETCERT\n", __FILE__, __LINE__);
			msg->env_data.NID_p7data = 
				NID_pkcs7_signedAndEnveloped;
			/* If it is a query for a general certificate
			 * the CAcert should be included in the enveloped
			 * data*/
			/* Otherwise, if it is a request for its own
			 * certificate, the self-signed certificate should
			 * be included */
			// if( cacert )
			// 	msg->env_data.cacert = cacert;

			/* Issuer and Serial should be present ! */
			if( !ias ) goto err;
			msg->env_data.content.ias = ias;
			envelope = 1;
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
			break;
		case MSG_GETCERTINITIAL:
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info] Actions for GETCERTINITIAL\n", __FILE__, __LINE__);
			msg->env_data.NID_p7data = NID_pkcs7_signed;
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
			break;
		case MSG_V2REQUEST: /* Not currently handled */
			if (debug) {
				BIO_printf( debug_bio, "%s:%d: [Debug Info] Actions for V2REQUEST\n", __FILE__, __LINE__);
				BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
			}
		default:
			goto err;
	}
	
	if (debug)
		BIO_printf( debug_bio, "%s:%d: Debug ... \n", __FILE__, __LINE__);

	/* If different from NULL, we have to encode something */
	if( envelope == 1 ) {
		if (debug)
			BIO_printf( debug_bio, "%s:%d: [Debug Info] encode\n", __FILE__, __LINE__);
		/* Encrypt the message data */
		if( !SCEP_MSG_encrypt( msg, recip_cert, cipher )) goto err;
		if (debug)
			BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
	}

	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info] add sign-cert to structure\n", __FILE__, __LINE__);
	/* Signer certificate */
	msg->signer_cert = cert;
	if (debug)
		PEM_write_bio_SCEP_MSG( debug_bio, msg, pkey );

	if (debug)
		BIO_printf( debug_bio, "%s:%d: [Debug Info] add attributes\n", __FILE__, __LINE__);
	/* Set message attributes, if any */
	if ( inMsg ) {
		char *tmp = NULL;
		int len = 0;
		if (debug)
			BIO_printf( debug_bio, "%s:%d: [Debug Info] take data from request\n", __FILE__, __LINE__);

		switch ( msg->messageType ) {
		   default:
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info]   set transId\n", __FILE__, __LINE__);
			/* The transId is ever required */
			tmp = SCEP_get_string_attr_by_name( inMsg->attrs, "transId");
			if( tmp ) {
				SCEP_set_transId( msg, tmp, strlen(tmp));
				OPENSSL_free( tmp );
				if (debug)
					BIO_printf( debug_bio, "%s:%d: [Debug Info]    done\n", __FILE__, __LINE__);
			}

			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info]   set recipient nonce (sendernonce from req)\n", __FILE__, __LINE__);
			/* Copy the sendernonce to the recipient nonce and
			 * generate a new sendernonce for the generated msg */
			tmp = SCEP_get_octect_attr_by_name( inMsg->attrs, 
					"senderNonce", &len);
			if( tmp ) {
				if (debug)
					BIO_printf( debug_bio, "%s:%d: [Debug Info]    %d\n", __FILE__, __LINE__, tmp);
				SCEP_set_recipientNonce( msg, tmp, len );
				OPENSSL_free( tmp );
			}
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info]   set sender nonce\n", __FILE__, __LINE__);
			SCEP_set_senderNonce_new(msg);
			if (debug)
				BIO_printf( debug_bio, "%s:%d: [Debug Info]    done\n", __FILE__, __LINE__);
		}
		if (debug)
			BIO_printf( debug_bio, "%s:%d: [Debug Info]   set pki_status\n", __FILE__, __LINE__);
		SCEP_set_pkiStatus ( msg, PKI_PENDING );
		if (debug) {
			BIO_printf( debug_bio, "%s:%d: [Debug Info]    done\n", __FILE__, __LINE__);
			BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
		}
	} else {
		if (debug)
			BIO_printf( debug_bio, "%s:%d: [Debug Info] generate new data\n", __FILE__, __LINE__);
		SCEP_set_senderNonce_new ( msg );
		SCEP_set_recipientNonce_new ( msg );
		SCEP_set_transId_new ( msg );
		if (debug)
			BIO_printf( debug_bio, "%s:%d: [Debug Info] done\n", __FILE__, __LINE__);
	}

	if (debug)
		PEM_write_bio_SCEP_MSG( debug_bio, msg, pkey );
	return (msg);
err:
	ERR_print_errors_fp(stderr);
	return(NULL);
}

int SCEP_MSG_set_ias ( SCEP_MSG *msg, PKCS7_ISSUER_AND_SERIAL *ias ) {
	int ret = 0;

	return ret;
}

int SCEP_MSG_set_pkey( SCEP_MSG *msg, EVP_PKEY *pkey ) {

	// FIXME: this is a complete misunderstanding of EVP_PKEY_copy_parameters
	// FIXME: the function only copies parameters and not a complete key !!!
//	EVP_PKEY *my_key = NULL;
//
//	if( !msg || !pkey ) return 0;
//
//	/* Free pkey if present */
//	//if( msg->env_data.pkey )
//		//EVP_PKEY_free( msg->env_data.pkey );
//	msg->env_data.pkey = NULL;
//
//	/* Create a new PKEY and copy the passed pkey */
//	my_key = EVP_PKEY_new();
//	if( !my_key ) return 0;
//
//	EVP_PKEY_copy_parameters(pkey, my_key);
//
//	/* Link the new key to the msg env_data structure */
//	msg->env_data.pkey = my_key;

	msg->env_data.pkey = pkey;

	return 1;
}

PKCS7_ISSUER_AND_SERIAL *X509_get_ISSUER_AND_SERIAL( X509 *cert ) {

	PKCS7_ISSUER_AND_SERIAL *ias = NULL;

	if(!cert) return NULL;

	if((ias = PKCS7_ISSUER_AND_SERIAL_new()) == NULL )
		return NULL;

	ias->issuer = X509_NAME_dup( X509_get_issuer_name(cert));
	ias->serial = ASN1_INTEGER_dup( X509_get_serialNumber(cert) );

	return ias;
}

/* Free the SCEP_MSG structures */
int SCEP_MSG_free( SCEP_MSG *msg ) {
	if( msg != NULL ) {
		free( msg );
	}
}

int SCEP_MSG_encrypt( SCEP_MSG *msg, X509 *recip_cert, EVP_CIPHER cipher ) {

	BIO *inbio = NULL;
	int ret = 0;
	int len = 0;

	BIO *debug_bio = NULL;

        if ((debug_bio=BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(debug_bio,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	// printf("%s:%d Debug... *** ENCRYPT ***\n", __FILE__, __LINE__ );

	/* Create the stack of the recipient(s) certificate(s) */
	if( recip_cert ) {
		STACK_OF(X509) *sk = NULL;

		if((sk = sk_X509_new(NULL)) == NULL) goto err;

		sk_X509_push( sk, recip_cert );
		msg->env_data.recip_info.sk_recip_certs = sk;
	} else {
		return 0;
	}
	
	inbio = BIO_new ( BIO_s_mem());
	/* Any message type has different data to be encrypted
	 * and checks to be done */
	switch ( msg->messageType ) {
		case MSG_PKCSREQ:

			/* There must be a request added to the msg */
			if(! msg->env_data.content.req ) goto err;

			/* Write the request to the inbio */
			if( i2d_X509_REQ_bio( inbio, msg->env_data.content.req ) <= 0) 
				goto err;
			break;
		case MSG_GETCRL:
		case MSG_GETCERT:
			if( !msg->env_data.content.ias ) goto err;
			len = i2d_PKCS7_ias_bio( inbio, msg->env_data.content.ias);
		
			if( len <= 0 ) goto err;
			break;
		case MSG_CERTREP:
		//	printf("%s:%d: Debug ... Case: MSG_CERTREP\n",
		//			__FILE__, __LINE__ );
/*			if ( msg->env_data.content.issued_cert ) {
				len = i2d_X509_bio ( inbio,
						msg->env_data.content.issued_cert );
			}
*/			
			if ( msg->env_data.p7 ) 
				len = i2d_PKCS7_bio( inbio, msg->env_data.p7 );
			break;
		default:
			printf("%s:%d Unsupported MessageType %d (%s)\n",
				__FILE__, __LINE__, msg->messageType, 
				SCEP_type2str(msg->messageType) );
	}

	BIO_flush( inbio );
	BIO_set_flags( inbio, BIO_FLAGS_MEM_RDONLY );

	/* Check for the recipients certs presence */
	if( !msg->env_data.recip_info.sk_recip_certs ) goto err;

	/* If already present an encoded pkcs7, let's free */
	if( msg->env_data.p7env ) 
		PKCS7_free( msg->env_data.p7env );

	/* Encrypt Data */
	msg->env_data.p7env = PKCS7_encrypt( 
		msg->env_data.recip_info.sk_recip_certs,
		inbio, &cipher, PKCS7_BINARY );

	ERR_clear_error();

	/* If an error occourred pkcs7 is empty */
	if( msg->env_data.p7env == NULL ) goto err;

	ret = 1;

err:
	if (inbio) BIO_free( inbio );
	return ret;
}

unsigned char *SCEP_MSG_decrypt( SCEP_MSG *msg, EVP_PKEY *ppkey, 
		X509 *cert, long *len ) {

	char *ret = NULL;
	char *data = NULL;

	BIO *bio = NULL;
	BIO *bio_err = NULL;
	BIO *bio_dup = NULL;

	X509 *foo_cert = NULL;
	EVP_PKEY *pkey = NULL;

	SCEP_RECIP_INFO *rinfo;

        if ((bio_err=BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	/* Get the recipient information to build the fake
	 * certificate needed into the PKCS7_decrypt function */
	rinfo = &(msg->env_data.recip_info);

	/* We need a private key */
	if( ppkey )
		pkey = ppkey;
	else
		pkey = msg->signer_pkey;

	if( !pkey ) return (NULL);

	if( cert ) {
		foo_cert = cert;
	} else {
		if( (foo_cert = X509_new()) == NULL ) {
			BIO_printf(bio_err, "%s:%d: foo_cert not alloc\n", __FILE__,
				__LINE__);

			goto err;
		};

		X509_set_issuer_name(foo_cert,rinfo->ias->issuer);
		X509_set_subject_name(foo_cert,rinfo->ias->issuer);
		X509_set_serialNumber(foo_cert,rinfo->ias->serial);
		X509_set_pubkey(foo_cert, pkey);
	}

	bio = BIO_new(BIO_s_mem());
	if (PKCS7_decrypt( msg->env_data.p7env, pkey, foo_cert, bio, 0) == 0) {
		// printf("%s:%d: decryption failed\n", __FILE__,
		// 	__LINE__);
		goto err;
	}
	BIO_flush(bio);
	if( len ) *len = BIO_get_mem_data(bio, &data);

	switch ( msg->messageType ) {
	   case MSG_CERTREP:
		if( msg->env_data.crl = d2i_X509_CRL_bio(bio,NULL) ) {
			/* There is a CRL */
			ret = (char *) msg->env_data.crl;
		}
		// p7 = d2i_PKCS7_bio(bio, NULL);
		break;
	   case MSG_PKCSREQ:
		msg->env_data.content.req = d2i_X509_REQ_bio(bio, NULL);
		ret = (char *) msg->env_data.content.req;
		break;
	   case MSG_GETCERTINITIAL:
		// req->rd.is = d2i_issuer_and_subject_bio(bio, NULL);
		break;
	   case MSG_GETCERT:
	   case MSG_GETCRL:
		msg->env_data.content.ias = d2i_PKCS7_ias_bio(NULL, bio);
		ret = (char *) msg->env_data.content.ias;
		break;
	case MSG_V2PROXY: // unsupported
	case MSG_V2REQUEST: // unsupported
	default:
		// BIO_printf(bio_err, "%s:%d: unknown message type: %s\n",
		// 	__FILE__, __LINE__, msg->messageType);
		break;
	}

err:
	if( foo_cert && !cert ) X509_free( foo_cert );
	if( bio ) BIO_free(bio);

	ERR_clear_error();

	return ret;
}
char *SCEP_MSG_transid ( SCEP_MSG *msg ) {
	       char *tmp = NULL; 
               tmp = SCEP_get_string_attr_by_name( msg->attrs, "transId" );
	       return tmp;
}

char *SCEP_MSG_sender_nonce2hex ( SCEP_MSG *msg ) {
	return SCEP_MSG_nonce2hex ( msg, "senderNonce" );
}

char *SCEP_MSG_recipient_nonce2hex ( SCEP_MSG *msg ) {
	return SCEP_MSG_nonce2hex ( msg, "recipientNonce" );
}

char *SCEP_MSG_nonce2hex ( SCEP_MSG *msg, char *nonceAttr ) {

	unsigned char *data = NULL;
	unsigned char *ret = NULL;

	int len, i, j;

	data = SCEP_get_octect_attr_by_name( msg->attrs, nonceAttr, &len);
	if( data ) {
		char *tmp;
		char buf[3];

		if( (ret = (char *)malloc(len*3)) == NULL) goto err;
		memset( ret, '\x0', len * 3 );

		i = 0;
		while ( i < len ) {
			sprintf( buf,"%x", data[i] );
			strncat( ret, buf, 2 );

			if( i < (len -1) ) strncat( ret, ":\x0",1);
			i++;
		}
	}
	return ret;

err:
	if( data ) free (data);
	if( ret ) free (ret);

	return NULL;
}

