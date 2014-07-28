/*
 * SCEP - BIO handling routines
 */

#include "scep_bio.h"

PKCS7_ISSUER_AND_SERIAL	*d2i_PKCS7_ias_bio( PKCS7_ISSUER_AND_SERIAL **ias,
	       	BIO *bio) {
	unsigned char buffer[1024];
	unsigned char *tmp = NULL;

	PKCS7_ISSUER_AND_SERIAL	*ret = NULL;
	int len = 0;

	// printf( "%s:%d: Debug! *** d2i_PKCS7_ias_bio ***\n", 
	// 		__FILE__, __LINE__ );

	len = BIO_read(bio, buffer, sizeof(buffer));

	if( len <= 0) return NULL;

	tmp = buffer;
	ret = d2i_PKCS7_ISSUER_AND_SERIAL(ias, &tmp, len);

	/* If an error is present, ret is NULL */
	return ret;
}

int i2d_PKCS7_ias_bio(BIO *bio, PKCS7_ISSUER_AND_SERIAL *ias) {

	unsigned char *data = NULL;
	unsigned char *tmp = NULL;
	int size = 0;

	if( !bio || !ias ) return 0;

	if( (size = i2d_PKCS7_ISSUER_AND_SERIAL(ias, NULL)) <= 0 )
		return 0;

	tmp = data = (unsigned char *) OPENSSL_malloc (size);

	if( !data ) return 0;

	/* get a DER block into memory */
	if ( i2d_PKCS7_ISSUER_AND_SERIAL(ias, &tmp) <= 0) {
		OPENSSL_free( data );
		return 0;
	}

	/* Write data to BIO */
	BIO_write(bio, data, size);
	BIO_flush(bio);

	return size;
}

/* Load a Base64 encoded message into SCEP_MSG structure */
SCEP_MSG *PEM_read_bio_SCEP_MSG( BIO *bio ) {

	BIO *pem, *der;

	if( bio == NULL) return (NULL);

	pem = BIO_new( BIO_f_base64() );
	der = BIO_push( pem, bio );

	return d2i_SCEP_MSG_bio( der );
}

/* Load a DER formatted file into internal SCEP_MSG structure */
SCEP_MSG *d2i_SCEP_MSG_bio (BIO *inbio) {

	BIO *outbio = NULL;
	BIO *p7bio = NULL;
	PKCS7 *p7 = NULL;
	// BIO *bio_err = NULL;

	SCEP_MSG *msg = NULL;

	int bytes, length, fd, used;
	int nMessageType = -1, nPkiStatus = -1;

	PKCS7_SIGNER_INFO *si = NULL;
	PKCS7_RECIP_INFO *ri = NULL;

	STACK_OF(X509_ATTRIBUTE) *sig_attribs = NULL;
	PKCS7 *p7env = NULL;

	SCEP_RECIP_INFO *rinfo = NULL;

	char buffer[1024];
	char *data = NULL;
	char *tmp_string = NULL;

	int debug = 0;
	int i;

        // if ((bio_err=BIO_new(BIO_s_file())) != NULL)
	// 	BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	msg = (SCEP_MSG *) OPENSSL_malloc ( sizeof(SCEP_MSG));
	if( msg == NULL ) return (NULL);

	/* decode the data */
	p7 = d2i_PKCS7_bio(inbio, NULL);
	if (p7 == NULL) goto err;

	/* make sure this is a signed data PKCS#7			*/
	// if (!PKCS7_type_is_signed(p7)) {
	// 	BIO_printf(bio_err, "%s:%d: supplied PKCS#7 is not signed "
	// 		"data\n", __FILE__, __LINE__);
	// 	goto err;
	// }

	/* create BIOs to read signed content data from			*/
	p7bio = PKCS7_dataInit(p7, NULL);
	if (p7bio == NULL) goto err;

	/* Use an outbio and fill it with data from the p7 */
	outbio = BIO_new(BIO_s_mem());
	used = 0;
	for (;;) {
		bytes = BIO_read(p7bio, buffer, sizeof(buffer));
		used += bytes;
		if (bytes <= 0) break;
		BIO_write(outbio, buffer, bytes);
	}
	BIO_flush(outbio);

	/* there should be exactly one signer info			*/
	msg->sk_signer_info = PKCS7_get_signer_info(p7);
	if (msg->sk_signer_info == NULL) {
		goto err;
	}
	if (sk_PKCS7_SIGNER_INFO_num(msg->sk_signer_info) != 1) {
		goto err;
	}

	si = sk_PKCS7_SIGNER_INFO_value(msg->sk_signer_info, 0);
	msg->signer_ias = si->issuer_and_serial;
	msg->signer_cert = PKCS7_cert_from_signer_info( p7, si );

	/* If msg->signer_cert == NULL there is no signer certificate,
	 * otherwise the certificate is included into the PKCS#7 envelope
	 * this certificate may be self signed, but for the PKCS7_
	 * signatureVerify method, this does not matter */

	/* verify the PKCS#7 using the store just constructed		*/
	if (PKCS7_signatureVerify(p7bio, p7, si, 
				msg->signer_cert) <= 0) {
		// BIO_printf(bio_err, "%s:%d: verification failed\n", __FILE__,
		// 	__LINE__);
		goto err;
	}

	/* extract the signed attributes				*/
	msg->attrs = PKCS7_get_signed_attributes(si);
	if ((msg->attrs == NULL) || (sk_X509_ATTRIBUTE_num(msg->attrs) == 0)){
		goto err;
	}

	tmp_string = (char *) 
		SCEP_get_string_attr_by_name(msg->attrs, "messageType");

	if( tmp_string != NULL ) {
		msg->messageType = atoi( tmp_string );
		free( tmp_string );
		tmp_string = NULL;
	} else {
		msg->messageType = -1;
	}

	/* unpack the internal PKCS#7					*/
	p7env = d2i_PKCS7_bio(outbio, NULL);
	if (p7env == NULL) return msg;

	i=OBJ_obj2nid(p7env->type);
	msg->env_data.NID_p7data = i;
	msg->env_data.p7env = p7env;

	/* use a commodity variable */
	rinfo = &(msg->env_data.recip_info);

	switch(i) {
		case NID_pkcs7_signed:
			break;
		case NID_pkcs7_signedAndEnveloped:
			rinfo->sk_recip_info =
				p7env->d.signed_and_enveloped->recipientinfo;
			break;
		case  NID_pkcs7_enveloped:
			rinfo->sk_recip_info =
				p7env->d.enveloped->recipientinfo;
			break;
		default:
			// BIO_printf( bio_err, "%s:%d: unknown PKCS7 structure\n",
			// 		__FILE__, __LINE__);
			break;
	}

	/* Lets do the pub key stuff :-) */
	// FIXME: usaly only 1, but pix has 4 in structure - to be clarified...
	// so currently set to 4 to get it working with cisco-pix
	if( sk_PKCS7_RECIP_INFO_num(rinfo->sk_recip_info) > 4 ) {
		goto err;
	}

	/* Let's get the recipient info at stack num 0, the first and
	 * hopefully, the only one */
	ri = sk_PKCS7_RECIP_INFO_value( rinfo->sk_recip_info, 0);

	/* Usually certificates are not present, but in case the standard
	 * will be updated... */
	// if (debug && ri->cert == NULL) {
	// 	BIO_printf( bio_err, 
	// 		"%s:%d: Recipient info cert %d missing\n",
	// 		__FILE__, __LINE__, 0);
	// }

	rinfo->ias = ri->issuer_and_serial;
	/*
	if( rinfo->ias != NULL ) {
		BIO_printf(bio_err, "%s:%d: Recip cert issued by ",
			__FILE__, __LINE__);
                X509_NAME_print_ex (bio_err, rinfo->ias->issuer,  
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
		BIO_printf(bio_err, "\n%s:%d: Recip cert serial: %s\n",
			__FILE__, __LINE__,
			BN_bn2hex(ASN1_INTEGER_to_BN(rinfo->ias->serial,
			NULL)));
	};
	*/

	if( ri->cert ) {
		/* Usually this does not happen to be included in
		 * the pkcs7env data, but in case we just get it */
		sk_X509_push( rinfo->sk_recip_certs, ri->cert );
        /*
		if ( debug ) {
                        BIO_printf(bio_err, "%s:%d: Recipient cert for ",
                              __FILE__, __LINE__);
                        X509_NAME_print_ex (bio_err, X509_get_subject_name(ri->cert),
                                0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));	
                        BIO_printf(bio_err, "\n");
		}
        */
	}

	/* perform some consistency checks				*/

	/* UniCert 3.1.2 seems to out the message type, so fudge 	*/
	/* the value of 3 (CertRep) if it is missing (problem pointed	*/
	/* out by Peter Onion						*/
	/*
	if (NULL == req->messageType) {
		BIO_printf(bio_err, "%s:%d: no message type (setting to 3)\n",
			__FILE__, __LINE__);
		req->messageType = "3";	// XXX should we strdup here?
	}
	*/

	/* UniCert doesn't seem to bother to put in a senderNonce,	*/
	/* so don't get upset if it is missing.				*/
	/*
	if (NULL == scep->senderNonce) {
		BIO_printf(bio_err, "%s:%d: senderNonce missing\n",
			__FILE__, __LINE__);
	}

	*/

	/* perform some type/status dependent checks			*/
	/*
	if ((used == 0) && (nMessageType != 3)) {
		BIO_printf(bio_err, "%s:%d: only CertRep message may be "
			"empty\n", __FILE__, __LINE__);
		goto err;
	}
	if ((used == 0) && (nMessageType == 3) && (nPkiStatus == 0)) {
		BIO_printf(bio_err, "%s:%d: CertRep may only be empty for "
			"failure or pending\n", __FILE__, __LINE__);
		goto err;
	}
	*/

	/* no content is only allowed if the message is a CertRep with	*/
	/* a pkiStatus of failure or pending				*/
	/*
	if (used == 0) {
		BIO_printf(bio_err, "%s:%d: empty PKCSReq, must be failure or "
			"pending\n", __FILE__, __LINE__);
		goto signedonly;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: working on inner pkcs#7\n",
			__FILE__, __LINE__);

	*/

	BIO_free(outbio);
signedonly:

	/* we were successfull in extracting the telescoping PKCS#7's	*/
	return(msg);
err:
	// if( debug ) ERR_print_errors(bio_err);
	return(NULL);
}

int SCEP_MSG_print( BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey, X509 *cert ) {

	char buffer[1024];
	unsigned char *data;

	BIO_printf( bio, "SCEP Message:\n" );

	BIO_printf( bio, "    Message Type: %s (%d)\n", 
			SCEP_type2str(msg->messageType), msg->messageType );

	BIO_printf( bio, "    Signed Data:\n" );
	BIO_printf( bio, "        Signer Info:\n" );
	if (msg->signer_cert == NULL) {
		BIO_printf(bio, "            Serial Number: %s\n",
				BN_bn2hex(ASN1_INTEGER_to_BN(msg->signer_ias->serial, NULL)));
		BIO_printf(bio, "            Issuer: ");
                X509_NAME_print_ex (bio, msg->signer_ias->issuer,  
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
		BIO_printf(bio, "\n");
	} else {
		X509 *sigcert;

		sigcert = msg->signer_cert;

		if( X509_NAME_cmp( X509_get_subject_name(sigcert),
				X509_get_issuer_name(sigcert) ) ) {
			BIO_printf(bio, "            Serial Number: %s\n",
				BN_bn2hex(ASN1_INTEGER_to_BN(
					msg->signer_cert->cert_info->serialNumber, NULL)));
		} else {
			/* Silly Serial Number */
			BIO_printf(bio, "            Serial Number: %s\n", "0x0 (fake)" );
		}

		BIO_printf(bio, "                Subject: ");
                X509_NAME_print_ex (bio, X509_get_subject_name(msg->signer_cert),  
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
		BIO_printf(bio, "\n");

		BIO_printf(bio, "                Issuer: ");
                X509_NAME_print_ex (bio, X509_get_issuer_name(msg->signer_cert),  
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
		BIO_printf(bio, "\n");
	}

	BIO_printf( bio, "        Signed Attributes:\n" );
	if( data = SCEP_get_string_attr_by_name( msg->attrs, "messageType")) {
		BIO_printf(bio, "            Message Type:\n"
				"                %s\n", data );
		free(data);
	}
	if( data = SCEP_get_string_attr_by_name( msg->attrs, "transId" )) {
		BIO_printf(bio, "            Transaction ID:\n"
				"                %s\n", data );
		free(data);
	}
	if( data = SCEP_get_string_attr_by_name( msg->attrs, "pkiStatus" )) {
		BIO_printf(bio, "            PKI Status:\n"
				"                %s\n", data );
		free(data);
	}
	if( data = SCEP_get_string_attr_by_name( msg->attrs, "failInfo" )) {
		BIO_printf(bio, "            Fail Info:\n"
				"                %s\n", data );
		free(data);
	}
	if( data = SCEP_get_string_attr_by_name( msg->attrs, "proxyAuthenticator" )) {
		BIO_printf(bio, "            Proxy Authenticator:\n"
				"                %s\n", data );
		free(data);
	}
	if( data = SCEP_get_octect_attr_by_name( msg->attrs, "senderNonce", NULL )) {
		BIO_printf(bio, "            Sender Nonce:\n"
				"                %s\n",
				SCEP_MSG_sender_nonce2hex( msg ));
		free(data);
	}
	if( data = SCEP_get_octect_attr_by_name( msg->attrs, "recipientNonce", NULL )) {
		BIO_printf(bio, "            Recipient Nonce:\n"
				"                %s\n",
				SCEP_MSG_recipient_nonce2hex( msg ));
		free(data);
	}

	if( msg->env_data.p7env )
		BIO_printf( bio, "    Enveloped Data:\n" );
	/*
	if( msg->env_data.algor ) {
		BIO_printf( bio, "        Encryption Algorithm: ");
		i2a_ASN1_OBJECT(bio, msg->env_data.algor->algorithm);
		BIO_printf( bio, "\n");
	}
	*/

	{
		int i = 0;
		
		STACK_OF(PKCS7_RECIP_INFO) *sk;

		i=OBJ_obj2nid(msg->env_data.p7env->type);
		switch (i) {
			case NID_pkcs7_signedAndEnveloped:
				sk=msg->env_data.p7env->d.signed_and_enveloped->recipientinfo;
				break;
			case NID_pkcs7_enveloped:
				sk=msg->env_data.p7env->d.enveloped->recipientinfo;
				break;
			default:
				break;
                }

		if ( sk ) {
			for(i=0;i<sk_PKCS7_RECIP_INFO_num(sk);i++ ) {
				PKCS7_RECIP_INFO *ri = NULL;

				ri = sk_PKCS7_RECIP_INFO_value(sk, i);

				if( ri->issuer_and_serial ) {
	
		BIO_printf( bio, "        Recipient Info [%d]:\n",i );
		BIO_printf(bio, "            Serial Number: 0x%s (%s)\n",
			BN_bn2hex(ASN1_INTEGER_to_BN(
				ri->issuer_and_serial->serial, NULL)),
			BN_bn2dec(ASN1_INTEGER_to_BN(
				ri->issuer_and_serial->serial, NULL)));
		BIO_printf(bio, "            Issuer: ");
                X509_NAME_print_ex (bio, ri->issuer_and_serial->issuer,
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
		BIO_printf(bio, "\n");
				}
			}
		}
	}

	/*
	if( msg->env_data.recip_info.ias ) {
		BIO_printf( bio, "        Recipient Info:\n" );
		BIO_printf(bio, "            Serial Number: 0x%s (%s)\n",
			BN_bn2hex(ASN1_INTEGER_to_BN(
				msg->env_data.recip_info.ias->serial, NULL)),
			BN_bn2dec(ASN1_INTEGER_to_BN(
				msg->env_data.recip_info.ias->serial, NULL)));
		BIO_printf(bio, "            Issuer: ");
                X509_NAME_print_ex (bio, msg->env_data.recip_info.ias->issuer,
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
		BIO_printf(bio, "\n");
	}
	*/

	if( pkey ) {
		unsigned char *data=NULL;
		long len = 0;

		data = (unsigned char *) SCEP_MSG_decrypt( msg, pkey,
				cert, &len);
		
		if( data ) {
			int i;
			char buf[1024];

			switch ( msg->messageType ) {
				case MSG_GETCRL:
				case MSG_GETCERT:
					/* Print the issuer 'n serial */
					BIO_printf( bio,
					    "        Issuer and Serial:\n");
 					BIO_printf( bio, "            Issuer: ");
                                        X509_NAME_print_ex (bio, msg->env_data.content.ias->issuer,
                                                      0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
					BIO_printf( bio, "\n            Serial: 0x");
					i2a_ASN1_INTEGER( bio, msg->env_data.content.ias->serial );
					BIO_printf( bio, "\n");
					break;
				default:
				   BIO_printf( bio, "        Decrypted Data:");

				   for (i=0; i<len; i++) {
					if ((i%18) == 0)
					if (BIO_write(bio, "\n            ",
						13) <= 0) return 0;
					if (BIO_printf(bio,"%02x%s",
						data[i], ((i+1) == len)?"":":") <= 0) return 0;
				   }
				   if (BIO_write(bio,"\n",1) != 1) return 0;
				   free( data );
				   break;
			}
		}
	} else {
		BIO *p7bio = NULL;
		unsigned char buffer[1024];

		long len = 0;
		int i;

		BIO_printf( bio, "        Encrypted Bytes (DER):");

		p7bio = BIO_new(BIO_s_mem());
		if ( msg->env_data.p7env ) 
			i = i2d_PKCS7_bio( p7bio, msg->env_data.p7env );
		else
			return 1;
		if( i == 0 ) {
			BIO_printf( bio, "cannot write data to mem bio\n");
			goto err;
		}

		for (;;) {
			len = BIO_read(p7bio, buffer, sizeof(buffer));
			if (len <= 0) break;
			for (i=0; i<len; i++) {
				if ((i%18) == 0)
				if (BIO_write(bio,"\n            ",13) <= 0)
					return 0;
				if (BIO_printf(bio,"%02x%s",buffer[i],
					((i+1) == len)?"":":") <= 0) return 0;
			}
			if (BIO_write(bio,"\n",1) != 1) return 0;
		}

		if (p7bio) BIO_free ( p7bio );
	}


	return 1;

err:
	return 0;
}

/* Base 64 write of PKCS#7 structure */
int B64_write_bio_PKCS7 ( BIO *bio, PKCS7 *p7 ) {
	BIO *b64 = NULL;
	int ret = 0;

	if( !p7 ) return 0;

	if(!(b64 = BIO_new(BIO_f_base64()))) {
		PKCS7err(PKCS7_F_B64_WRITE_PKCS7,ERR_R_MALLOC_FAILURE);
		return 0;
	}
	
	bio = BIO_push(b64, bio);
	ret = i2d_PKCS7_bio(bio, p7);
	BIO_flush(bio);
	bio = BIO_pop(bio);
	BIO_free(b64);
	
	return ret;
}

/* Base 64 read and write of PKCS#7 structure */
int B64_write_bio_SCEP_MSG(BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey ) {

	PKCS7 *p7 = NULL;

	if( (p7 = i2pk7_SCEP_MSG( msg, pkey )) == NULL )
		return 0;

	return B64_write_bio_PKCS7 ( bio, p7 );
}

int PEM_write_bio_SCEP_MSG(BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey) {

	PKCS7 *p7 = NULL;
	int ret = 0;

	/* Generate the signed pkcs7 message */
	if( (p7 = i2pk7_SCEP_MSG( msg, pkey )) == NULL )
		return 0;

	BIO_printf( bio, "-----BEGIN SCEP MESSAGE-----\n" );
	ret = B64_write_bio_PKCS7(bio, p7);
	BIO_printf( bio, "-----END SCEP MESSAGE-----\n" );
	PKCS7_free( p7 );

	ERR_clear_error();

	return ret;
}

int i2d_SCEP_MSG_bio( BIO *bio, SCEP_MSG *msg, EVP_PKEY *pkey ) {

	PKCS7 *p7 = NULL;
	int ret = 0;

	/* Generate the signed pkcs7 message */
	if( (p7 = i2pk7_SCEP_MSG( msg, pkey )) == NULL )
		return 0;

	ret = i2d_PKCS7_bio(bio, p7);
	PKCS7_free( p7 );

	ERR_clear_error();

	return ret;
}

