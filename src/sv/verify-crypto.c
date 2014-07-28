/* OpenCA SV Tool - Thanks to Eric Young for basic tool writing */
/* ============================================================ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <openca/general.h>

extern int stop_on_errors;

int do_verify (int verbose, BIO *bio_out, BIO *bio_err,
               BIO *data, BIO *signature, BIO *output,
               int chainVerify, char *certsdir, char *certsfile, int flags, int purpose, int outdata)
{
    PKCS7 *p7 = NULL;
    int err = 0;
    X509_STORE *cert_store=NULL;
    BIO *p7bio = NULL;
    int i, ret;
    PKCS7_SIGNER_INFO *si = NULL;
    char buf[1024*4];
    STACK_OF(PKCS7_SIGNER_INFO) *sk;
    X509 *x509 = NULL;
    X509_STORE_CTX *cert_ctx;
    int error;

    /* Load the PKCS7 object from a file */
    if ((p7=PEM_read_bio_PKCS7(signature,NULL,NULL,NULL)) == NULL) {
        err=1;
        goto err;
    };
    if( verbose )
        BIO_printf(bio_out,"[Info]: PKCS#7 object loaded.\n");

    /* This stuff is added for the OpenCA project by
     * Massimiliano Pala <madwolf@openca.org>
     */

    /* This stuff is being setup for certificate verification.
     * When using SSL, it could be replaced with a 
     * cert_store=SSL_CTX_get_cert_store(ssl_ctx); */
    cert_store=X509_STORE_new();
    if (cert_store == NULL) goto end;

    // X509_STORE_set_default_paths(cert_store);
    // X509_STORE_load_locations(cert_store,certsfile,certsdir);
    /* Set the verify flags */
    X509_STORE_set_flags(cert_store, 0);

    if( chainVerify ) {
        X509_STORE_load_locations(cert_store,certsfile,certsdir);
    } else {
        X509_STORE_load_locations(cert_store,NULL,NULL);
    }
    // X509_STORE_set_verify_cb_func(cert_store,verify_callback);
    X509_STORE_set_verify_cb_func(cert_store, cb);

    ERR_clear_error();

    /* We need to process the data */
    if ((PKCS7_get_detached(p7) || data)) {
        if (data == NULL) {
            BIO_printf(bio_out, "no data to verify the signature on\n");
            exit(1);
        } else {
            p7bio=PKCS7_dataInit(p7,data);
        }
    } else {
        p7bio=PKCS7_dataInit(p7,NULL);
    }

    /* We now have to 'read' from p7bio to calculate digests etc. */
    do {
        i=BIO_read(p7bio,buf,sizeof(buf));
    } while ( i > 0 );
    if (verbose)
        BIO_printf (bio_out, "[Info]: Data is ready for verification.\n", ret);

    /* We can now verify signatures */
    sk=PKCS7_get_signer_info(p7);
    if (sk == NULL) {
        BIO_printf(bio_err, "[Error]: there are no signatures on this data\n");
        exit(1);
    }

    /* now the real PKCS#7 evaluation starts */

    if( verbose )
        BIO_printf( bio_out, "[Info]: Signature Informations (PKCS#7):\n" );

    // if(!(trusted_chain = sk_X509_new_null())) goto end;

    si = sk_PKCS7_SIGNER_INFO_value(sk,0);
    x509 = PKCS7_cert_from_signer_info(p7,si);

    if(!(cert_ctx = X509_STORE_CTX_new())) {;
        ERR_print_errors(bio_err);
        goto end;
    }

    if(!X509_STORE_CTX_init(cert_ctx,cert_store,x509,NULL))
    {
        ERR_print_errors(bio_err);
        goto end;
    }

    // if(trusted_chain) 
    // 	X509_STORE_CTX_trusted_stack(cert_ctx, trusted_chain);
	 
    if(purpose >= 0) X509_STORE_CTX_set_purpose(cert_ctx, purpose);

    if( (!X509_verify_cert(cert_ctx)) && (stop_on_errors)) {
        BIO_printf(bio_err, "[Error]: The verification of the certificate failed.\n");
        err=1;
        ERR_print_errors_fp(stderr);
        goto err;
    }

    /* Ok, first we need to, for each subject entry */
    for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++) {
        //		ASN1_UTCTIME *tm;
        //		char *str1,*str2;

        si=sk_PKCS7_SIGNER_INFO_value(sk,i);
        // i=PKCS7_dataVerify(cert_store,cert_ctx,p7bio,p7,si);
        ret=PKCS7_signatureVerify(p7bio, p7, si, PKCS7_cert_from_signer_info(p7,si));

        if ( ret <= 0 ) {
            if( verbose )
            {
                BIO_printf (bio_out, "[Info]: Signature is corrupt. Errorcode %d.\n", ret);
                /* FIXME: can we remove this message without crashing OpenCA? */
                /* FIXME: several parts of OpenCA using error:12              */
                /* FIXME: we must define an errorcode format for OpenCA-SV    */
                BIO_printf( bio_out,"signature:error:%d\n", ret );
            }
            err=1;
            goto err;
        }

    }

    /*
    if( verbose ) {
        BIO_printf(bio_out,"    Signature: Ok.\n");
    };
    */
    if( verbose )
        BIO_printf( bio_out,"signature:ok:%d\n", ret );

    // the reuse of the BIO data is more then dangerous
    // so this option makes only sense with not detached data
    if( outdata && !PKCS7_get_detached(p7))
    {
        p7bio=PKCS7_dataInit(p7,NULL);

        if( verbose )
            BIO_printf( bio_out, "\n");

        BIO_printf( bio_out, "Stored PKCS7 data:\n" );
        do {
            i=BIO_read(p7bio,buf,sizeof(buf)-1);
            buf[i] = '\x0';
            BIO_printf( bio_out, "%s", buf );
        } while ( i > 0 );
        BIO_printf( bio_out, "\n");
    }
    if( output && output != bio_out && !PKCS7_get_detached(p7))
    {
        p7bio=PKCS7_dataInit(p7,NULL);
        do {
            i=BIO_read(p7bio,buf,sizeof(buf)-1);
            buf[i] = '\x0';
            BIO_printf( output, "%s", buf );
        } while ( i > 0 );
    }
err:
	X509_STORE_free(cert_store);
	if( data ) BIO_free( data );
	if( signature ) BIO_free( signature );

	if( err == 0 )
		exit(0);

        error = ERR_get_error();
        if (ERR_GET_REASON (error) == PKCS7_R_DIGEST_FAILURE)
        {
                BIO_printf (bio_err, "[Error]: Digest mismatch. Signature is wrong.\n");
	} else if (error != 0) {
                BIO_printf (bio_err, "[Error]: %s\n", ERR_error_string(error,NULL));
	}

	exit(1);
end:
	X509_STORE_free(cert_store);
	X509_STORE_CTX_cleanup(cert_ctx);
	if( data ) BIO_free( data );
	if( signature ) BIO_free( signature );

	if( err == 0 ) exit(0);

	if( verbose ) {
		ERR_print_errors_fp(stderr);
	}

	exit(1);
    return 1;
}


int do_decrypt (int verbose, BIO *bio_out, BIO *bio_err,
                BIO *data, BIO *output, X509 *x509, EVP_PKEY *pkey, int flags)
{
    PKCS7 *p7 = NULL;
    int err = 0;
    X509_STORE *cert_store=NULL;
    X509_STORE_CTX *cert_ctx;

    if( verbose )
        BIO_printf(bio_out,"Start decrypting PKCS#7 object.\n");

    /* Load the PKCS7 object from a file */
    if ((p7=PEM_read_bio_PKCS7(data,NULL,NULL,NULL)) == NULL) {
        err=1;
        goto err;
    };
    if( verbose )
        BIO_printf(bio_out,"PKCS#7 object loaded.\n");

    if( verbose )
        BIO_printf(bio_out,"Start decryption.\n");

    if(!PKCS7_decrypt(p7, pkey, x509, output, flags|PKCS7_BINARY)) {
        BIO_printf(bio_err, "Error decrypting PKCS#7 structure\n");
        goto err;
    }
    if( verbose )
        BIO_printf(bio_out, "PKCS#7 successfully decrypted.\n");

err:
	X509_STORE_free(cert_store);

	if( err == 0 )
		exit(0);

	ERR_print_errors_fp(stderr);

	exit(1);
end:
	X509_STORE_free(cert_store);
	X509_STORE_CTX_cleanup(cert_ctx);

	if( err == 0 ) exit(0);

	if( verbose ) {
		ERR_print_errors_fp(stderr);
	}

	exit(1);
    return 1;
}
