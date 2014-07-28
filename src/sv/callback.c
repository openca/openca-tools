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

/* Local Include */
#include <openca/callback.h>

int verify_depth=0;
int verify_error=X509_V_OK;
static int err_depth = -1;

extern int chainVerify;
extern int stop_on_errors;

/* should be X509 * but we can just have them as char *. */
int verify_callback (int ok, X509_STORE_CTX *ctx)
	{
	char buf[256];
	X509 *err_cert = NULL;
	int err,depth;

	err_cert=X509_STORE_CTX_get_current_cert(ctx);
	err=	X509_STORE_CTX_get_error(ctx);
	depth=	X509_STORE_CTX_get_error_depth(ctx);
	
	if( verbose ) {
	    if( (!chainVerify) || (verify_depth >= depth)) {
		BIO_printf(bio_out,"depth:%d serial:",depth);
		i2a_ASN1_INTEGER( bio_out, X509_get_serialNumber(err_cert) );
		BIO_printf(bio_out," subject:");
                X509_NAME_print_ex (bio_out, X509_get_subject_name(err_cert),
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
                BIO_printf(bio_out, "\n");
	    }
	}

        if (!ok) {
		if (verify_depth >= depth) {
			ok=1;
			verify_error=X509_V_OK;
		} else {
			ok=0;
			verify_error=X509_V_ERR_CERT_CHAIN_TOO_LONG;
		}
		X509_STORE_CTX_set_error(ctx,verify_error);
	}

	// if( (depth > 0) && (chainVerify == 0) ) {
	// 	return ok;
	// }

	if(!ok)
        switch (ctx->error) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),buf,256);
			if( verbose && chainVerify)
				BIO_printf(bio_out," (error:%s)\n",
					X509_verify_cert_error_string(err));
			if( !chainVerify) ok=1;
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			if( verbose )
				BIO_printf(bio_out," (error:%s)",
					X509_verify_cert_error_string(err));
			if( !stop_on_errors ) ok=1;
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			if( verbose )
				BIO_printf(bio_out," (error:%s)",
					X509_verify_cert_error_string(err));
			if( !stop_on_errors ) ok=1;
			break;
	}
	if( !stop_on_errors ) ERR_clear_error();

	/*
	if( !ok ) {
		BIO_printf(bio_out," (error:%s)",
				X509_verify_cert_error_string(err));
	}
	*/
	BIO_printf(bio_out,"\n");
	// if( stop_on_errors == 0 ) ok = 1;

	/*
	if ( verbose ) {
		BIO_printf(bio_err,"verify return:%d\n",ok);
		BIO_printf(bio_err,"depth return:%d\n",depth);
	}

	if( verbose ) {
		BIO_printf(bio_err,"Verify Return: %d\n", ok);
		BIO_printf( bio_out, "    Signed Attributes:\n");
	};
	*/

	return ( ok );
}

int cb(int ok, X509_STORE_CTX *ctx)
	{
	int depth;
	int echo=1;

	if( err_depth == ctx->error_depth ) echo = 0;
	if( !chainVerify && ctx->error_depth ) echo = 0;
	if( echo ) {
		BIO_printf(bio_out,"depth:%d serial:",ctx->error_depth);
		i2a_ASN1_INTEGER( bio_out, X509_get_serialNumber(ctx->current_cert) );
		BIO_puts (bio_out, " subject:");
		X509_NAME_print_ex (bio_out, X509_get_subject_name (ctx->current_cert), 
                                    0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
		BIO_puts (bio_out, "\n");
		err_depth = ctx->error_depth;
	}

	if (!ok)
		{
		if( echo && verbose )
			BIO_printf( bio_out, "        error:%d:%s\n",
				ctx->error, X509_verify_cert_error_string(ctx->error));
		/* since we are just checking the certificates, it is
		 * ok if they are self signed. But we should still warn
		 * the user.
		 * 2002-Sep-09
		 * But it is not ok to wrote "error: ..." therefore the user will not bewarned.
 		 */
		/* Continue after extension errors too */
		if( !stop_on_errors )
			{
			if (ctx->error == X509_V_ERR_CERT_HAS_EXPIRED) ok=1;
			if (ctx->error == X509_V_ERR_INVALID_CA) ok=1;
			if (ctx->error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok=1;
			if (ctx->error == X509_V_ERR_INVALID_PURPOSE) ok=1;
			if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
			if (ctx->error == X509_V_ERR_CRL_HAS_EXPIRED) ok=1;
			if (ctx->error == X509_V_ERR_CRL_NOT_YET_VALID) ok=1;
			if (ctx->error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) ok=1;
			if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
			}
		if( !chainVerify )
			{
			if (ctx->error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ) ok=1;
			if (ctx->error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ) ok=1;
			if (ctx->error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE ) ok=1;
			if (ctx->error == X509_V_ERR_CERT_UNTRUSTED ) ok=1;
			if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok=1;
			}
		}
	// if (!verbose)
	 // 	ERR_clear_error();

	return(ok);
	}

