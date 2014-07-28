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
#include <openca/apps.h>
#include <openca/sv.h>
#include <openca/tools.h>

BIO *bio_err=NULL;

int main( int argc, char *argv[]) {

	int cmd=-1;
        char *infile=NULL;
        char *certfile=NULL;
        char *keyfile=NULL;
        char *key=NULL;
	int nodetach=0;
	int keyform=FORMAT_PEM;
	char *passinarg = NULL;
	char *engine = NULL;
        STACK *pre_cmds = sk_new_null();
        STACK *post_cmds = sk_new_null();
	const EVP_CIPHER *cipher = NULL;
        X509 *x509 = NULL;
        EVP_PKEY *pkey = NULL;
	int flags = 0;
	int purpose = X509_PURPOSE_SMIME_SIGN;

#ifndef OPENSSL_NO_ENGINE
        ENGINE *e;
#endif

        BIO *data   = NULL;
        BIO *org_data = NULL;
        BIO *output = NULL;
	char *datafile = NULL;
	char *outfile = NULL;

	/* char buf[1024*4]; */
	char **pp = NULL;
	/* int badops=0, outdata=0, err=0, version=0, i; */
	int badops=0, outdata=0, i;

	 /* default certificates dir */
	 /* char *certsdir="/usr/local/OpenCA/certs"; */

	 /* default certificates file */
	 /* char *certsfile="/usr/local/OpenCA/cacert.pem"; */

	char *certsdir = NULL;
	char *certsfile = NULL;

	/* stdout, stdin, stderr initialization */

	if ((bio_err=BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	bio_out=BIO_new_fp(stdout,BIO_NOCLOSE);

        /* OpenSSL toolkit init */

	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
        ERR_load_crypto_strings();
#ifndef NO_MD5
        EVP_add_digest(EVP_md5());
#endif
#ifndef NO_SHA1
        EVP_add_digest(EVP_sha1());
#endif

	if( argc <= 1 ) {
		printVersion( bio_err, INFO );
		printf("ERROR: needed command and arguments missing\n\n");
		badops=1;
		goto badops;
	}

	if( ( cmd = getCommand( argc, argv ) ) == -1 ) {
		printVersion( bio_err, INFO );
		printf("ERROR: unknown command %s\n\n", argv[1] );
		badops=1;
		goto badops;
	}

	if( cmd == OPENCA_PKCS7_VERSION ) {
		whichVersion( bio_err, INFO );
		exit(0);
	}

	if( argc >= 1 ) {
		argc--;
		argv++;

		if( argc <= 1 )
		{
			printVersion( bio_err, INFO );
			printf("ERROR: needed at least one argument!\n\n" );
	                badops=1;
        	        goto badops;
		}
	}

	while (argc > 1) {
		argc--;
		argv++;
		if (strcmp(*argv,"-verbose") == 0)
                        {
			verbose=1;
			}
		else if (strcmp(*argv,"-print_data") == 0)
                        {
			outdata=1;
			}
		else if (strcmp(*argv,"-no_chain") == 0)
                        {
			chainVerify=0;
			}
		else if (strcmp(*argv,"-data") == 0)
			{
                        if (--argc < 1) goto bad;
			datafile= *( ++argv );
			}
		else if (strcmp(*argv,"-d") == 0)
			{
			/* Present for compatibility reasons ... */
                        if (--argc < 1) goto bad;
			datafile= *( ++argv );
			}
		else if (strcmp(*argv,"-in") == 0)
			{
                        if (--argc < 1) goto bad;
			infile= *( ++argv );
			}
		else if (strcmp(*argv,"-out") == 0)
			{
                        if (--argc < 1) goto bad;
			outfile= *( ++argv );
			}
		else if (strcmp(*argv,"-cd") == 0)
			{
                        if (--argc < 1) goto bad;
                        certsdir = *(++argv);
			}
		else if (strcmp(*argv,"-cf") == 0)
			{
                        if (--argc < 1) goto bad;
                        certsfile = *( ++argv );
			}
		else if (strcmp(*argv,"-cert") == 0)
			{
                        if (--argc < 1) goto bad;
                        certfile = *( ++argv );
			}
		else if (strcmp(*argv,"-keyfile") == 0)
			{
                        if (--argc < 1) goto bad;
                        keyfile = *( ++argv );
			}
		else if (strcmp(*argv,"-keyform") == 0)
			{
			if (--argc < 1) goto bad;
			keyform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-engine") == 0)
			{
			if (--argc < 1) goto bad;
			engine= *(++argv);
			}
                else if (strcmp(*argv,"-pre") == 0)
                        {
                        argc--; argv++;
                        sk_push(pre_cmds,*argv);
                        }
                else if (strcmp(*argv,"-post") == 0)
                        {
                        argc--; argv++;
                        sk_push(post_cmds,*argv);
                        }
		else if (strcmp(*argv,"-passin") == 0)
			{
                        if (--argc < 1) goto bad;
                        passinarg = *( ++argv );
			}
		else if (strcmp(*argv,"-key") == 0)
			{
                        if (--argc < 1) goto bad;
                        key = *( ++argv );
			}
		else if (strcmp(*argv,"-nd") == 0)
                        {
			nodetach=1;
			}
#ifndef OPENSSL_NO_DES
		else if (!strcmp (*argv, "-des3")) 
				cipher = EVP_des_ede3_cbc();
		else if (!strcmp (*argv, "-des")) 
				cipher = EVP_des_cbc();
#endif
#ifndef OPENSSL_NO_RC2
		else if (!strcmp (*argv, "-rc2-40")) 
				cipher = EVP_rc2_40_cbc();
		else if (!strcmp (*argv, "-rc2-128")) 
				cipher = EVP_rc2_cbc();
		else if (!strcmp (*argv, "-rc2-64")) 
				cipher = EVP_rc2_64_cbc();
#endif
#ifndef OPENSSL_NO_AES
		else if (!strcmp(*argv,"-aes128"))
				cipher = EVP_aes_128_cbc();
		else if (!strcmp(*argv,"-aes192"))
				cipher = EVP_aes_192_cbc();
		else if (!strcmp(*argv,"-aes256"))
				cipher = EVP_aes_256_cbc();
#endif
		else if (!strcmp (*argv, "-text")) 
				flags |= PKCS7_TEXT;
		else if (!strcmp (*argv, "-nointern")) 
				flags |= PKCS7_NOINTERN;
		else if (!strcmp (*argv, "-noverify")) 
				flags |= PKCS7_NOVERIFY;
		else if (!strcmp (*argv, "-nochain")) 
				flags |= PKCS7_NOCHAIN;
		else if (!strcmp (*argv, "-nocerts")) 
				flags |= PKCS7_NOCERTS;
		else if (!strcmp (*argv, "-noattr")) 
				flags |= PKCS7_NOATTR;
		else if (!strcmp (*argv, "-nodetach")) 
				flags &= ~PKCS7_DETACHED;
		else if (!strcmp (*argv, "-nosmimecap"))
				flags |= PKCS7_NOSMIMECAP;
		else if (!strcmp (*argv, "-binary"))
				flags |= PKCS7_BINARY;
		else if (!strcmp (*argv, "-nosigs"))
				flags |= PKCS7_NOSIGS;
		else if (!strcmp(*argv,"-purpose"))
			{
			X509_PURPOSE *xptmp;
			if (argc-- < 1) goto badops;
			i = X509_PURPOSE_get_by_sname(*(++argv));
			if(i < 0)
				{
				BIO_printf(bio_err, "unrecognized purpose\n");
				goto badops;
				}
			xptmp = X509_PURPOSE_get0(i);
			purpose = X509_PURPOSE_get_id(xptmp);
			}
		else if (strcmp(*argv,"-h") == 0)
			{
			   badops=1;
			   break;
			}
		else
			{
			if( argc == 2 ) {
				datafile = *argv;
				argc--;
				continue;
			}
bad:
			printVersion( bio_err, INFO );
                        BIO_printf(bio_err,"ERROR: unknown option %s\n\n",*argv);
                        badops=1;
                        break;
			}
	}

badops:
        if (badops) {
                for (pp=usage; (*pp != NULL); pp++)
                        BIO_printf(bio_err,*pp);
                        exit(1);
        }

        /* input and output intialization */
        data = BIO_new(BIO_s_file());
        if( infile == NULL ) {
                BIO_set_fp(data,stdin,BIO_NOCLOSE);
        } else {
                if (!BIO_read_filename(data,infile))
                {
                        BIO_printf(bio_err,"[Error]: Cannot open file %s for reading.\n", infile);
                        exit (1);
                }
                if( verbose )
                        BIO_printf(bio_out,"[Info]: Input file intialized.\n");
        }
	if (outfile != NULL)
	{
		output=BIO_new(BIO_s_file());
        	if (BIO_write_filename(output,outfile) <= 0)
                {
			BIO_printf(bio_err,"[Error]: Error during output file %s initialization\n", outfile);
                	perror(outfile);
                        exit (0);
                }
                if (verbose)
                    BIO_printf(bio_out,"[Info]: Output file intialized.\n");
        } else {
        	output = bio_out;
	}
	org_data=BIO_new(BIO_s_file());
	if (datafile == NULL) {
		BIO_set_fp(org_data,stdin,BIO_NOCLOSE);
	} else {
		if (!BIO_read_filename(org_data, datafile)) {
			BIO_printf( bio_err, "[Error]: Cannot access %s\n\n",
							datafile );
			exit(1);
		}
	}
	if( verbose )
        	BIO_printf(bio_out, "[Info]: Signaturefile initialized.\n");

#ifndef OPENSSL_NO_ENGINE
	/* engine loading */
        if (engine != NULL)
        {
            e = load_engine (engine, pre_cmds, post_cmds, bio_err);
            if (e == NULL)
            {
                BIO_printf(bio_err, "[Error]: Failed to load engine\n");
                exit (1);
            }
        }
#endif

        /* load certificate */
	if( verbose )
        	BIO_printf(bio_out,"[Info]: Reading Certificate file.\n");
	if (certfile || cmd != OPENCA_PKCS7_VERIFY)
	{
#ifndef OPENSSL_NO_ENGINE
		if ((x509= (X509 *) load_cert(bio_err, certfile, FORMAT_PEM, NULL, e, "certificate")) == NULL)
#else
		if ((x509= (X509 *) load_cert(bio_err, certfile, FORMAT_PEM, NULL, NULL, "certificate")) == NULL)
#endif
			exit (1);
	}

        /* load and check private key */
	if (OPENCA_PKCS7_SIGN == cmd || OPENCA_PKCS7_DECRYPT == cmd)
        {
	        if( verbose )
        	        BIO_printf(bio_out,"[Info]: Starting private key handling.\n");

		/* Passin support */
		if(!key && !app_passwd(bio_err, passinarg, NULL, &key, NULL)) {
			BIO_printf(bio_err, "[Error]: Error getting passwords\n");
			exit (1);
		}

	        if( verbose )
        	        BIO_printf(bio_out,"[Info]: Try to load private key.\n");
#ifndef OPENSSL_NO_ENGINE
		pkey = (EVP_PKEY *) load_key(bio_err, keyfile, keyform, 0, key,
			e, "private key");
#else
		pkey = (EVP_PKEY *) load_key(bio_err, keyfile, keyform, 0, key,
			NULL, "private key");
#endif
		if (key) memset(key,0,strlen(key));
		if (pkey == NULL)
			{
			/* load_key() has already printed an appropriate message */
			exit (1);
			}
	        if( verbose )
        	        BIO_printf(bio_out,"[Info]: Private key loaded.\n");

                /* Verify the key */
                if ( !X509_check_private_key(x509,pkey) )
	        {
	            BIO_printf(bio_err,"[Error]: certificate and private key do not match\n");
                    exit (18);
	        }

	        if( verbose )
        	        BIO_printf(bio_out,"[Info]: Private key handling complete.\n");
	}

        /* command execution */

	if( cmd == OPENCA_PKCS7_SIGN )
        {
            do_sign (verbose, bio_out, bio_err,
                     data, output, x509, pkey, cipher, flags, nodetach);
        } else if ( cmd == OPENCA_PKCS7_VERIFY )
        {
            if (datafile == NULL)
            {
                do_verify (verbose, bio_out, bio_err,
                           NULL, data, output, chainVerify, certsdir, certsfile,
                           flags, purpose, outdata);
            } else {
                do_verify (verbose, bio_out, bio_err,
                           org_data, data, output, chainVerify, certsdir, certsfile,
                           flags, purpose, outdata);
            }
        } else if ( cmd == OPENCA_PKCS7_ENCRYPT )
        {
            do_encrypt (verbose, bio_out, bio_err,
                        data, output, x509, cipher, flags);
        } else if ( cmd == OPENCA_PKCS7_DECRYPT )
        {
            do_decrypt (verbose, bio_out, bio_err,
                        data, output, x509, pkey, flags);
	}

	exit(0);
}

