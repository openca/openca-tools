/* 
 * OpenCA SCEP tool
 * (c) 2002/2003 by Massimiliano Pala and OpenCA Group
 * OpenCA Licensed Software
 *
 * Many thanks for support and ideas go to
 * Dr. Andreas Mueller, Beratung und Entwicklung
 *
 */

#include "scep.h"
#include "scep_msg.h"
#include "scep_sigattr.h"
#include "scep_bio.h"

#include <openca/config.h>
#include <openca/general.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <sys/times.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* General exported variables */
int debug = 0;
int verbose = 0;

static char *usage[] = {
"OpenCA Simple Certificate Enrollment Protocol Tools\n",
"(c) 2002 by Massimiliano Pala and OpenCA Group\n",
"OpenCA licensed software\n",
"\n",
"   USAGE: openca-scep [ args ]\n",
"\n",
" -new              build a new SCEP message.\n",
" -in file          input SCEP message file (default is stdin)\n",
" -out file         write SCEP message to file (default is stdout).\n",
" -inform           input data format (default is PEM).\n",
" -outform          output data format (default is PEM).\n",
" -signcert file    signer certificate for SCEP message.\n",
" -signcertform     certificate file format (default is PEM).\n",
" -reccert file     recipient encoding certificate for SCEP message.\n",
" -reccertform      certificate file format (default is PEM).\n",
" -keyfile file     decoding secret key file.\n",
" -keyform          decoding secret key file format (default is PEM).\n",
" -passin arg       Password passing method (check openssl for options).\n",
" -passwd pwd       Password protecting the private key (if any).\n",
" -CAfile file      CA's trusted certificate.\n",
" -CAform           CA's trusted certificate format (default is PEM).\n",
"\nNew Message Extensions:\n\n",
" -msgtype <arg>    new message format type (default is PKCSReq).\n",
" -print_serial     print serial (CertReq msgtype).\n",
" -status <arg>     new SCEP message status (SUCCESS|PENDING|FAILURE).\n",
" -failinfo <arg>   new SCEP message failure info ( BadAlg|... ).\n",
" -recnonce <arg>   new SCEP message Recipient NONCE val (i.e. 04:A4:...).\n",
" -sendnonce <arg>  new SCEP message Sender NONCE val (i.e. 04:06:FF:...).\n",
" -copynonce        copy NONCE from input message (generate the reply).\n",
" -des              encrypt envelope with normal des (default is 3des).\n",
"\nData Content (to be added in the envelope):\n\n",
" -reqfile file     pkcs#10 request to be included into the PKCSReq.\n",
" -reqformat file   pkcs#10 request's format.\n",
" -crlfile file     CRL to be included into the CertRep Message.\n",
" -crlformat file   CRL's format.\n",
" -issuedcert file  issued cert to be added to a SUCCESS CertRep msg.\n",
" -issuedcertform   issued cert file format (default is PEM).\n",
" -serial           serial of requested certificate (CertReq msgtype).\n",
#ifdef HAVE_ENGINE
" -e engine         use engine e, possibly a hardware device.\n",
#endif
" -text             Prints out data in human readable form.\n",
" -print_scert      print signer's certificate.\n",
" -print_req        print request data (PKCSReq messages).\n",
" -print_crl        print CRL (CertRep messages).\n",
" -print_sendnonce  print used sender NONCE.\n",
" -print_recnonce   print used recipient NONCE.\n",
" -print_transid    print used transaction ID.\n",
" -print_msgtype    print message type.\n",
" -noout            Do not output original data.\n",
" -version          Print Package Version and exits.\n",
" -debug            Output Debugging information.\n",
" -v                Talk alot while doing things\n",
NULL
};

static char *scep_exts[] = {
	MESSAGE_TYPE_OID, MESSAGE_TYPE_OID_STRING,
	PKI_STATUS_OID, PKI_STATUS_OID_STRING,
	FAIL_INFO_OID, FAIL_INFO_OID_STRING,
	SENDER_NONCE_OID, SENDER_NONCE_OID_STRING,
	RECIPIENT_NONCE_OID, RECIPIENT_NONCE_OID_STRING,
	TRANS_ID_OID, TRANS_ID_OID_STRING,
	EXTENSION_REQ_OID, EXTENSION_REQ_OID_STRING,
	 PROXY_AUTHENTICATOR_OID,  PROXY_AUTHENTICATOR_OID_STRING,
	 NULL, NULL
};

static char *prgname = "openca-scep";

/* Passwd functions, thanks to OpenSSL people for these */
static char *app_get_pass(BIO *err, char *arg, int keepbio);
static int add_objects_oids( void );
int str2fmt(char *s);
int dump_cert_text (BIO *out, X509 *x);
STACK_OF(X509) *load_certificate_stack ( char *fname, int format );
X509 *load_certificate ( char *fname, int format );

int app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2) {
	int same;
	if(!arg2 || !arg1 || strcmp(arg1, arg2))
		same = 0;
	else 
		same = 1;
	if(arg1) {
				//is this a FIXME: ???
				//can we reduce it to one repetition?
				//check if cacert or racert - is it *cert? 
				//check if cacert or racert - is it *cert? 
				//check if cacert or racert - is it *cert? 
				//check if cacert or racert - is it *cert? 
				//check if cacert or racert - is it *cert? 
				//check if cacert or racert - is it *cert? 
		*pass1 = app_get_pass(err, arg1, same);
		if(!*pass1) return 0;
	} else if(pass1) *pass1 = NULL;
	if(arg2) {
		*pass2 = app_get_pass(err, arg2, same ? 2 : 0);
		if(!*pass2) return 0;
	} else if(pass2) *pass2 = NULL;
	return 1;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio)
{
	char *tmp, tpass[APP_PASS_LEN];
	static BIO *pwdbio = NULL;
	int i;
	if(!strncmp(arg, "pass:", 5)) return BUF_strdup(arg + 5);
	if(!strncmp(arg, "env:", 4)) {
		tmp = getenv(arg + 4);
		if(!tmp) {
			BIO_printf(err, "Can't read environment variable %s\n", arg + 4);
			return NULL;
		}
		return BUF_strdup(tmp);
	}
	if(!keepbio || !pwdbio) {
		if(!strncmp(arg, "file:", 5)) {
			pwdbio = BIO_new_file(arg + 5, "r");
			if(!pwdbio) {
				BIO_printf(err, "Can't open file %s\n", arg + 5);
				return NULL;
			}
		} else if(!strncmp(arg, "fd:", 3)) {
			BIO *btmp;
			i = atoi(arg + 3);
			if(i >= 0) pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
			if((i < 0) || !pwdbio) {
				BIO_printf(err, "Can't access file descriptor %s\n", arg + 3);
				return NULL;
			}
			/* Can't do BIO_gets on an fd BIO so add a buffering BIO */
			btmp = BIO_new(BIO_f_buffer());
			pwdbio = BIO_push(btmp, pwdbio);
		} else if(!strcmp(arg, "stdin")) {
			pwdbio = BIO_new_fp(stdin, BIO_NOCLOSE);
			if(!pwdbio) {
				BIO_printf(err, "Can't open BIO for stdin\n");
				return NULL;
			}
		} else {
			BIO_printf(err, "Invalid password argument \"%s\"\n", arg);
			return NULL;
		}
	}
	i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
	if(keepbio != 1) {
		BIO_free_all(pwdbio);
		pwdbio = NULL;
	}
	if(i <= 0) {
		BIO_printf(err, "Error reading password from BIO\n");
		return NULL;
	}

	tmp = (char *) strchr(tpass, '\n');

	if( tmp )
		*tmp = 0;

	return BUF_strdup(tpass);
}


/* Main function where you get all options read and operations done */
int	main(int argc, char *argv[]) {

	int badops = 0;
	int ret = 0;

	/* certificate and key bios */
	BIO *keyf = NULL;
	BIO *certf = NULL;

	/* input bios */
	BIO *inbio = NULL;
	// BIO *req_inbio = NULL;
	// BIO *resp_inbio = NULL;

	/* output related bios */
        BIO *outbio = NULL;
        // BIO *req_outbio = NULL;
        // BIO *resp_outbio = NULL;

	/* error bio */
        BIO *bio_err = NULL;

	/* input file names */
	char *infile = NULL;
	// char *req_infile = NULL;
	// char *resp_infile = NULL;

	/* output file names */
	char *outfile = NULL;
	// char *req_outfile = NULL;
	// char *resp_outfile = NULL;

	/* certificate and key filenames */
	char *keyfile = NULL;
	char *reccertfname = NULL;
	char *signcertfname = NULL;
	char *issuedcertfname = NULL;
	char *reqfname = NULL;
	char *crlfname = NULL;
	
	/* CA's certificate filename */
	char *cacertfname = NULL;

	char **pp = NULL;
	char *key = NULL;
	char *passargin = NULL;
	char *msgrecnonce = NULL;
	char *msgsendnonce = NULL;
	char *msgtype = NULL;
	char *msgstatus = NULL;
	char *msgfailinfo = NULL;

	int keyform = FORMAT_PEM;
	int signcertform = FORMAT_PEM;
	int reccertform = FORMAT_PEM;
	int issuedcertform = FORMAT_PEM;
	int cacertform = FORMAT_PEM;
	int reqform = FORMAT_PEM;
	int crlform = FORMAT_PEM;
	int inform = FORMAT_PEM;
	int outform = FORMAT_PEM;

	int new = 0;
	int text = 0;
	int print_scert = 0;
	int print_req = 0;
	int print_crl = 0;
	int print_sendnonce = 0;
	int print_recnonce = 0;
	int print_transid = 0;
	int print_msgtype = 0;
	int print_serial = 0;

	//private - not documented
	
	int noout = 0;
	int version = 0;

	char *sendnonce = NULL;
	char *recnonce = NULL;
	char *transId = NULL;

	int copynonce = 1;
	ASN1_INTEGER *sno = NULL;

	/* encryption algorithm */
	EVP_CIPHER cipher = *EVP_des_ede3_cbc();

	/* Private key for the signer */
	EVP_PKEY *pkey = NULL;

	/* recipien/signer certificate */
	X509 *signcert = NULL;
	X509 *reccert = NULL;
	X509 *issuedcert = NULL;
	X509_CRL *crl = NULL;

	/* trusted CA certificate */
	X509 *cacert = NULL;

	/* X509 Request for a new PKCSReq */
	X509_REQ *req = NULL;

        /* ADD ENGINE SUPPORT */
#ifdef HAVE_ENGINE
        char *engine=NULL;
        ENGINE *e = NULL;
#endif

	// int		c, rc, bytes, fd;
	// char		filename[1024];
	
	/* Incoming message structure */
	SCEP_MSG	*msg = NULL;

	/* New message structure */
	SCEP_MSG *newMsg = NULL;

	/* Pointer to the message to be printed */
	SCEP_MSG *out_msg = NULL;

	/* What are really needed here ?? Please help... */
	X509V3_add_standard_extensions();
	OpenSSL_add_all_algorithms();

	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

        if ((bio_err=BIO_new(BIO_s_file())) != NULL)
        	BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

        outbio=BIO_new_fp(stdout,BIO_NOCLOSE);

	/* ARGUMENTS PARSING */
	argv++;
	argc--;

	infile=NULL;
	outfile=NULL;

	while (argc >= 1)
		{
		if      (strcmp(*argv,"-inform") == 0)
			{
			if (--argc < 1) goto bad;
			inform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-outform") == 0)
			{
			if (--argc < 1) goto bad;
			outform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-reccert") == 0)
                        {
                        if (--argc < 1) goto bad;
                        reccertfname= *(++argv);
                        }
		else if (strcmp(*argv,"-reccertform") == 0)
			{
			if (--argc < 1) goto bad;
			reccertform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-signcert") == 0)
                        {
                        if (--argc < 1) goto bad;
                        signcertfname= *(++argv);
                        }
		else if (strcmp(*argv,"-signcertform") == 0)
			{
			if (--argc < 1) goto bad;
			signcertform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-issuedcert") == 0)
                        {
                        if (--argc < 1) goto bad;
                        issuedcertfname= *(++argv);
                        }
		else if (strcmp(*argv,"-issuedcertform") == 0)
			{
			if (--argc < 1) goto bad;
			issuedcertform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-CAfile") == 0)
			{
			if (--argc < 1) goto bad;
			cacertfname= *(++argv);
			}
		else if (strcmp(*argv,"-CAform") == 0)
			{
			if (--argc < 1) goto bad;
			cacertform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-reqfile") == 0)
                        {
                        if (--argc < 1) goto bad;
                        reqfname= *(++argv);
                        }
		else if (strcmp(*argv,"-reqform") == 0)
			{
			if (--argc < 1) goto bad;
			reqform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-crlfile") == 0)
                        {
                        if (--argc < 1) goto bad;
                        crlfname= *(++argv);
                        }
		else if (strcmp(*argv,"-crlform") == 0)
			{
			if (--argc < 1) goto bad;
			crlform=str2fmt(*(++argv));
			}
		else if (strcmp(*argv,"-passwd") == 0)
			{
			if (--argc < 1) goto bad;
			key= *(++argv);
			}
		else if (strcmp(*argv,"-keyfile") == 0)
			{
			if (--argc < 1) goto bad;
			keyfile= *(++argv);
			}
		else if (strcmp(*argv,"-passin") == 0)
			{
			if (--argc < 1) goto bad;
			passargin= *(++argv);
			}
		else if (strcmp(*argv,"-in") == 0)
			{
			if (--argc < 1) goto bad;
			infile = *(++argv);
			}
		else if (strcmp(*argv,"-msgtype") == 0)
			{
			if (--argc < 1) goto bad;
			msgtype = *(++argv);
			}
		else if (strcmp(*argv,"-status") == 0)
			{
			if (--argc < 1) goto bad;
			msgstatus = *(++argv);
			}
		else if (strcmp(*argv,"-failinfo") == 0)
			{
			if (--argc < 1) goto bad;
			msgfailinfo = *(++argv);
			}
		else if (strcmp(*argv,"-recnonce") == 0)
			{
			if (--argc < 1) goto bad;
			recnonce = *(++argv);
			}
		else if (strcmp(*argv,"-sendnonce") == 0)
			{
			if (--argc < 1) goto bad;
			sendnonce = *(++argv);
			copynonce = 0;
			}
		else if (strcmp(*argv,"-serial") == 0)
			{
			if (--argc < 1) goto bad;
			sno = s2i_ASN1_INTEGER(NULL, *(++argv));
			if( !sno ) goto bad;
			}
		else if (strcmp(*argv,"-out") == 0)
			{
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			}
#ifdef HAVE_ENGINE
		else if (strcmp(*argv,"-e") == 0)
			{
			if (--argc < 1) goto bad;
			engine = *(++argv);
			}
#endif
		else if (strcmp(*argv,"-des") == 0)
			cipher=*EVP_des_cbc();
		else if (strcmp(*argv,"-v") == 0)
			verbose=1;
		else if (strcmp(*argv,"-debug") == 0)
			debug=1;
		else if (strcmp(*argv,"-version") == 0)
			version=1;
		else if (strcmp(*argv,"-new") == 0)
			new=1;
		else if (strcmp(*argv,"-text") == 0)
			text=1;
		else if (strcmp(*argv,"-print_sendnonce") == 0)
			print_sendnonce=1;
		else if (strcmp(*argv,"-print_recnonce") == 0)
			print_recnonce=1;
		else if (strcmp(*argv,"-print_transid") == 0)
			print_transid=1;
		else if (strcmp(*argv,"-print_msgtype") == 0)
			print_msgtype=1;
		else if (strcmp(*argv,"-print_req") == 0)
			print_req=1;
		else if (strcmp(*argv,"-print_crl") == 0)
			print_crl=1;
		else if (strcmp(*argv,"-print_scert") == 0)
			print_scert=1;
		else if (strcmp(*argv,"-print_serial") == 0)
		        print_serial=1;
		else if (strcmp(*argv,"-noout") == 0)
			noout=1;
		else badops = 1;
		argc--;
		argv++;
		}

bad:
	if (badops) {
		for (pp=usage; (*pp != NULL); pp++)
                        BIO_printf(bio_err,*pp);
		goto err;
	}

	ERR_load_crypto_strings();

	if (version) {
		BIO_printf( bio_err, "OpenCA Simple Certificate Enrollment Protocol Tools\n");
		BIO_printf( bio_err, "(c) 2002/2003 by Massimiliano Pala and OpenCA Group\n");
		BIO_printf( bio_err, "OpenCA licensed software\n\n");
		BIO_printf( bio_err, "\tVersion %s\n\n", VERSION );
		exit(0);
	}

        if (badops) {
                for (pp=usage; (*pp != NULL); pp++)
                        BIO_printf(bio_err,*pp);
                        exit(1);
        }

	inbio=BIO_new(BIO_s_file());

	/* Input file */
	if( infile == NULL ) {
		BIO_set_fp(inbio,stdin,BIO_NOCLOSE);
	} else {
		if (!BIO_read_filename(inbio,infile)) {
			perror(infile);
			goto err;
		}
	}

	/* Output to file */
	if (outfile != NULL)
	{
		outbio = BIO_new(BIO_s_file());
        	if (BIO_write_filename(outbio,outfile) <= 0)
                {
			BIO_printf(bio_err,"Error writing file %s\n", outfile);
                	perror(outfile);
                        goto err;
                }
        }

        /* ENGINE support added */
#ifdef HAVE_ENGINE
	if (engine != NULL) {
		if((e = ENGINE_by_id(engine)) == NULL) {
			BIO_printf(bio_err,"invalid engine \"%s\"", engine);
			goto err;
		}

		if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
			BIO_printf(bio_err,"can't use that engine");
			goto err;
		}
		BIO_printf(bio_err,"engine \"%s\" set.\n", engine);
		ENGINE_free(e);
	}
#endif

        /* Passin support */
        if(!key && !app_passwd(bio_err, passargin, NULL, &key, NULL)) {
                BIO_printf(bio_err, "Error getting passwords\n");
                goto err;
        }

	/*****************************************************************/
        /* Reading Private key file */
	/*
        if (keyfile == NULL) {
		BIO_printf(bio_err, "no keyfile provided!\n");
		goto err;
       	}
	*/

	if( keyfile != NULL ) {
        	if( verbose )
        	        BIO_printf(bio_err,
				"Reading Private Key file %s", keyfile);
        	if ((keyf=BIO_new_file( keyfile, "r")) == NULL) {
			BIO_printf( bio_err,"cannot open BIO file, why ?" );
        	        goto err;
		}

        	if ( keyform == FORMAT_ENGINE)
		        {
#ifdef HAVE_ENGINE
			/*
        	        if(!e) {
				BIO_printf( bio_err,"no engine loaded!\n");
        	                goto err;
        	        }
        	        pkey = ENGINE_load_private_key( e, keyfile, key );
			*/

        	        BIO_printf(bio_err,"No engine support yet.\n");
        	        goto err;
#else
        	        BIO_printf(bio_err,"No engine support compiled.\n");
        	        goto err;
#endif
	        	} else if ( keyform == FORMAT_PEM ) {
	        	        pkey = (EVP_PKEY *) PEM_read_bio_PrivateKey(
						keyf, NULL,NULL, key);
	        	        if (key) memset(key,0,strlen(key));
	        	} else {
                	BIO_printf(bio_err,"bad input format specified for key file\n");
			goto err;
        	};
        	if( keyf ) BIO_free( keyf );

        	if( pkey == NULL ) {
        	        BIO_printf(bio_err,"Error loading private key\n");
        	        goto err;
        	};
	}


	/*****************************************************************/
	/* Load the recipient certificate file (if any) */
	if ( reccertfname ) {
		// if( verbose )
	        //         BIO_printf(outbio,"reading certificate file.\n");
		reccert = load_certificate ( reccertfname, reccertform );
	        if ( reccert == NULL) {
	                BIO_printf(bio_err,"cannot load recipient cert.\n");
	                goto err;
		}
	}


	/*****************************************************************/
	/* Load the signer certificate file */

	if ( signcertfname ) {
		// if( verbose )
	        //         BIO_printf(outbio,"reading certificate file.\n");
		signcert = load_certificate( signcertfname, signcertform);
	        if ( signcert == NULL ) {
	                BIO_printf(bio_err,"cannot load signer certificate.\n");
	                goto err;
		}

        	if ((pkey) && !X509_check_private_key(signcert,pkey)) {
        	       	BIO_printf(bio_err, "cert/private key do not match\n");
        	       	goto err;
		}

	}

	/*****************************************************************/
	/* Load the CA certificate file */
	/*
        if (cacertfname == NULL)
                {
		BIO_printf( bio_err, "no CA certificate provided!\n");
                goto err;
                }
	*/
	if ( cacertfname ) {
		// if( verbose )
	        //         BIO_printf(outbio,"reading CA certificate file.\n");
		cacert = load_certificate( cacertfname, cacertform );
	        if (cacert == NULL) {
	                BIO_printf(bio_err,"cannot load CA certificate.\n");
	                goto err;
		}
	}

	/*****************************************************************/
	/* Load the issued certificate file (if any) for the CertRep with
	 * success pkiStatus*/
	if ( issuedcertfname ) {
		// if( verbose )
	        //         BIO_printf(outbio,"reading certificate file.\n");
		issuedcert = load_certificate ( issuedcertfname, 
				issuedcertform );
	        if ( issuedcert == NULL) {
	                BIO_printf(bio_err,"cannot load isseued cert.\n");
	                goto err;
		}
	}

        /*****************************************************************/
	/* Load the PKCS#10 to be included into the PKCSReq message */
	if ( reqfname ) {
		BIO *reqf = NULL;

		if( verbose )
	                BIO_printf(outbio,"reading request file.\n");
	        if ((reqf=BIO_new_file( reqfname, "r")) == NULL) {
	                BIO_printf(bio_err,"unable to open request file.\n");
	                goto err;
		}

		if (reqform == FORMAT_ASN1)
			req=d2i_X509_REQ_bio(reqf,NULL);
		else if (reqform == FORMAT_PEM)
			req=(X509_REQ *)PEM_read_bio_X509_REQ(reqf,NULL,NULL,NULL);
		else {
			BIO_printf(bio_err,
				"bad input format specified for X509 request\n");
			goto err;
		}

		if( !req ) {
	                BIO_printf(bio_err,"cannot load pkcs#10 request.\n");
	                goto err;
		}
		BIO_free( reqf );
	}

        /*****************************************************************/
	/* Load CRL for a CertRep Message */
	if( crlfname ) {
		BIO *crlf = NULL;

		if( verbose )
	                BIO_printf(outbio,"reading crl file.\n");
		
	        if ((crlf=BIO_new_file( crlfname, "r")) == NULL) {
	                BIO_printf(bio_err,"unable to open crl file.\n");
			ERR_print_errors(bio_err);
	                goto err;
		}

		if (crlform == FORMAT_ASN1)
			crl=d2i_X509_CRL_bio(crlf,NULL);
		else if (crlform == FORMAT_PEM)
			crl=PEM_read_bio_X509_CRL(crlf,NULL,NULL,NULL);
		else	{
			BIO_printf(bio_err,"bad input format specified for input crl\n");
			BIO_free( crlf );
			goto err;
			}

		BIO_free( crlf );
		if (crl == NULL)
			{
			BIO_printf(bio_err,"unable to load CRL\n");
			ERR_print_errors(bio_err);
			goto err;
			}
	}
        /*****************************************************************/
	/* Add SCEP related OIDs */
	if( add_objects_oids() == 0 ) {
		goto err;
	}

        /*****************************************************************/
	/* Load a SCEP message */
	if( infile ) {
	        if (( inbio = BIO_new_file( infile, "r")) == NULL) {
	                BIO_printf(bio_err,
				"%s:%d: unable to open SCEP request %s.\n",
				__FILE__, __LINE__, infile);
	                goto err;
		}

		if( inform == FORMAT_PEM ) {
			msg = (SCEP_MSG *) PEM_read_bio_SCEP_MSG(inbio);
		} else if ( inform == FORMAT_ASN1 ) {
			msg = (SCEP_MSG *) d2i_SCEP_MSG_bio(inbio);
		} else {
			BIO_printf(bio_err, "%s:%d: format not supported\n",
					__FILE__,__LINE__);
			goto err;
		}

		if( msg == NULL) {
			BIO_printf(bio_err, "%s:%d: error while reading msg\n",
					__FILE__,__LINE__);
			goto err;
		}

		out_msg = msg;
	}

	/****************************************************************/
	/* Create a new message, if there is an infile, then try to build
	 * a reply */

	if( new ) {
		// Generate a new message, if an input message is given
		// then we will build a corrisponding reply with passed
		// information (command line overrides default from in
		// msg)
		
		PKCS7_ISSUER_AND_SERIAL *ias = NULL;
		int type;
		int status;
		int failinfo;

		type = (int) SCEP_str2type( msgtype );
		if( type < 0 ) {
			BIO_printf( bio_err, 
				"%s:%d Message type (%s) not supported (%d)!\n",
			       	__FILE__, __LINE__, msgtype, type );
		}

		if( (type == MSG_GETCERT) || (type == MSG_GETCRL)) {
			if( !sno ) {
				if (!signcert) goto bad;
				sno = ASN1_INTEGER_dup(
					X509_get_serialNumber(signcert));

				if(!sno) goto bad;
			}

			if( !sno || !(cacert || signcert) ) {
				BIO_printf( bio_err, 
					"%s:%d serial and cacert/signcert required for %s messages!\n",
			       	__FILE__, __LINE__, msgtype );
				goto bad;
			}

			ias = PKCS7_ISSUER_AND_SERIAL_new();
			if( cacert )
				ias->issuer = X509_NAME_dup( 
						X509_get_subject_name(cacert));
			else if ( signcert )
				ias->issuer = X509_NAME_dup( 
						X509_get_issuer_name(signcert));
			else
				goto err;

			ias->serial = sno;
		}

		newMsg = SCEP_MSG_new( type, signcert, pkey, reccert, msg,
				    req, issuedcert, NULL, ias, crl, cacert, cipher );

		if( newMsg == NULL ) {
			BIO_printf( bio_err, "%s:%d Error creating message!\n",
				__FILE__, __LINE__ );
			goto err;
		}

		/* Let's set the pki status extension */
		status = (int) SCEP_str2status( msgstatus );
		if( status < -1 ) {
			BIO_printf( bio_err,
				"%s:%d Message status (%s) not supported (%d)!\n",
				__FILE__, __LINE__, msgstatus, status );
		}
		if( status >= 0 ) SCEP_set_pkiStatus ( newMsg, status );
		
		/* Set the failinfo extension */
		failinfo = (int) SCEP_str2failure( msgfailinfo );
		if( failinfo < -1 ) {
			BIO_printf( bio_err,
				"%s:%d Message failinfo (%s) not supported (%d)!\n",
				__FILE__, __LINE__, msgstatus, status );
		}
		if( failinfo >= 0) SCEP_set_failInfo ( newMsg, failinfo );

		/* Let's set the senderNonce extension */
		if( sendnonce ) SCEP_set_senderNonce(newMsg,sendnonce,strlen(sendnonce));

		/* Let's set the recipientNonce extension */
		if( recnonce ) SCEP_set_recipientNonce_new(newMsg,recnonce,strlen(recnonce));

		/* Message to be sent out is the new one */
		out_msg = newMsg;
	}

	// BIO_printf( bio_err, "%s:%d Debug!\n", __FILE__, __LINE__ );

	/*
	switch (atoi(scep.request.messageType)) {
	case MSG_CERTREP:
		BIO_printf(outbio, "%s:%d: CertRep message, should not happen",
			__FILE__, __LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: CertRep message received\n",
				__FILE__, __LINE__);
		rc = certrep(&scep);
		break;
	case MSG_V2PROXY:
	case MSG_V2REQUEST:
		rc = v2request(&scep);
		break;
	case MSG_PKCSREQ:
		BIO_printf(outbio, "%s:%d: PKCSReq message received", __FILE__,
			__LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: PKCSReq message received\n",
				__FILE__, __LINE__);
		rc = pkcsreq(&scep);
		break;
	case MSG_GETCERTINITIAL:
		BIO_printf(outbio, "%s:%d: GetCertInitial message received",
			__FILE__, __LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: GetCertInitial message "
				"received\n", __FILE__, __LINE__);
		rc = getcertinitial(&scep);
		break;
	case MSG_GETCERT:
		BIO_printf(outbio, "%s:%d: GetCert message received",
			__FILE__, __LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: GetCert message received\n",
				__FILE__, __LINE__);
		rc = getcert(&scep);
		break;
	case MSG_GETCRL:
		BIO_printf(outbio, "%s:%d: GetCRL message received", __FILE__,
			__LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: GetCRL message received\n",
				__FILE__, __LINE__);
		rc = getcrl(&scep);
		break;
	default:
		BIO_printf(outbio, "%s:%d: message of unknown type: %s",
			__FILE__, __LINE__, scep.request.messageType);
		BIO_printf(bio_err, "%s:%d: unknown message type: %s\n",
			__FILE__, __LINE__, scep.request.messageType);
		scep.reply.failinfo = SCEP_FAILURE_BADREQUEST;
	}

prepreply:
	if (debug)
		BIO_printf(bio_err, "%s:%d: reply prepared, encoding follows\n",
			__FILE__, __LINE__);

	if (rc < 0) {
		//create a failure reply by setting the failinfo field
		BIO_printf(bio_err, "%s:%d: bad return code from handler\n",
			__FILE__, __LINE__);
		scep.reply.failinfo = SCEP_FAILURE_BADREQUEST;
	}
	*/

	/* print a HTTP header						*/
	/*
	if (debug)
		BIO_printf(bio_err, "%s:%d: preparing reply headers\n",
			__FILE__, __LINE__);
	printf("Content-Transfer-Encoding: 8bit\r\n");
	printf("Content-Type: application/x-pki-message\r\n");
	printf("Content-Length: %d\r\n\r\n", scep.reply.length);
	// fflush(outbio);
	if (debug)
		BIO_printf(bio_err, "%s:%d: headers sent\n", __FILE__,
			__LINE__);
	*/

	if( print_sendnonce && out_msg ) {
		char *nonce = NULL;

		if( (nonce = SCEP_MSG_sender_nonce2hex( out_msg )) != NULL )
			BIO_printf( outbio, "SENDER NONCE=%s\n", nonce );
		else
			BIO_printf( outbio, "SENDER NONCE= not found\n");
	}

	if( print_recnonce && out_msg ) {
		char *nonce = NULL;

		if( (nonce = SCEP_MSG_recipient_nonce2hex( out_msg )) != NULL )
			BIO_printf( outbio, "RECIPIENT NONCE=%s\n", nonce );
		else
			BIO_printf( outbio, "RECIPIENT NONCE= not found\n");
	}

	if( print_transid && out_msg ) {
		char *transid = NULL;
		
		if( (transid = SCEP_MSG_transid( out_msg )) != NULL )
			BIO_printf( outbio, "TRANSACTION ID=%s\n", transid );
		else
			BIO_printf( outbio, "TRANSCATION ID= not found\n");

		OPENSSL_free( transid );
	}

	if( print_msgtype && out_msg ) {
		BIO_printf( outbio, "%s (%d)\n", 
			SCEP_type2str(out_msg->messageType), out_msg->messageType );
	}

	if( text && out_msg )
		SCEP_MSG_print(outbio, out_msg,  pkey, signcert);

	//Implemented by Radu Gajea, NBM (RIG)
	if( print_serial && out_msg ) {
	  unsigned char *data=NULL;
	  long len = 0;
	  data = (unsigned char *) SCEP_MSG_decrypt(out_msg, pkey, signcert, &len);
	  if( data ) {
	    i2a_ASN1_INTEGER( outbio, out_msg->env_data.content.ias->serial );
	    free( data );
	  }
	}

	if( !noout && out_msg ) {
		int ret = 0;

		if( outform == FORMAT_PEM ) {
			ret = PEM_write_bio_SCEP_MSG( outbio, out_msg, pkey );
		} else if( outform == FORMAT_B64 ) {
			ret = B64_write_bio_SCEP_MSG( outbio, out_msg, pkey );
		} else if( outform == FORMAT_ASN1 ) {
			ret = i2d_SCEP_MSG_bio ( outbio, out_msg, pkey );
		} else {
			BIO_printf(bio_err, "%s:%d: format not supported\n",
					__FILE__, __LINE__ );
			goto err;
		}
		if( ret <= 0 ) {
			BIO_printf(bio_err, "%s:%d: error writing message %d\n",
				__FILE__, __LINE__, ret);
		}
	}

	if( print_req && out_msg ) {
		X509_REQ *x509_req = NULL;

		if( !pkey ) {
			BIO_printf(bio_err, "%s:%d: needed private key\n",
		 		__FILE__, __LINE__);
			goto err;
		}

		x509_req = SCEP_MSG_decrypt_PKCSREQ( out_msg,
						pkey,signcert,NULL );
		if( x509_req ) {
                        if( text ) X509_REQ_print_ex(outbio, x509_req,
                                                     XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB), X509_FLAG_COMPAT );

			PEM_write_bio_X509_REQ(outbio, x509_req);
		} else {
			BIO_printf(bio_err, "%s:%d: cannot decrypt request\n",
                                __FILE__, __LINE__);
			goto err;
		}
		X509_REQ_free( x509_req );

	}

	if( print_crl && out_msg ) {
		X509_CRL *crl = NULL;

		if(!pkey) {
			BIO_printf( bio_err, "%s:%d: needed private key\n",
					__FILE__, __LINE__ );
			goto err;
		}

		crl = SCEP_MSG_decrypt_CERTREP( out_msg, pkey, 
				signcert, NULL );

		if( crl ) {
			if( text ) X509_CRL_print( outbio, crl );
			PEM_write_bio_X509_CRL( outbio, crl );
		} else {
			BIO_printf( bio_err, "%s:%d: no CRL found!\n",
					__FILE__, __LINE__ );
			goto err;
		}
		X509_CRL_free ( crl );
	}

	if( print_scert && out_msg ) {
		if( out_msg->signer_cert == NULL ) {
			BIO_printf( bio_err, "%s:%d: cannot find signer certificate!\n",
					__FILE__, __LINE__);
			goto err;
		}

		if ( text ) {
			BIO_printf( outbio, "\nSigner Certificate:\n" );
                        X509_print_ex( outbio, out_msg->signer_cert,
                                       XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB), X509_FLAG_COMPAT );
		} 
		if ( !noout && text ) {
			dump_cert_text( outbio, out_msg->signer_cert );
		}

		if( noout ) PEM_write_bio_X509( outbio, out_msg->signer_cert );
	}
	
	/* successful completion					*/
	exit(EXIT_SUCCESS);

	/* but we may as well fail					*/
err:
	ERR_print_errors(bio_err);
	exit(EXIT_FAILURE);
}

static int add_objects_oids( void ) {

	int i;

	i = 0;
	while( scep_exts[i] && scep_exts[i+1] ) {
		if(OBJ_create(scep_exts[i], scep_exts[i+1], scep_exts[i+1])
			       	== NID_undef) {
			return 0;
		}

		i = i+2;
	}

	return 1;

}

int dump_cert_text (BIO *out, X509 *x)
{
        BIO_puts(out,"subject=");
        X509_NAME_print_ex (out, X509_get_subject_name(x),
                            0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));

        BIO_puts(out,"\nissuer= ");
        X509_NAME_print_ex (out, X509_get_issuer_name(x),
                            0, XN_FLAG_RFC2253&(~ASN1_STRFLGS_ESC_MSB));
        BIO_puts(out,"\n");
	return 0;
}

int str2fmt(char *s) {
	if      ((*s == 'D') || (*s == 'd'))
		return(FORMAT_ASN1);
	else if ((*s == 'T') || (*s == 't'))
		return(FORMAT_TEXT);
	else if ((*s == 'P') || (*s == 'p'))
		return(FORMAT_PEM);
	else if ((*s == 'B') || (*s == 'b'))
		return(FORMAT_B64);
	else if ((*s == 'E') || (*s == 'e'))
		return(FORMAT_ENGINE);
	else
		return(FORMAT_UNDEF);
}

X509 *load_certificate ( char *fname, int format ) {

	BIO *certf = NULL;
	X509 *cert = NULL;

	if (!fname) return NULL;

	if (format == FORMAT_UNDEF) 
		format = FORMAT_PEM;

	if ((certf=BIO_new_file( fname, "r")) == NULL)
	                return NULL;

	if (format == FORMAT_ASN1)
		cert = d2i_X509_bio(certf,NULL);
	else if (format == FORMAT_PEM)
		cert = (X509 *) PEM_read_bio_X509(certf,NULL,NULL,NULL);

	BIO_free( certf );

	/* if loaded certificate, cert !NULL */
	return cert;

}

STACK_OF(X509) *load_certificate_stack ( char *fname, int format ) {

	STACK_OF(X509) *sk;
	BIO *certf = NULL;
	X509 *cert = NULL;

	if (!fname) return NULL;

	if (format == FORMAT_UNDEF) 
		format = FORMAT_PEM;

	if ((certf=BIO_new_file( fname, "r")) == NULL)
	                return NULL;

	sk = sk_X509_new(NULL);
	if( !sk ) {
		BIO_free(certf);
		return NULL;
	}

	do {
		if (format == FORMAT_ASN1)
			cert = d2i_X509_bio(certf,NULL);
		else if (format == FORMAT_PEM)
			cert = (X509 *) PEM_read_bio_X509(certf,NULL,NULL,NULL);
		else {
			if( certf ) BIO_free ( certf );
			return NULL;
		}
		if( cert ) sk_X509_push( sk, cert );
	} while (cert);

	return sk;
}
