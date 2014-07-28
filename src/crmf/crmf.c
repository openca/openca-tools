/* OpenCA CRMF Tool */
#include <openca/general.h>
#include <openca/crmf_asn1.h>
#include <openca/crmf_bio.h>

BIO *bio_err=NULL;

char *usage[] = {
	"Usage: openca-crmf [options]\n\n",
	NULL
};

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

        BIO *data   = NULL;
        BIO *output = NULL;
	char *datafile = NULL;
	char *outfile = NULL;

	char **pp = NULL;
	int badops=0, outdata=0, i;

	char *certsdir = NULL;
	char *certsfile = NULL;

	CRMF_REQ *req = NULL;
	BIO *bio_out = NULL;
	int verbose = 0;
	int inform = FORMAT_PEM;
	int outform = FORMAT_PEM;
	int to_pkcs10 = 1;
	int text = 0;

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
		printf("ERROR: needed command and arguments missing\n\n");
		badops=1;
		goto badops;
	}

	while (argc > 1) {
		argc--;
		argv++;
		if (strcmp(*argv,"-verbose") == 0)
                        {
			verbose=1;
			}
		else if ( strcmp (*argv, "-to_pkcs10") == 0 )
			{
			to_pkcs10=1;
			}
		else if ( strcmp (*argv, "-text") == 0 )
			{
			text=1;
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
		else if (strcmp(*argv,"-outform") == 0)
			{
                        if (--argc < 1) goto bad;

			++argv;
			if ( strcmp(*argv, "DER") == 0) 
				{
				outform=FORMAT_ASN1;
				}
			else if ( strcmp( *argv, "PEM" ) == 0)
				{
				outform=FORMAT_PEM;
				} 
			else 
				{
				goto bad;
				}
			}
		else if (strcmp(*argv,"-inform") == 0)
			{
			if (--argc < 1) goto bad;
			++argv;
			if ( strcmp(*argv, "DER") == 0) 
				{
				inform=FORMAT_ASN1;
				}
			else if ( strcmp( *argv, "PEM" ) == 0)
				{
				inform=FORMAT_PEM;
				} 
			else 
				{
				goto bad;
				}
			}
		else 
			{
bad:
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

	if( inform == FORMAT_PEM ) {
		req = PEM_read_bio_CRMF_REQ( data );
	} else if ( inform == FORMAT_ASN1 ) {
		req = d2i_CRMF_REQ_bio( data, NULL );
	};

	if( !req ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	
	exit(0);
}

