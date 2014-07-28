/* OpenCA PKCS#7 tool - (c) 2000 by Massimiliano Pala and OpenCA Group */
/* OpenCA PKCS#7 tool - (c) 2004 The OpenCA Project */

#include <openca/general.h>
#include <openca/tools.h>

int getCommand ( int argc, char *argv[] ) {

	if( strcmp( argv[1], "sign" ) == 0 )
		{
		return(OPENCA_PKCS7_SIGN);
		}
	else if ( strcmp( argv[1], "verify" ) == 0 )
		{
		return(OPENCA_PKCS7_VERIFY);
		}
	else if ( strcmp( argv[1], "encrypt" ) == 0 )
		{
		return(OPENCA_PKCS7_ENCRYPT);
		}
	else if ( strcmp( argv[1], "decrypt" ) == 0 )
		{
		return(OPENCA_PKCS7_DECRYPT);
		}
	else if ( strcmp( argv[1], "--version" ) == 0 )
		{
		return(OPENCA_PKCS7_VERSION);
		}
	else
		{
		return( -1 );
		}
		
}

void printVersion( BIO *bio_err, char *INFO[] ) {
	BIO_printf( bio_err, "\n%s (Ver. %s)\n", INFO[1], INFO[0] );
	BIO_printf( bio_err, "by %s\n", INFO[2] );
	BIO_printf( bio_err, "%s\n\n", INFO[3] );
}

void whichVersion( BIO *bio_err, char *INFO[] ) {
	BIO_printf( bio_err, "%s\n", INFO[0] );
}

