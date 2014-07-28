/* $Id: acconfig.h,v 1.1.1.1 2007/04/11 01:46:08 madwolf Exp $ */

#ifndef _CONFIG_H
#define _CONFIG_H

/* Generated automatically from acconfig.h by autoheader. */
/* Please make your changes there */

@TOP@

/* Define if you want to install preformatted manpages.*/
#undef MANTYPE

/* Define if your ssl headers are included with #include <openssl/header.h>  */
#undef HAVE_OPENSSL

/* Define if you are linking against RSAref.  Used only to print the right
 * message at run-time. */
#undef RSAREF

/* Define if libc defines __progname */
#undef HAVE___PROGNAME

/* Define if we want shared libraries support */
#undef HAVE_SHARED_LIBS

@BOTTOM@

/* ******************* Shouldn't need to edit below this line ************** */

#include "defines.h"

#endif /* _CONFIG_H */
