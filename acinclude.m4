dnl Check for library paths and if static-dynamic linking is
dnl supported
AC_DEFUN(AC_CHECK_OPENSSL_PATH,
[
_package=OPENSSL
_version=$1
_prefix=$2
_dirs=$3
_libs="crypto ssl"

library_ldflags=
library_ldadd=
library_cflags=
library_path=
library_setup=no

if ! [[ "x${_prefix}" = "x" ]] ; then

   if [[ "x${_version}" = "x" ]] ; then
	_version=0.0.0
   fi

   if [[ -d "/usr/sfw/lib/pkgconfig" ]] ; then
   	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/sfw/lib/pkgconfig
   fi
	
   if [[ -d "/opt/csw/lib/pkgconfig" ]] ; then
   	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/opt/csw/lib/pkgconfig
   fi

   if [[ "$enable_shared" = "yes" ]] ; then
   ifdef([PKG_CHECK_MODULES],
	[
            if ! [[ x${HAS_PKGCONF} = x  ]]; then
                PKG_CHECK_MODULES( OPENSSL, openssl >= $_version, [
                   AC_MSG_RESULT([ OPENSSL $_version or greater found via pkg-config])
                   library_cflags=$OPENSSL_CFLAGS
                   library_ldflags=$OPENSSL_LDFLAGS
                   library_ldadd=$OPENSSL_LIBS
                   library_prefix=$OPENSSL_PREFIX
		   if [[ "x$library_prefix" = "x" ]] ; then
			my_path=${library_libs#-L}
			my_path=`echo "${my_path}" | sed "s| .*||"`
			library_path=$my_path
		   else
		   	library_path=$library_prefix/lib
		   fi
                   library_setup=yes
            fi
		],
		[
			AC_MSG_RESULT( [good openssl not found via pkgconfig])
			library_setup=no
		])
                dnl End of PKG_CHECK macro
          ],
          [
            ## Skipping pkg-config macros...
	    AC_MSG_RESULT( [ Skipping pkg-config macros ])
          ])
fi

fi

if [[ "$library_setup" = "no" ]] ; then
	if [[ "x${_prefix}" = "x" ]]; then
		_path=$_dirs
	else
		_path=$_prefix/lib
	fi

	_shared=0
	_static=0

	for _i in $_path; do

		if [[ "$library_setup" = "yes" ]] ; then
			break
		fi

		library_prefix=${_i%/lib}
		library_includes=$library_prefix/include/openssl/opensslv.h

		if ! [[ -f $library_includes ]] ; then
			continue;
		fi;

		AC_MSG_RESULT([Searching OpenSSL Version: $library_includes]);
		ver=`grep "#define SHLIB_VERSION_NUMBER" $library_includes | sed 's/[#_a-zA-Z" ]//g' | sed 's|\.|0|g'`;
		my_ver=`echo $_version | sed "s|\.|0|g"`;

		AC_MSG_RESULT([Detected Version: $ver (required > $my_ver )]);

		if [[ $ver -ge $my_ver ]] ; then
			AC_MSG_RESULT([OpenSSL Version $ver: Ok.]);
		else
			AC_MSG_RESULT([OpenSSL Version $ver: Too old, skipping.]);
			continue;
		fi

		# crypto_so=${_i}/librcrypto*.$shlext
		# ssl_so=${_i}/libssl*.$shlext"

		_i=`echo ${_i} | sed 's| |\\ |g'`
		crypto_so=`ls ${_i}/libcrypto*.$shlext 2>/dev/null`
		ssl_so=`ls ${_i}/libssl*.$shlext 2>/dev/null`

		for _k in $crypto_so ; do
			crypto_so=$_k;
		done

		for _k in $ssl_so ; do
			ssl_so=$_k
		done

		dnl AC_MSG_RESULT([*** DEBUG _i = ${_i}]);
		dnl AC_MSG_RESULT([*** DEBUG crypto_so = $crypto_so]);
		dnl AC_MSG_RESULT([*** DEBUG ssl_so = $ssl_so]);
		dnl AC_MSG_RESULT([*** DEBUG arch = $myarch]);
		dnl AC_MSG_RESULT([*** DEBUG shlext = $shlext]);

		if ! [[ -z "${crypto_so}" ]] ; then
			if ! [[ -z "${ssl_so}" ]] ; then
				_shared=1
				library_shared=yes
				library_ldflags="-L${_i}"
				library_ldadd="-lssl -lcrypto "
				# library_libs="-lssl -lcrypto"
				# library_ldflags="${_i}/libcrypto.${shlext} ${_i}/libssl.${shlext}"
				library_path=${_i}
				library_prefix=${_i%/lib}
				library_cflags="-I${library_prefix} -I${library_prefix}/include"
				if [[ "x$library_prefix" = "x" ]] ; then
					library_prefix=/
				fi

				library_setup=yes
			fi
		fi

		if [[ "$enable_shared" = "no" ]] ; then
			_library_setup=no
			_library_shared=no
			_shared=0
		fi

		if [[ $_shared -eq 0 ]] ; then
			if [[ -r "${_i}/libcrypto.$libext" ]] ; then
				if [[ -r "${_i}/libssl.$libext" ]] ; then
					_static=1
				fi
			fi

			if [[ $_static = 1 ]] ; then
				library_shared=no
				library_path=${_i}
				library_prefix=${_i%/lib}
				if [[ "x$library_prefix" = "x" ]] ; then
					library_prefix=/
				fi
				if [[ -d "${library_prefix}/include" ]] ; then
					library_cflags="-I${library_prefix}/include"
				else
					library_cflags="-I${library_prefix}"
				fi
				library_ldflags="-L${library_prefix}"
				library_ldadd="-lcrypto -lssl "
				# library_ldflags="${_i}/libcrypto.$libext ${_i}/libssl.$libext"
				if [[ "${enable_shared}" = "yes" ]] ; then
					AC_MSG_RESULT([ *** WARNING: non-shared libs found, try using "--disable-shared" to use them])
					continue;
				fi

				library_setup=yes
				dnl AC_MSG_RESULT([ *** DEBUG: lib setup ok $library_ldflags / $library_ldadd])
				break
			fi
		fi
	done
fi

if ! [[ "$library_setup" = "no" ]] ; then

if test "$cross_compiling" = yes; then
	library_setup=yes
else

old_cflags=$CFLAGS
old_ldflags=$LDFLAGS
old_libs=$LIBS

export CFLAGS=$library_cflags
export LDFLAGS=$library_ldflags
export LIBS=$library_ldadd
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$library_path

dnl AC_MSG_RESULT([LD_LIBRARY_PATH=$library_path]);

AC_RUN_IFELSE( [
#include <openssl/x509.h>
int main(void) {
	X509 *x = NULL;
	return(0);
}], [ ok=1 ], [ ok=0 ])

CFLAGS=$old_cflags
LDFLAGS=$old_ldflags
LIBS=$old_libs

if [[ $ok = 0 ]] ; then
	AC_MSG_ERROR([*** ERROR::Can not configure OPENSSL library!])
	library_shared=
	library_prefix=
	library_cflags=
	library_ldflags=
	library_ldadd=
	library_libs=
	library_setup=no
else
	dnl AC_MSG_RESULT([Library OPENSSL prefix... $library_prefix ])
	dnl AC_MSG_RESULT([Library OPENSSL is SHARED... $library_shared ])
	dnl AC_MSG_RESULT([Library OPENSSL C flags... $library_cflags ])
	dnl AC_MSG_RESULT([Library OPENSSL LD flags... $library_ldflags ])
	dnl AC_MSG_RESULT([Library OPENSSL LIBS flags ... $library_libs ])
	library_setup=yes
fi

fi # End of Cross Compiling Check

fi # End of Library Setup 

])


dnl Check for extra support libraries and options 
AC_DEFUN(AC_CHECK_C_OPTION,
[ 
old_cflags=$CFLAGS
CFLAGS="$CFLAGS $1"

AC_MSG_CHECKING([checking for $1 support]);

AC_RUN_IFELSE( [
#include <stdlib.h>
int main(void)
{
        return(0);
}], [ _supported=yes ], [ _supported=no])

if [[ $_supported = no ]] ; then
        AC_MSG_RESULT([not supported]);
	CFLAGS=$old_cflags
else
        AC_MSG_RESULT([yes]);
fi])

AC_DEFUN(AC_LDAP_VENDOR,
[
_prefix=$1

dnl old_cflgas="$CFLAGS"
dnl old_ldflags="$LDFLAGS"

dnl export CFLAGS="-I$_prefix/include"
dnl export LDFLAGS="-L$_prefix/lib -lldap"

dnl AC_MSG_RESULT([LDAP VENDOR ===> prefix = $_prefix])

AC_MSG_CHECKING([checking for ldap vendor]);

if ! [[ "$_prefix" = "" ]] ; then
	if $EGREP "Sun" "$_prefix/include/ldap.h" 2>&1 >/dev/null ; then
	AC_DEFINE(LDAP_VENDOR_SUN)
	AC_MSG_RESULT([yes])
	ldap_vendor="SUN"
   else
   	if $EGREP "OpenLDAP" "$_prefix/include/ldap.h" 2>&1 >/dev/null ; then
		AC_DEFINE(LDAP_VENDOR_OPENLDAP)
		ldap_vendor="OPENLDAP"
	else
		AC_MSG_ERROR([*** LDAP::No supported vendors found in ($_prefix)***])
	fi
   fi

dnl AC_MSG_RESULT([LDAP VENDOR ===> searching for Sun])
   AC_EGREP_CPP( [Sun],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  	[
	   AC_DEFINE(LDAP_VENDOR_SUN)
	   ldap_vendor="SUN"
        ])

   if ! [[ "$ldap_vendor" = "SUN" ]] ; then
   	dnl AC_MSG_CHECKING([checking for OpenLDAP vendor ($_prefix) ]);
   	AC_EGREP_CPP( [OpenLDAP],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  		[
		   AC_DEFINE(LDAP_VENDOR_OPENLDAP)
   		   dnl AC_MSG_CHECKING([checking for OpenLDAP vendor ($_prefix) ]);
		   ldap_vendor="OPENLDAP"
		])
   fi

else

   dnl AC_MSG_RESULT([LDAP VENDOR ($_prefix) ===> searching for Sun])
   AC_EGREP_CPP( [Sun],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  	[
	   AC_DEFINE(LDAP_VENDOR_SUN)
	   ldap_vendor="SUN"
        ])

   if ! [[ "x$ldap_vendor" = "SUN" ]] ; then
   	dnl AC_MSG_CHECKING([checking for OpenLDAP vendor ($_prefix) ]);
   	AC_EGREP_CPP( [OpenLDAP],
[
#include <ldap.h>

int main(void) {
   char *p = LDAP_VENDOR_NAME;
   return(0);
}], 
  		[
		   AC_DEFINE(LDAP_VENDOR_OPENLDAP)
		   ldap_vendor="OPENLDAP"
		])
   fi
fi

   CFLAGS=$old_cflags
   LDFLAGS=$old_ldflags

   AC_MSG_RESULT([$ldap_vendor]);

])

AC_DEFUN(CHECKEC,
[ 

if test "$cross_compiling" = yes; then
	enable_ecdsa=yes
else

AC_RUN_IFELSE( [
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/opensslconf.h>
int main(void)
{
#ifdef OPENSSL_NO_EC
-garbage!
#endif
	EC_KEY *d = NULL;
	return(0);
}], [ 
	AC_DEFINE([ENABLE_ECDSA], 1, [ECC Support for OpenSSL])
	activate_ecdsa=yes
    ], [activate_ecdsa=no])
fi

dnl if [[ "$enable_ecdsa" = "no" ]] ; then
dnl 	AC_MSG_RESULT([checking for OpenSSL ECDSA support ... no])
dnl 	AC_MSG_ERROR(
dnl [*** ECDSA support]
dnl [*** missing support for ECDSA, please update OpenSSL version]
dnl )
dnl else
dnl 	AC_MSG_RESULT([OpenSSL ECDSA support    : yes]);
dnl fi
])

AC_DEFUN(AC_OPENSSL_OCSP,
[ AC_RUN_IFELSE( [
#include <openssl/ocsp.h>
int main(void)
{
	OCSP_CERTID *cid = NULL;
	return(0);
}], [ AC_DEFINE(HAVE_OCSP) ], [ocsp_error=1])

if [[ ocsp_error = 1 ]] ; then
	AC_MSG_RESULT([checking for OpenSSL OCSP support ... no])
	AC_MSG_ERROR(
[*** OCSP support]
[*** missing support for ocsp, please update OpenSSL version]
[*** to 0.9.7 (or SNAPs). More info on http://www.openssl.org]
)
else
	AC_MSG_RESULT([OpenSSL OCSP support    : yes]);
fi])

AC_DEFUN(AC_OPENSSL_VERSION,
[ AC_EGREP_HEADER( [\#define\sOPENSSL_VERSION_NUMBER\s0x],
	[ $openssl_prefix/include/openssl.h ],
	[ openssl_ver="0.9.8+"], 
    	[ openssl_ver="0.9.7"]
)

if [[ $openssl_ver = "0.9.8+" ]] ; then
	AC_DEFINE(OPENSSL_VER_00908000)
else
	AC_DEFINE(OPENSSL_VER_00907000)
fi
        AC_MSG_RESULT([OpenSSL Detected Version: $openssl_ver])
])

