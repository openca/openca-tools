## file: src/Makefile.am
## OpenCA MuscleCard ENGINE Makefile - by Massimiliano Pala
## 2002/2003 OpenCA Licensed Released Software
## All Rights Reserved

lib_LTLIBRARIES =
sbin_PROGRAMS = 
bin_PROGRAMS = openca-scep
include_HEADERS = 
check_PROGRAMS = 
TESTS =

if ENABLED_DEBUG
AM_CFLAGS = -ggdb -g -O2
else
AM_CFLAGS = -O2
endif


if ARCH_LINUX
MYLDFLAGS      =
# INCLUDE_LIBS   = 
INCLUDE_LIBS   = 
else
if ARCH_BSD
MYLDFLAGS      =
INCLUDE_LIBS   =
else
if ARCH_OSX
MYLDFLAGS      = -framework CoreFoundation
INCLUDE_LIBS   = -ll -lIOKit
COND_INCLUDES  = -I/System/Library/Frameworks/IOKit.framework/Headers
else
if ARCH_SOLARIS
MYLDFLAGS      =
INCLUDE_LIBS   = -ll -ldl -lnsl -lsocket -lposix4
else
if ARCH_HPUX
MYLDFLAGS      =
INCLUDE_LIBS   = -ll
endif
endif
endif
endif
endif

INCLUDES = -I$(top_srcdir)/include $(openssl_cflags) $(COND_INCLUDES)

openca_scep_SOURCES = \
	scep_asn1.h \
	scep_bio.h \
	scep.h \
	scep_msg.h \
	scep_pk7.h \
	scep_sigattr.h \
	scep_asn1.c \
	scep_sigattr.c \
	scep_bio.c \
	scep_pk7.c \
	scep_msg.c \
	scep.c

openca_scep_LDADD = $(openssl_libs) $(INCLUDE_LIBS)



