# file: (src/modules/openca-sv/)src/Makefile
## OpenCA-SV Makefile - by Massimiliano Pala
## 2000/2001 OpenCA Licensed Released Software
## All Rights Reserved

if ARCH_LINUX
MYLDFLAGS      =
INCLUDE_LIBS   = -ldl
else
if ARCH_BSD
MYLDFLAGS      =
INCLUDE_LIBS   = 
else
if ARCH_OSX
MYLDFLAGS      = -framework CoreFoundation
INCLUDE_LIBS   = -ll -lIOKit
COND_INCLUDES  = -I/System/Library/Frameworks/IOKit.framework/Headers/usb \
            -I/System/Library/Frameworks/IOKit.framework/Headers
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

bin_PROGRAMS = openca-crmf
INCLUDES = -I$(top_srcdir)/include $(COND_INCLUDES) $(openssl_cflags)

openca_crmf_SOURCES =  \
	crmf_asn1.c \
	crmf_bio.c \
	crmf.c

openca_crmf_LDADD   = $(openssl_libs) $(INCLUDE_LIBS)

