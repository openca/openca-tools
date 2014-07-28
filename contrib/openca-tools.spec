# OpenCA Base Tools RPM File
# (c) 2006 by Massimiliano Pala and OpenCA Team
# OpenCA Licensed Software

# %define __find_requires %{nil}
%define debug_package %{nil}

# %define _unpackaged_files_terminate_build 0
# %define _missing_doc_files_terminate_build 0

%define is_mandrake %(test -e /etc/mandrake-release && echo 1 || echo 0)
%define is_suse %(test -e /etc/SuSE-release && echo 1 || echo 0)
%define is_fedora %(test -e /etc/fedora-release && echo 1 || echo 0)
%define is_centos  %(echo `rpm -qf /etc/redhat-release --qf '%{name} 0' 2>/dev/null | sed -e 's@centos-release@1 1@' | sed -e 's@[^ ]*@@' | awk {'print $1'}`)
%define is_ubuntu %(grep Ubuntu /etc/issue >/dev/null; if test $? -gt 0 ; then echo 0; else echo 1; fi)

%define dist redhat
%define disttag rh

%if %is_mandrake
%define dist mandrake
%define disttag mdk
%endif
%if %is_suse
%define dist suse
%define disttag suse
%define nogroup nogroup
%define httpd_usr wwwwrun
%define httpd_grp nogroup
%endif
%if %is_fedora
%define dist fedora
%define disttag rhfc
%endif

%define distver %(release="`rpm -q --queryformat='%{VERSION}' %{dist}-release 2> /dev/null | tr . : | sed s/://g`" ; if test $? != 0 ; then release="" ; fi ; echo "$release")

%if %is_ubuntu
%define dist ubuntu
%define disttag ub
%define distver %(cat /etc/issue | grep -o -e '[0-9.]*' | sed -e 's/\\.//' )
%else
%if %is_centos
%define dist centos
%define disttag el
%endif
%endif

%define packer %(finger -lp `echo "$USER"` | head -n 1 | cut -d ' ' -f 2)

%define ver      	1.3.0
%define RELEASE 	1
%define rel     	%{?CUSTOM_RELEASE} %{!?CUSTOM_RELEASE:%RELEASE}
%define prefix   	/usr
%define mand		/usr/man
%define sslprefix	/usr/local/openssl
%define openssl_req 	0.9.7
%define openldap_req 	2.2

Summary: OpenCA Base Tools
Name: openca-tools
Version: %ver
Release: %rel.%{disttag}%{distver}
License: OpenCA License (BSD Style)
Group: Network/Daemons
Source: openca-tools-%{ver}.tar.gz
BuildRoot: /var/tmp/openca-tools-%{ver}-root
URL: http://www.openca.org/projects/ocspd
Packager:  %packer
Docdir: %{prefix}/doc
Prefix: %prefix
Requires: openssl >= %openssl_req

%description
OpenCA Tools provide command line facilities for (1) digital
signatures generation and verifications and for (2) SCEP message
handling.

%prep
%setup

%ifarch alpha
  ARCH_FLAGS="--host=alpha-redhat-linux"
%endif

if [ ! -f configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh $ARCH_FLAGS --prefix=%{prefix} --with-openssl-prefix=%{sslprefix} --enable-openssl-engine --mandir=%{mand} --disable-shared
else
  DESTDIR="$RPM_BUILD_ROOT" CFLAGS="$RPM_OPT_FLAGS" ./configure $ARCH_FLAGS --prefix="%{prefix}" --with-openssl-prefix="%{sslprefix}" --enable-openssl-engine --mandir="%{mand}" --disable-shared
fi

%build

if [ "$SMP" != "" ]; then
  (make "MAKE=make -k -j $SMP"; exit 0)
  make
else
  make
fi

%install
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && rm -rf $RPM_BUILD_ROOT

echo DESTDIR="$RPM_BUILD_ROOT" prefix="%{prefix}" install # mandir="$RPM_BUILD_ROOT%{mand}" install

make DESTDIR="$RPM_BUILD_ROOT" prefix="%{prefix}" install # mandir="$RPM_BUILD_ROOT%{mand}" install

%clean
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)

%doc AUTHORS COPYING INSTALL ChangeLog NEWS README VERSION

%{prefix}/bin/*
# %{mand}/*

%post

%postun


%changelog
* Mon Oct 9 2006 Massimiliano Pala <madwolf@openca.org>
- New Package building for openca-tools
- Fixed VERSION and PACKAGE_VERSION variables

* Mon Sep 18 2006 Massimiliano Pala <madwolf@openca.org>
-First Package version (removed tools from OpenCA-Base)

