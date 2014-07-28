# file: (src/openca-sv/)Makefile.global-vars.in
# contains all the configured settings
#
# © 2001 OpenCA Group

TODAY	= `/bin/date +%Y%m%d`
VERSION	= @VERSION@
MINOR   = @MINOR@
PKGNAME = @PKGNAME@
MAKEFILE = Makefile

#-------- installation paths: --------

srcdir			= @srcdir@
top_srcdir		= @top_srcdir@

BUILD_DIR		= @build_dir@
DEST_BINDIR		= @bindir@
DEST_DATADIR		= @datadir@
DEST_INFODIR		= @infodir@
DEST_LIBDIR		= @libdir@
DEST_MANDIR		= @mandir@
DEST_SBINDIR		= @sbindir@

#-------- --------

## PRG_PREFIX		= openca-
## HAVE_SHARED_LIBS	= @HAVE_SHARED_LIBS@
POD2MAN			= @POD2MAN@

#-------- user and group for installation: --------

openca_user		= @openca_user@
openca_group		= @openca_group@

openssl_libs		= @openssl_libs@
openssl_cflags		= @openssl_cflags@

OPENSSL			= @OPENSSL@

AUTOMAKE_OPTIONS = no-dependencies
SUBDIRS = src/sv src/scep src/crmf docs

AUX_DIST = \
	$(ac_aux_dir)/config.guess \
	$(ac_aux_dir)/config.sub \
	$(ac_aux_dir)/install-sh \
	$(ac_aux_dir)/ltmain.sh \
	$(ac_aux_dir)/missing \
	$(ac_aux_dir)/mkinstalldirs \
	$(ac_aux_dir)/depcomp

EXTRA_SCRIPTS = \
	contrib/autogen.sh \
	contrib/build-rpm.sh \
	contrib/openca-tools.spec.orig \
	contrib/openca-tools.spec

INCLUDE_DIST = \
	include/openca/acconfig.h 	\
	include/openca/apps.h		\
	include/openca/callback.h	\
	include/openca/config.h		\
	include/openca/crmf_asn1.h	\
	include/openca/crmf_bio.h	\
	include/openca/general.h	\
	include/openca/sv.h		\
	include/openca/tools.h		\
	include/openca/config.h.in

EXAMPLES = examples

EXTRA_DIST = $(EXAMPLES) $(TEST) $(EXTRA_SCRIPTS) $(AUX_DIST) $(INCLUDE_DIST) VERSION

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 configure \
	include/openca/config.h.in $(AUX_DIST)

test:: 

########################################################
##               BEGIN RELEASE STUFF                  ##
########################################################
 
INSTALL_BUILDER = @INSTALL_BUILDER@
DEST_DIR = `pwd`"tmp-$(PKGNAME)-$(VERSION)"
IB_OUTPUT=`find $(HOME)/installbuilder* -name output`
PACKAGE_NAME="$(PKGNAME)-$(VERSION)"
RC=1

snap:
	make -f $(MAKEFILE) source VERSION=snap-$(TODAY)

source:
	@echo
	@echo -n "Cleaning up sources if necessary ... "
	@if [ -e $(PACKAGE_NAME).tar.gz ]; then \
		rm $(PACKAGE_NAME).tar.gz; \
	fi
	@echo "done."
	@echo -n "Creating GZIP TAR archive $(PACKAGE_NAME).tar.gz ... "
	@mkdir -p /tmp/$(PKGNAME)-source-$$/$(PACKAGE_NAME)
	@tar cpf - * | tar xf - -C /tmp/$(PKGNAME)-source-$$/$(PACKAGE_NAME)
	@( \
		cd /tmp/$(PKGNAME)-source-$$ ; \
		tar cpf $(PACKAGE_NAME).tar --exclude "CVS" $(PACKAGE_NAME);\
		gzip $(PACKAGE_NAME).tar;\
	);
	@mv /tmp/$(PKGNAME)-source-$$/$(PACKAGE_NAME).tar.gz .
	@rm -rf /tmp/$(PKGNAME)-source-$$
	@echo "done."
	@echo

rpm: rpmbuild

rpmbuild:
	@echo
	@echo -n "Cleaning up old RPMs ... "
	@for i in $(PKGNAME)*.rpm ; do \
                rm -f $$i ; \
        done
	@echo "Done."
	@echo -n "Creating spec file ... " ; \
	filename=openca-tools.spec.orig ; \
	if [ -e "contrib/$$filename" ] ; then \
		echo "($$filename)"; \
		cat "contrib/$$filename" | \
			sed -e "s/\@VERSION\@/$(VERSION)/g" | \
			sed -e "s/\@MINOR\@/$(MINOR)/g" | \
			sed -e "s/\@PKGNAME\@/$(PKGNAME)/g" | \
			sed -e "s|\@BUILDROOT\@|/var/tmp/$(PKGNAME)-%{ver}-root|g" > \
			"contrib/openca-tools.spec" ; \
	else \
		echo "contrib/$$filename ... not found" ; \
		exit 1 ; \
	fi ; \
	make -f $(MAKEFILE) dist ; \
	echo "Building RPM package(s)... " ; \
	echo "%_topdir /var/tmp/rpm" > ~/.rpmmacros ; \
	if [ -d "/var/tmp/rpm" ] ; then \
		rm -rf "/var/tmp/rpm" ; \
	fi ; \
	mkdir -p /var/tmp/rpm/BUILD  \
			/var/tmp/rpm/RPMS \
			/var/tmp/rpm/RPMS/athlon \
			/var/tmp/rpm/RPMS/i386  \
			/var/tmp/rpm/RPMS/i486  \
			/var/tmp/rpm/RPMS/i586  \
			/var/tmp/rpm/RPMS/i686  \
			/var/tmp/rpm/RPMS/noarch \
			/var/tmp/rpm/SOURCES  \
			/var/tmp/rpm/SPECS  \
			/var/tmp/rpm/SRPMS ; \
	rpmbuild -tb $(PACKAGE_NAME).tar.gz ; \
	mv /var/tmp/rpm/RPMS/*/$(PKGNAME)*.rpm . ; \
	rm ~/.rpmmacros ; \
	echo


pkgbuild: 
	@rm -rf "$(DEST_DIR)"
	@DESTDIR="$(DEST_DIR)" ./configure --prefix=/usr
	@$(MAKE) -f Makefile
	@$(MAKE) DESTDIR="$(DEST_DIR)" install
	@$(MAKE) -f Makefile pkgconfig

pkgconfig:
	@if [ "$(DIST_NAME)" = "darwin" ] ; then \
		IB_OUTPUT=`find $(HOME)/installbuilder*/ -maxdepth 1 -name output` ; \
		rm -rf $(PACKAGE_NAME)-*.app ; \
		$(INSTALL_BUILDER) build contrib/install-builder/$(PKGNAME).xml && \
		hdiutil create -srcfolder "$$IB_OUTPUT" \
			-volname "$(PACKAGE_NAME) v$(VERSION) Install" \
			"$(PACKAGE_NAME)-$(VERSION)-osx-$(ARCH_TARGET).dmg" ; \
		rm -r $$IB_OUTPUT/$(PACKAGE_NAME)-*.app ; \
	else \
		ret=`echo ${build_os} | grep 'solaris'`; \
		if [ $$? -eq 0 ] ; then \
		   IB_OUTPUT=`find $(HOME)/installbuilder*/* -name output` ; \
		else \
		   IB_OUTPUT=`find $(HOME)/installbuilder*/ -maxdepth 1 -name output` ; \
		fi ; \
		sudo $(INSTALL_BUILDER) build contrib/install-builder/$(PKGNAME).xml && \
		$(SHELL) -c "cp -r $$IB_OUTPUT/$(PACKAGE_NAME)-* ." ; \
			$(SHELL) -c "sudo rm -f $$IB_OUTPUT/$(PACKAGE_NAME)-*" ; \
	fi

# pkgconfig:
# 	@if [ "$(DIST_NAME)" = "darwin" ] ; then \
# 		rm -rf $(PACKAGE_NAME)-*.app ; \
# 		$(INSTALL_BUILDER) build contrib/install-builder/$(PKGNAME).xml && \
# 		$(SHELL) -c "cp -r "$(IB_OUTPUT)/$(PKGNAME)-*" ." ; \
# 		o=`find . -name $(PKGNAME)-*.app` ; \
# 		zip -rq "$$o.zip" "$$o" && rm -rf "$$o" ; \
# 		rm -r $(IB_OUTPUT)/$$o ; \
# 	else \
# 		sudo $(INSTALL_BUILDER) build contrib/install-builder/$(PKGNAME).xml && \
# 		$(SHELL) -c "cp -r "$(IB_OUTPUT)/$(PKGNAME)-*" ." ; \
# 			$(SHELL) -c "rm -f $(IB_OUTPUT)/$(PKGNAME)-*" ; \
# 	fi

#	rm -rf /usr/src/redhat/BUILD/$(PKGNAME)* ;

########################################################
##                END RELEASE STUFF                   ##
########################################################

#	@echo -n "Creating spec file ... " ; \
#	filename=openca-tools.spec.orig ; \
#	if [ -e "contrib/$$filename" ] ; then \
#		echo "($$filename)"; \
#		cat "contrib/$$filename" | \
#			sed -e "s/\@VERSION\@/$(VERSION)/g" | \
#			sed -e "s/@MINOR@/$(MINOR)/g" | \
#			sed -e "s/@PKGNAME@/$(PKGNAME)/g" | \
#			sed -e "s|@BUILDROOT@|/var/tmp/$(PKGNAME)-%{ver}-root|g" > \
#			"contrib/openca-tools.spec" ; \
#	else \
#		echo "contrib/$$filename ... not found" ; \
#		exit 1 ; \
#	fi ;
