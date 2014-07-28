# file: (src/modules/openca-sv/)docs/Makefile
#
# © 2001 OpenCA Group

man_MANS 	= verify.1 sign.1
EXTRA_DIST 	= $(PODS)

POD2MAN		= @POD2MAN@
PODS		= sign.1.pod verify.1.pod
POD_MANS	= $(PODS:%.pod=%)

SUFFIXES	= .pod

#---- variable settings above, rules below ----

.PHONY:	default

all: default

default::	man

man::		$(POD_MANS)

.pod:
		$(POD2MAN) $(P2M_FLAGS) --section=1 $< > $@

