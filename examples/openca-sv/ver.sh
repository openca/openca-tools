#!/bin/sh

prg=../../src/sv/openca-sv
vf_flags="-in pippo.p7 -print_data -cf cacert.pem -verbose"

$prg verify $vf_flags

exit 0;
