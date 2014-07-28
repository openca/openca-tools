#!/bin/bash

# Used data to generate scep messages
cert=data/cert_03.pem
key=data/key_03.pem
ca=data/cacert.pem
req=data/req.pem
scep_req=scep_req.pem

# program path
prg=../../src/scep/openca-scep

# script start: let's build a brand new request
gen_req_flags=" -new -signcert ${cert} -reccert ${cert} -keyfile ${key} -CAfile ${ca} -msgtype PKCSReq -status PENDING -reqfile ${req} -out ${scep_req}"
${prg} ${gen_req_flags}

# Now we print in human readable format the message (we hope to at least!)
view_req_flags="-in ${scep_req} -text -noout"
${prg} ${view_req_flags}
