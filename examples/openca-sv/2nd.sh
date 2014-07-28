../bin/sv sign2nd -in TEXT.sig -verbose -data TEXT -out pippo.p7 -print_data
../bin/sign -in TEXT -out pippo2.p7 -cert 03.pem -keyfile 03_key.pem -verbose -nd
