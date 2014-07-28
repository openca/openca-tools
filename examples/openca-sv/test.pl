#!/usr/bin/perl

use strict;

my $prog = "../../src/sv/openca-sv";

my $begin = "-----BEGIN PKCS7-----";
my $end   = "-----END PKCS7-----";

print STDOUT "Testing openca-sv tool ...\n";

## test encryption

print STDOUT "  Testing encryption ...\n";
my $command = "encrypt -in TEXT -cert 03.pem";
print STDOUT "    $prog $command\n";
my $ret = `$prog $command`;
if ($ret !~ /^${begin}.*${end}\n$/s)
{
    print STDOUT "    Encryption does not work properly.\n";
    exit 1;
}
print STDOUT "    Encryption works.\n";

## test decryption

print STDOUT "  Testing decryption ...\n";
my $file = "";
open FD, "<TEXT" or die "Cannot read data from file TEXT.\n";
while (<FD>)
{
    $file .= $_;
}
close FD;
my $filename = "${$}_decrypt.tmp";
open FD, ">$filename" or die "Cannot open tempfile for encrypted data.\n";
print FD $ret;
close FD;
$command = "decrypt -in $filename -out $filename.dec -keyfile 03_key.pem -cert 03.pem";
print STDOUT "    $prog $command\n";
$ret = `$prog $command`;
$ret = `diff TEXT ${$}_decrypt.tmp.dec`;
if ($ret !~ /^(\s*\n)*$/s)
{
    print STDOUT "    Decryption does not work properly.\n";
    exit 1;
}
unlink "${$}_decrypt.tmp";
unlink "${$}_decrypt.tmp.dec";
print STDOUT "    Decryption works correctly.\n";

## test signing

print STDOUT "  Testing signing ...\n";
my $command = "sign -in TEXT -keyfile 03_key.pem -cert 03.pem -nd";
print STDOUT "    $prog $command\n";
$ret = `$prog $command`;
if ($ret !~ /^${begin}.*${end}$/s)
{
    print STDOUT "    Signing does not work properly.\n";
    exit 1;
}
print STDOUT "    Signing works.\n";

## test verification

print STDOUT "  Testing verification ...\n";
open FD, ">$filename" or die "Cannot open tempfile for signed data.\n";
print FD $ret;
close FD;
$command = "verify -data TEXT -in $filename -cf cacert.pem -keyfile 03_key.pem -cert 03.pem -out TEXT.nd";
print STDOUT "    $prog $command\n";
$ret = `$prog $command`;
if ($ret !~ /depth:1 serial:00 subject:/)
{
    print STDOUT "    Verification does not work properly.\n";
    exit 1;
}
$ret = `diff TEXT TEXT.nd`;
if ($ret)
{
    print STDOUT "    The data which is attached to signature differs from the original.\n";
    exit 1;
}
unlink "${$}_decrypt.tmp";
unlink "TEXT.nd";
print STDOUT "    Verification works correctly.\n";

## test case 1 (from bug #969515)

print STDOUT "  Testing for fixed bug #969515 (sig error must be detected) ...\n";
$command = "verify -verbose -cf case_1_cacert.pem -data case_1_data.txt -in case_1_sig.pem 2>&1";
print STDOUT "    $prog $command\n";
$ret = `$prog $command`;
if ($ret !~ /digest\s+mismatch/i)
{
    print STDOUT "    Bug #969515 is still present.\n";
    exit 1;
}
print STDOUT "    Bug #969515 is fixed.\n";
1;
