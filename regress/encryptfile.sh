#!/bin/sh
hose="../hose/hose -Q -d 9"
MARU_PASSPHRASE=BeamingScientistsLastWeekShowedOff
export MARU_PASSPHRASE
bs=8192

ciphers=`$hose list -m ciphers`

danger () {
    echo Danger Will - $*
    exit 1
}

encrypt () {
    src=$1
    dst=$2
    for n in $ciphers; do
	echo $hose encryptfile $src $dst.$n
	$hose encryptfile $src $dst.$n || danger hose encryptfile is unahppy
    done
}

encrypt_compare () {
    src=$1
    dst=$2
    orig=$3
    for n in $ciphers; do
	echo $hose encryptfile $src $dst.$n
	$hose encryptfile $src $dst.$n || danger hose decryptfile is unhappy
	if ! cmp $orig.$n $dst.$n; then
	    danger $orig does not equal $dst.$n
	fi
	rm -f $dst.$n
    done
}

decrypt_compare () {
    src=$1
    dst=$2
    orig=$3
    for n in $ciphers; do
	echo $hose decryptfile $src.$n $dst.$n
	$hose decryptfile $src.$n $dst.$n || danger hose decryptfile is unhappy
	if ! cmp $orig $dst.$n; then
	    danger $orig does not equal $dst.$n
	fi
	rm -f $dst.$n
    done
}

bootstrap () {
    encrypt $pt $ct
    decrypt_compare $ct $pt.tmp $pt
    echo bootstrap succeeded
}

check () {
    encrypt_compare $pt $ct.tmp $ct
    decrypt_compare $ct $pt.tmp $pt
    echo 'All encrypt/decrypt file tests passed!'
}

eval $*
exit 0
