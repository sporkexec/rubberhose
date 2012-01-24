#!/bin/sh
# $Id: creation.sh,v 1.13 2000/05/15 08:36:38 proff Exp $
# $Smallcopyright:$

log=creation.log
rm -f $log

h="../hose/hose -Q -d 9"
pass=youcanalwayscountonamurdererforafancyprosestyle

#XXX non cbc ciphers
ciphers=`$h list -m ciphers`

#block size (in bytes)
bs=2048
#number of blocks in each aspect
ablocks=64

aspects=0
for cipher in $ciphers; do
    aspects=$(($aspects + 1))
done
#number of blocks in extent
eblocks=$(($aspects * $ablocks))

danger () {
    echo Danger Will - $*
    echo See \"$log\" for details
    exit 1
}

decrypt_aspect () {
    echo
    aspect=$1
    cipher=$2
    echo decrypting "($cipher)" $ablocks x $bs bytes from aspect $aspect to maru.out.$aspect
    $h  decryptaspect -o maru.out.$aspect -a $aspect </dev/null >>$log 2>&1 || danger decryption failed
    echo comparing maru.in.$aspect with maru.out.$aspect
    if ! cmp maru.in.$aspect maru.out.$aspect >>$log 2>&1; then
	danger maru bits sold out to evil forces
    fi
    rm -f maru.out.$aspect
    echo we have achieved equality
}

encrypt_aspect () {
    echo
    aspect=$1
    cipher=$2
    in=$3
    echo encrypting \($cipher\) $ablocks x $bs bytes from $in to aspect $aspect
    $h encryptaspect -i $in -a $aspect </dev/null >>$log 2>&1 || danger encryption failed
    $h remapinfo </dev/null >>$log 2>&1 || danger remapinfo failed
    echo encryption successful
}

do_aspect () {
    echo
    aspect=$1
    cipher=$2
    echo creating maru.in.$aspect $ablocks x $bs byte random test file
    dd if=/dev/urandom of=maru.in.$aspect bs=$bs count=$ablocks >>$log 2>&1 || danger couldn\'t create maru.in.$aspect
    eval MARU_PASSPHRASE_$aspect=$pass$cipher$aspect
    eval export MARU_PASSPHRASE_$aspect
    echo creating new aspect $aspect \($cipher\)
    $h newaspect -t 0 -2 $cipher -3 $cipher -a $aspect -s $ablocks >>$log 2>&1|| danger newaspect failed
}

do_keymap () {
    remap=$1
    echo creating new keymap, remap = $remap
    $h newkeymap -A $aspects -b $bs -s $eblocks -r $remap >>$log 2>&1 || danger newkeymap failed
    echo creating new $eblocks x $bs byte extent
    $h newextent -b $bs -s $eblocks -w 0 >>$log 2>&1 || danger new extent failed
}

# we should test the 'none' type too
for remap in `$h list -m remaps | egrep -v none | sort`; do
    rm -f maru.keymap
    rm -f maru.extent
    rm -f maru.in.*
    rm -f maru.out.*

    dd if=/dev/zero of=maru.in.zeros bs=$bs count=$ablocks >>$log 2>&1 || danger couldn\'t create maru.in.zeros

    unset MARU_PASSPHRASE
    n=0;
    for cipher in $ciphers; do
	eval unset MARU_PASSPHRASE_$n
	n=$(($n + 1))
    done

    do_keymap $remap
    echo
    echo "Starting $remap pass 1 -- incremental addition and encryption of aspects"
    n=0
    for cipher in $ciphers; do
	do_aspect $n $cipher
        encrypt_aspect $n $cipher maru.in.$n
	n=$(($n + 1))
    done
    n=0
    echo
    echo "Starting $remap pass 2 -- decryption of incrementally created aspects"
    for cipher in $ciphers; do
	decrypt_aspect $n $cipher
	n=$(($n + 1))
    done
    n=0
    echo
    echo "Starting $remap pass 3 -- re-encryption of all aspects from zero block data"
    for cipher in $ciphers; do
        encrypt_aspect $n $cipher maru.in.zeros
	n=$(($n + 1))
    done
    echo
    echo "Starting $remap pass 4 -- re-encryption of all aspects"
    n=0
    for cipher in $ciphers; do
        encrypt_aspect $n $cipher maru.in.$n
	n=$(($n + 1))
    done
    echo
    echo "Starting $remap pass 5 -- decryption of all aspects"
    n=0
    for cipher in $ciphers; do
	decrypt_aspect $n $cipher
	n=$(($n + 1))
    done
    rm -f maru.keymap
    rm -f maru.extent
    rm -f maru.in.*
done

mv $log creation_done

echo Heyho! passed aspect creation, encryption, zeroing, decryption tests with flying colours!

exit 0
