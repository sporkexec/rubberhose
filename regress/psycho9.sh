#!/bin/sh
danger () {
    echo Danger Will - $*
    exit 1
}
(../hose/hose -Q -d 9 -P 9 psycho 2>&1 | tee psycho9.log) || danger failed psychoanalysis
echo hose passed maru psychoanalysis level 9
mv psycho9.log psycho9_done
exit 0
