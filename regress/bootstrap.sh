#!/bin/sh
for n in pi rand; do
	/bin/sh encryptfile.sh pt=plaintext.$n.8192 ct=ciphertext.$n.8192 bootstrap|| exit 1
done
exit 0
