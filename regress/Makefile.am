scripts=psycho9.sh encryptfilecheck.sh creation.sh
TESTS=list_test $(scripts)

plaintexts = \
	plaintext.rand.8192 \
	plaintext.pi.8192

ciphertexts = \
ciphertext.pi.8192.bcopy		ciphertext.rand.8192.bcopy \
ciphertext.pi.8192.cast-cbc		ciphertext.rand.8192.cast-cbc \
ciphertext.pi.8192.idea-cbc		ciphertext.rand.8192.idea-cbc \
ciphertext.pi.8192.rc16			ciphertext.rand.8192.rc16 \
ciphertext.pi.8192.ssl-blowfish-cbc	ciphertext.rand.8192.ssl-blowfish-cbc \
ciphertext.pi.8192.ssl-cast-cbc		ciphertext.rand.8192.ssl-cast-cbc \
ciphertext.pi.8192.ssl-des-cbc		ciphertext.rand.8192.ssl-des-cbc \
ciphertext.pi.8192.ssl-des-ede-cbc	ciphertext.rand.8192.ssl-des-ede-cbc \
ciphertext.pi.8192.ssl-des-ede3-cbc	ciphertext.rand.8192.ssl-des-ede3-cbc \
ciphertext.pi.8192.ssl-desx-cbc		ciphertext.rand.8192.ssl-desx-cbc \
ciphertext.pi.8192.ssl-idea-cbc		ciphertext.rand.8192.ssl-idea-cbc \
ciphertext.pi.8192.ssl-rc2-cbc		ciphertext.rand.8192.ssl-rc2-cbc \
ciphertext.pi.8192.ssl-rc4		ciphertext.rand.8192.ssl-rc4 \
ciphertext.pi.8192.ssl-rc5-cbc		ciphertext.rand.8192.ssl-rc5-cbc \
ciphertext.pi.8192.xor			ciphertext.rand.8192.xor

noinst_SCRIPTS = $(scripts) bootstrap.sh encryptfile.sh

EXTRA_DIST = \
	$(noinst_SCRIPTS) \
	$(plaintexts) \
	$(ciphertexts)

noinst_PROGRAMS = list_test pi
list_test_SOURCES = list_test.c
LIBS = ../libmclient/libmclient.a
pi_SOURCES = pi.c

INCLUDES = -I../libmclient

creation_done: creation.sh
	sh $(srcdir)/creation.sh

psycho9_done: psycho9.sh
	sh $(srcdir)/psycho9.sh

# why pi as a plaintext test vector?
# pi is the same everywhere in the universe, and with the exception of blowfish
# sbox's has no conceivable cryptographic relation. it is constrained in the
# sense that it could not have been arbitary chosen to hide trapdoors in the
# cryptographic process, and is universally verifiable
plaintext.pi.8192: pi
	./pi > $@

# we also include a purely random testvector just in case there is some
# magical relation between cipher maths and arctangents
plaintext.rand.8192: 
	dd if=/dev/urandom of=$@ bs=8192 count=1

bootstrap: bootstrap.sh $(plaintexts)
	sh $(srcdir)/bootstrap.sh
