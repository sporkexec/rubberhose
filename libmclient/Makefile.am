# $Id: Makefile.am,v 1.15 2000/08/17 02:57:44 proff Exp $
# $Smallcopyright: $


if SSLEAY
mssleay = mSSLeay.c
else
mssleay =
endif

ciphers = ciphers.c idea.c rc16.c mcast.c cast.c mxor.c mbcopy.c blowfish.c cipher_tests.c $(mssleay)

BUILT_SOURUCS = conf.c conf.h quotes.qh

headers=\
assert.h	    encoding.h	     maru.h	       pipeline.h	\
block.h		    getpassphrase.h  maru_bsd_ioctl.h  psycho.h		\
blowfish.h	    haval.h	     maru_config.h     psycho_unix.h	\
bsdioctl.h	    havalapp.h	     maru_types.h      rc16.h		\
cast.h		    idea.h	     maru_version.h    rc5.h		\
cast_sboxes.h	    idea_lcl.h	     mbcopy.h	       remap.h		\
cipher_tests.h	    ipc_commands.h   mbsdioctl.h       remap_bmap.h	\
ciphers.h	    kue-api.h	     mcast.h	       remap_none.h	\
client_assert.h     kue_bsd_ioctl.h  mevp.h	       remap_splice.h	\
client_common.h     libmclient.h     mkern-api.h       remappers.h	\
common.h	    list.h	     mquote.h	       version.h	\
confused_runtime.h  mSSLeay.h	     mxor.h

ext=$(wildcard *.ext)

EXTRA_DIST=quotes.txt

noinst_LIBRARIES = libmclient.a
libmclient_a_SOURCES =\
	conf.c \
	conf.h \
	conf.cf \
	quotes.qh \
	$(ext) \
	$(headers) \
	$(ciphers) \
	block.c \
	client_assert.c \
	client_common.c \
	common.c \
	confused_runtime.c \
	encoding.c \
	getpassphrase.c \
	list.c \
	mquote.c \
	psycho.c \
	psycho_unix.c \
	remap.c \
	remap_bmap.c \
	remap_none.c \
	remap_splice.c \
	remappers.c \
	version.c

INCLUDES = -I../libmcommon -I../libproff
SUFFIXES = .txt .qh

%.qh: %.txt
	$(AWK) <$< >$@ -f $(srcdir)/makequotes.awk 

include ../mk/rules.mk