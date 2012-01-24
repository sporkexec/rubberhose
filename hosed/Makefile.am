# $Id: Makefile.am,v 1.9 2000/08/17 02:12:22 proff Exp $
# $Smallcopyright: $

bin_PROGRAMS = hosed
hosed_SOURCES =\
	hosed.c hosed.h \
	block.c block.h block.ext

hosed_LDADD = ../libmclient/libmclient.a ../libproff/libproff.a

INCLUDES = -I../libmclient -I../libproff

install-exec-local:
	chown root @bindir@/hosed
	chmod u+s @bindir@/hosed

include ../mk/rules.mk
