# $Id: Makefile.am,v 1.7 2000/08/16 09:42:59 proff Exp $
# $Smallcopyright: $

bin_PROGRAMS = hose
hose_SOURCES = hose.c
hose_LDADD = \
	../libmclient/libmclient.a \
	../libproff/libproff.a

INCLUDES = -I../libmclient -I../libproff -I../hosed

install-exec-local:
	chown root @bindir@/hose
	chmod u+s @bindir@/hose

include ../mk/rules.mk

