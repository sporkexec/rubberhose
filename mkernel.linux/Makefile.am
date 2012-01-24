# $Id: Makefile.am,v 1.13 2000/08/17 02:34:49 proff Exp $
# $Smallcopyright: $

# location of kernel source tree
#ksrc = /usr/src/linux
ksrc = /usr/src/linux

sbin_SCRIPTS = hose_makedevs hose_modload hose_modunload

sbin_PROGRAMS = maru.o kue.o kanook.o

headers=linux_compat.h queue.h kue_linux.ext

kue_o_SOURCES = kue_linux.c kue_linux.h kue-api.h $(headers)
maru_o_SOURCES = maru_linux.c maru_linux.h $(headers)
kanook_o_SOURCES = kanook_linux.c $(headers)

DEFS = -D__KERNEL__ -DMODULE -DMARU_MOD -DDEBUG
CFLAGS = -O6 -Wall
INCLUDES = -I${ksrc}/include -I../libmclient
LDFLAGS = -r -nostdlib
LIBS = 

include ../mk/rules.mk
