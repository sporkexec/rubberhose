# $Id: Makefile.am,v 1.5 2000/08/17 02:12:27 proff Exp $
# $Smallcopyright: $

# location of kernel source tree
ksrc = /sys

sbin_PROGRAMS = maru.o kue.o
sbin_SCRIPTS = mmakedev mload munload
maru_o_SOURCES = nbsd_maru.c nbsd_maru.h lkminit_maru.c mnetbsd.h nbsd_kue.ext nbsd_maru.ext
#maru_o_LDADD =  ../libmcipher/libmcipher.a ../libmcommon/libmcommon.a
maru_o_LDFLAGS = -r

kue_o_SOURCES = lkminit_kue.c nbsd_kue.c nbsd_kue.h kue.h
kue_o_LDFLAGS = -r

LINK = ld $(LDFLAGS) -o $@

INCLUDES = -nostdinc -I../libmclient -I../libmcipher -I../libmcommon -I$(ksrc) -DMARU_MOD -DKERNEL -D_KERNEL -DLKM -D_LKM -DUVM -DPMAP_NEW

lint:
	lint $(INCLUDES) $(maru_o_SOURCES) $(kue_o_SOURCES)

install-exec-hook:
	mv -f $(sbindir)/maru.o $(libexecdir)/maru.o
	strip -d $(libexecdir)/maru.o

machine: .$(target_cpu) $(target_arch)
	-rm -f $(srcdir)/machine && ln -s $(ksrc)/arch/$(target_cpu)/include $(srcdir)/machine

.$(target_cpu):
	-rm -f .$(target_cpu) && touch .$(target_cpue)

$(target_arch):
	-rm -f $(srcdir)/machine && ln -s $(ksrc)/arch/$(target_arch)/include $(srcdir)/$(target_arch)

load: $(moru)
	modload $<

unload:
	modunload -n 

include ../mk/rules.mk
