# $Id: Makefile.am,v 1.3 2000/08/17 01:50:18 proff Exp $
# $Smallcopyright: $

# location of kernel source tree
# warning. this code is completely antiquated and WILL NOT BUILD
ksrc = /sys
kern = $(ksrc)/kern

sbin_PROGRAMS = maru_mod.o
sbin_SCRIPTS = mmakedev mload munload
maru_mod_o_SOURCES = mfreebsd.c mfreebsd.h
maru_mod_o_LDADD =  ../libmcipher/libmcipher.a ../libmcommon/libmcommon.a
maru_mod_o_LDFLAGS = -r
LINK = ld $(LDFLAGS) -o $@

INCLUDES = -nostdinc -I../libmclient -I../libmcipher -I../libmcommon -I$(ksrc) -DMARU_MOD -DKERNEL -DACTUALLY_LKM_NOT_KERNEL

mfreebsd.c: machine

# bzero used in libcommon (compiled in user mode) went bozotic when
# called from the kernel). this is a hack to compile common.c from
# libcommon in kernel mode. we still link with the original
# libmcommon.a, although at this stage this does nothing because it
# only contains common.o which is over-ridden by our local common.o
# symbols

install-exec-hook:
	mv -f $(sbindir)/maru_mod.o $(libexecdir)/maru_mod.o
	strip -d $(libexecdir)/maru_mod.o

vnode_if.h: machine $(kern)/vnode_if.sh $(kern)/vnode_if.src
	sh $(kern)/vnode_if.sh $(kern)/vnode_if.src

machine:
	rm -f $(srcdir)/machine
	ln -s $(ksrc)/$(target_cpu)/include $(srcdir)/machine

load: $(modo)
	modload $<

unload:
	modunload -n 


include ../mk/rules.mk
