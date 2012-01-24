# $Id: Makefile.am,v 1.15 2000/08/18 09:46:04 proff Exp $
# $Smallcopyright:$


# ugly -- any simpler way to handle these conditionals in automake?

if mlinux
mkernel = mkernel.linux
else
if mfreebsd 
mkernel = mkernel.freebsd
else
if mnetbsd
mkernel = mkernel.netbsd
endif
endif
endif

SUBDIRS = mk libproff confused libmclient hose hosed $(mkernel) regress ideas doc

EXTRA_DIST = \
	unamep unamep.make ACKNOWLEDGEMENTS AUTHORS ENUMAELISH FAQ \
	FEATURES MYTHOLOGY PATENTS ChangeLog SECURITY

SUFFIXES = .c .ext

pv=@PACKAGE@-@VERSION@
wdist=www/dist/$(pv)

tovm:
	tovm ../marutukku

htags:
	gtags
	mkdir -p $(wdist)
	htags -t "@PACKAGE@-@VERSION@ source code world tour!" $(wdist)
	mv $(wdist)/HTML $(wdist)/$(pv)-html
	ln -s $(pv)-html $(wdist)/src_tour

cleanwdist:
	rm -rf www/dist

web: cleanwdist htags dist
	rm -rf www/current
	ln -s dist/$(pv) www/current
	mkdir -p $(wdist)
	cp $(pv).tar.gz $(wdist)
	cd $(wdist) && tar -zxf $(pv).tar.gz
	ln -s $(pv) $(wdist)/src
	chmod -R a+r www
	find www -type d | xargs chmod a+rx

syncweb:
	cd www && rsync -Cavz -e ssh . proff@suburbia.com.au:www/rubberhose.org

include mk/rules.mk
