# $Id: Makefile.am,v 1.21 2001/03/28 13:25:13 proff Exp $
# $Smallcopyright:%

export MARU_PASSPHRASE_0=Thelawwillnevermakemenfreeitismenwhohavegottomakethelawfree
hose=../hose/hose
h=$(hose) -Q -f < /dev/null
commands=$(shell $h list -m commands)
commands_sgmlh=$(addsuffix .sgmlh,$(commands)) inc.sgmlh
commands_sgmlhh=$(addsuffix .sgmlhh,$(commands)) commands.sgmlhh options.sgmlhh
# we explicitly mention the following first for dependency reasons
preexamples=newkeymap newaspect newextent encryptaspect encryptfile
examples=$(addsuffix .example,$(preexamples))
examples += $(addsuffix .example,$(commands))
examples_cmd=$(addsuffix .example_cmd,$(commands))

BUILT_SOURCES = $(commands_sgmlhh) $(examples) $(examples_cmd)
CLEANFILES = $(BUILT_SOURCES) $(docs)

docs=hose.sgml hose.1 hose.man hose.html hose.dvi hose.pdf maruguide.html maruguide.dvi maruguide.pdf

EXTRA_DIST=\
	ALGORITHM \
	ARCHITECTURE \
	HACKING \
	README-manpages \
	authors.sgml \
	beatings.txt \
	copyright.sgml \
	docbook-intro.html \
	hose \
	hose.1 \
	hose.dvi \
	hose.man \
	hose.pdf \
	hose.sgml \
	hose.sgmlp \
	inc.sgmlh \
	maruguide \
	maruguide.dvi \
	maruguide.pdf \
	maruguide.sgml \
	proff.style \
	review.html \
	rfc2040.txt \
	rfc2144.txt \
	sergienko.html

man_MANS = \
	hose.1

SUFFIXES = .example_cmd .example .sgmlhh .sgmlh .sgmlp .sgml .1 .page

doc: $(docs)

maintainer-clean-local:
	rm -rf hose maruguide

hose.sgml: hose.sgmlp $(commands_sgmlh) $(commands_sgmlhh) copyright.sgml authors.sgml

inc.sgmlh:
	rm -f inc.sgmlh
	for n in $(commands); do \
		echo "#include \"$$n.sgmlh\"" >> $@ ; \
	done

speeds.sgml:
	$(h) speeds -S | tee $@

maru.plaintext:
	dd if=/dev/zero of=$@ bs=8192 count=32

encryptaspect.example: encryptaspect.example_cmd maru.plaintext

%.example_cmd:
	$(h) example -m $(basename $@) > $@

psycho.example:
	@echo "<refsect2> \
                <title>EXAMPLE</title> \
                <example> \
	          <title>Example $(basename $@)</title> \
                  <screen> \
                    <prompt>$$ </prompt> \
		    <userinput>" >$@
	@echo -n "hose " >> $@
	@echo "-d 9 -P 9 psycho" >> $@
	@echo "</userinput>" >> $@
	@echo >> $@
	$(h) -d 9 -P 9 psycho 2>&1 | expand >>$@
	@echo "    </screen> \
                </example> \
              </refsect2>" >> $@

%.example: %.example_cmd
	@echo "<refsect2> \
                <title>EXAMPLE</title> \
                <example> \
	          <title>Example $(basename $@)</title> \
                  <screen> \
                    <prompt>$$ </prompt> \
		    <userinput>" >$@
	@echo -n "hose " >> $@
	@cat $< >> $@
	@echo "</userinput>" >> $@
	@echo >> $@
	if ! fgrep -- -R $< ; then $(h) -d 1 `cat $<` < /dev/null 2>&1 |expand >>$@; fi
	@echo "    </screen> \
                </example> \
              </refsect2>" >> $@
%.sgmlhh:
	$(h) help -S $(basename $@) > $@

%.sgmlh: %.sgmlhh %.example
	echo "#include \""$(basename $@)".sgmlhh\"" > $@
	echo "#include \""$(basename $@)".example\"" >> $@

%.sgml: %.sgmlp
	cpp -P <$< >$@

%.html: %.sgml
	db2html $<

%.ps:	%.sgml
	db2ps $<

%.dvi:	%.sgml
	db2dvi $<

%.pdf:	%.sgml
	db2pdf $<

%.rtf:	%.sgml
	db2rtf $<

%.1: %.sgml
	docbook-to-man $< >$@

%.man: %.1
	groff -Tascii -man $< >$@

%.page: %.1
	groff -Tascii -man $< | $${PAGER:-less}

include ../mk/rules.mk
