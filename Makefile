CFLAGS:= -ggdb -O2 -Wall -pipe -D_GNU_SOURCE --std=c99
CXXFLAGS:= -ggdb -O2 -Wall -pipe -D_GNU_SOURCE -Wno-write-strings

OUT_DIR:=	.
PREFIX:=	/usr/local

#
# Target aliases
#

SLICER:=	$(OUT_DIR)/ginsu-slicer
CAPTURE:=	$(OUT_DIR)/ginsu-capture


TARGETS:=	$(CAPTURE) $(SLICER)

.PHONY:		all clean install

all:		$(TARGETS)

clean:
	rm -f $(TARGETS)
	find . -name "*.[oa]" -o -name "core" | xargs rm -f

##########################################################################
##########################################################################

SLICER_SRC:=	ginsu config

SLICER_OBJ:=	$(SLICER_SRC:=.o)

SLICER_OBJ:	ginsu.h

$(SLICER):	$(SLICER_OBJ)
	g++ -o $@ $(SLICER_OBJ) -lpcap -lpcapnav -lconfuse


##########################################################################
##########################################################################

CAPTURE_SRC:=	capture

CAPTURE_OBJ:=	$(CAPTURE_SRC:=.o)

$(CAPTURE):	$(CAPTURE_OBJ)
	g++ -o $@ $(CAPTURE_OBJ) -lpcap -lpcapnav

##########################################################################
##########################################################################

install:	$(CAPTURE) $(GINSU)
	install -m 755 -o root -g root $(SLICER) $(PREFIX)/bin/`basename $(SLICER)`
	install -m 755 -o root -g root $(CAPTURE) $(PREFIX)/bin/`basename $(CAPTURE)`
	install -m 755 -o root -g root ginsu-pruner.pl $(PREFIX)/bin/ginsu-pruner
	install -m 755 -o root -g root gentoo-init-script /etc/init.d/ginsu-capture
	if [ ! -f /etc/conf.d/ginsu-capture ]; then install -m 644 -o root -g root gentoo-conf /etc/conf.d/ginsu-capture; fi
