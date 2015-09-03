# Copyright (c) 2010-2011, Red Hat, Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND RED HAT, INC. DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RED HAT, INC. BE LIABLE
# FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# VERSION         ?= $(shell git tag -l | tail -1)
VERSION         := `grep PROGRAM_VERSION omping.h | head -n 1 | sed 's/^.*\"\(.*\)\"/\1/'`
EXEC             = omping
OBJS             = addrfunc.o aiifunc.o cli.o cliprint.o clisig.o clistate.o gcra.o	\
		   logging.o msg.o msgsend.o omping.o rhfunc.o rsfunc.o sfset.o		\
		   sockfunc.o tlv.o util.o
PKG              = $(EXEC)-$(VERSION)
ARCHIVE          = $(PKG).tar.gz
CFLAGS          += -W -Wall -Wshadow -Wp,-D_FORTIFY_SOURCE=2 -O2

PREFIX          ?= /usr/local
BINDIR          ?= $(PREFIX)/bin
MANDIR          ?= $(PREFIX)/share/man

RM               = rm -f
CC              ?= $(CROSS)$(CC)
INSTALL         ?= install


all: $(EXEC)

all-illumos:
	@CPPFLAGS="-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D__EXTENSIONS__=1" \
	    LDLIBS="-lsocket -lnsl" $(MAKE) all

.c.o:
	@printf "  CC      $@\n"
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(EXEC): $(OBJS)
	@printf "  LINK    $@\n"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

addrfunc.o: addrfunc.c addrfunc.h logging.h
aiifunc.o: aiifunc.c addrfunc.h aiifunc.h logging.h
cli.o: cli.c cli.h addrfunc.h omping.h logging.h sockfunc.h
cliprint.o: cliprint.c cliprint.h logging.h
clisig.o: clisig.c clisig.h
clistate.o: clistate.c clistate.h logging.h
gcra.o: gcra.c gcra.h util.h
logging.o: logging.c logging.h
msg.o: msg.c msg.h logging.h omping.h tlv.h
msgsend.o: msgsend.c addrfunc.h logging.h msg.h msgsend.h omping.h rsfunc.h util.h
omping.o: omping.c addrfunc.h cli.h logging.h msg.h msgsend.h omping.h rhfunc.h rsfunc.h sockfunc.h tlv.h util.h
rhfunc.o: rhfunc.c rhfunc.h addrfunc.h util.h
rsfunc.o: rsfunc.c rsfunc.h addrfunc.h logging.h util.h
sfset.o: sfset.c logging.h sfset.h
sockfunc.o: sockfunc.c addrfunc.h logging.h sfset.h sockfunc.h
tlv.o: tlv.c logging.h addrfunc.h util.h
util.o: util.c util.h logging.h

install: $(EXEC)
	@test -z "$(DESTDIR)/$(BINDIR)" || mkdir -p "$(DESTDIR)/$(BINDIR)"
	@$(INSTALL) -c $< $(DESTDIR)/$(BINDIR)
	@test -z "$(DESTDIR)/$(MANDIR)/man8" || mkdir -p "$(DESTDIR)/$(MANDIR)/man8"
	@$(INSTALL) -c -m 0644 $<.8 $(DESTDIR)/$(MANDIR)/man8

uninstall:
	@$(RM) $(DESTDIR)/$(BINDIR)/$(EXEC)
	@$(RM) $(DESTDIR)/$(MANDIR)/man8/$(EXEC).8

install-strip:
	@$(MAKE) INSTALL="$(INSTALL) -s" install

TAGS:
	@ctags *.[ch]

clean:
	@$(RM) $(EXEC) $(OBJS)

distclean: clean
	@$(RM) *~ *.bak *.o *.map *.d DEADJOE *.gdb *.elf core core.*

package:
	@dpkg-buildpackage -b -uc -tc

dist:
	@mkdir -p $(PKG)
	@cp -a AUTHORS COPYING Makefile *.[ch] $(EXEC).8 $(EXEC).spec debian $(PKG)/
	@tar cfz $(ARCHIVE) $(PKG)
	@rm -rf $(PKG)

installdirs:
	@mkdir -p "$(DESTDIR)/bin"
