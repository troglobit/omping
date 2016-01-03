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
DEPS            := $(OBJS:.o=.d)
PKG              = $(EXEC)-$(VERSION)
ARCHIVE          = $(PKG).tar.gz
CFLAGS          += -O2
CPPFLAGS        += -W -Wall -Wshadow -Wp,-D_FORTIFY_SOURCE=2

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

# Pretty printing and GCC -M for auto dep files
.c.o:
	@printf "  CC      $@\n"
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c -MMD -MP -o $@ $<

$(EXEC): $(OBJS)
	@printf "  LINK    $@\n"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

install-exec: $(EXEC)
	@test -z "$(DESTDIR)/$(BINDIR)" || mkdir -p "$(DESTDIR)/$(BINDIR)"
	@$(INSTALL) -c $< $(DESTDIR)/$(BINDIR)

install-data:
	@test -z "$(DESTDIR)/$(MANDIR)/man8" || mkdir -p "$(DESTDIR)/$(MANDIR)/man8"
	@$(INSTALL) -c -m 0644 $<.8 $(DESTDIR)/$(MANDIR)/man8

install: install-exec install-data

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
	@cp -a README.md AUTHORS COPYING Makefile *.[ch] $(EXEC).8 $(EXEC).spec debian extras $(PKG)/
	@tar cfz $(ARCHIVE) $(PKG)
	@rm -rf $(PKG)

installdirs:
	@mkdir -p "$(DESTDIR)/bin"

# Include automatically generated rules
-include $(DEPS)
