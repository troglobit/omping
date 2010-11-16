# Copyright (c) 2010, Red Hat, Inc.
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

CFLAGS+=-Wall -g
DESTDIR ?= /usr/local
INSTALL_PROGRAM ?= install

PROGRAM_NAME = omping
VERSION_SH = `grep PROGRAM_VERSION omping.h | head -n 1 | sed 's/^.*\"\(.*\)\"/\1/'`

all: $(PROGRAM_NAME)

$(PROGRAM_NAME): addrfunc.o cli.o logging.o msg.o msgsend.o omping.o rhfunc.o rsfunc.o sockfunc.o tlv.o util.o
	$(CC) $(CFLAGS) $(LDFLAGS) addrfunc.o cli.o logging.o msg.o msgsend.o omping.o rhfunc.o \
	    rsfunc.o sockfunc.o tlv.o util.o -o $@

addrfunc.o: addrfunc.c addrfunc.h logging.h
	$(CC) -c $(CFLAGS) $< -o $@

cli.o: cli.c cli.h omping.h logging.h addrfunc.h
	$(CC) -c $(CFLAGS) $< -o $@

logging.o: logging.c logging.h
	$(CC) -c $(CFLAGS) $< -o $@

msg.o: msg.c msg.h logging.h tlv.h
	$(CC) -c $(CFLAGS) $< -o $@

msgsend.o: msgsend.c addrfunc.h logging.h msg.h msgsend.h omping.h rsfunc.h util.h
	$(CC) -c $(CFLAGS) $< -o $@

omping.o: omping.c logging.h addrfunc.h cli.h rhfunc.h util.h msg.h
	$(CC) -c $(CFLAGS) $< -o $@

rhfunc.o: rhfunc.c rhfunc.h addrfunc.h util.h
	$(CC) -c $(CFLAGS) $< -o $@

rsfunc.o: rsfunc.c rsfunc.h addrfunc.h logging.h util.h
	$(CC) -c $(CFLAGS) $< -o $@

sockfunc.o: sockfunc.c addrfunc.h logging.h sockfunc.h
	$(CC) -c $(CFLAGS) $< -o $@

tlv.o: tlv.c logging.h addrfunc.h util.h
	$(CC) -c $(CFLAGS) $< -o $@

util.o: util.c util.h logging.h
	$(CC) -c $(CFLAGS) $< -o $@

install: $(PROGRAM_NAME)
	test -z "$(DESTDIR)/bin" || mkdir -p "$(DESTDIR)/bin"
	$(INSTALL_PROGRAM) -c $< $(DESTDIR)/bin

uninstall:
	rm -f $(DESTDIR)/bin/$(PROGRAM_NAME)

install-strip:
	$(MAKE) INSTALL_PROGRAM="$(INSTALL_PROGRAM) -s" install

TAGS:
	ctags *.[ch]

dist:
	mkdir -p $(PROGRAM_NAME)-$(VERSION_SH)
	cp AUTHORS COPYING Makefile *.[ch] $(PROGRAM_NAME)-$(VERSION_SH)/
	tar -czf $(PROGRAM_NAME)-$(VERSION_SH).tar.gz $(PROGRAM_NAME)-$(VERSION_SH)
	rm -rf $(PROGRAM_NAME)-$(VERSION_SH)

installdirs:
	mkdir -p "$(DESTDIR)/bin"

clean:
	rm -f $(PROGRAM_NAME) *.o
