![OMPing Banner](extras/img/omping-banner.png "Open Multicast Ping")

The omping tool is a pure UDP client and server wrapped in a small
binary.  Perfectly suited for verifying multicast connectivity on your
local network.

Compared to traditional ping omping does not use ICMP.  It is based on
RFC draft <http://tools.ietf.org/html/draft-ietf-mboned-ssmping-08> and
can thus test many different aspects of a setup:

> “In addition to checking reception of multicast (SSM or ASM), the
> protocol can provide related information such as multicast tree setup
> time, the number of hops the packets have traveled, as well as packet
> delay and loss.”

Features:

- Similar user experience as classic ping tool
- Ping multiple hosts at once
- Any-source and Source-specific Multicast 


Installation
------------

### In RedHat/Fedora

Omping is available as an .rpm package in Fedora.  Use yum for
installation:

    $ yum install omping

### In Debian/Ubuntu

Not yet available in Debian or Ubuntu, but a .deb package can be built
using the sources (below):

    $ make package

There are also unsigned packages available from <ftp://troglobit.com>
for adventurous users.

### From Source

For stable version, download the latest official release from Fedora:
<https://github.com/jfriesse/omping/releases/download/0.0.4/omping-0.0.4.tar.gz>

For latest git, use

    $ git clone git://github.com/jfriesse/omping.git
	$ cd omping
	$ make


Mailing List
------------

The omping mailing list should be used for all communication relating to
Open Multicast Ping.  Please send mail to the mailing list instead of
developers directly.  This allows more then one person to respond to
information requests and allows everyone to see the solution to a
possible problem.

- ​[Subscribe mailing list](https://lists.fedorahosted.org/mailman/listinfo/omping)
- Send mail to mailing list: omping@…
- ​[View list archives](https://lists.fedorahosted.org/pipermail/omping/)


Origin & References
-------------------

This project was initially developed by Jan Friesse for Red Hat.  The
GitHub hosting at https://github.com/troglobit/omping/ is mainly for
packaging to Debian/Ubuntu.

<!--
  -- Local Variables:
  -- mode: markdown
  -- End:
  -->
