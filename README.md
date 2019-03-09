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


Articles
--------

- <https://www.ibm.com/support/knowledgecenter/en/SSWMAJ_2.0.0/com.ibm.ism.doc/Administering/ad00943_.html>


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

Latest releases at <https://github.com/troglobit/omping/releases>, for
older releases, see <https://github.com/jfriesse/omping/releases>.

For latest git, use

    $ git clone https://github.com/troglobit/omping.git
	$ cd omping/
	$ make


Origin & References
-------------------

This project was initially developed by Jan Friesse for Red Hat.  It was
hosted at the now defunct fedorahosted.org, and can now be found on Jan's
GitHub: <https://github.com/jfriesse/omping>

The https://github.com/troglobit/omping/ project is mainly for packaging
to Debian/Ubuntu but also has some minor fixes.

