Name: omping
Version: 0.0.1
Release: 1%{?dist}
Summary: Utility to test IP multicast functionality
Group: Applications/Internet
License: ISC
URL: http://fedorahosted.org/omping/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
Omping (Open Multicast Ping) is tool to test IP multicast functionality
primarily in local network.

%prep
%setup -q

%build
make %{?_smp_mflags} CFLAGS="%{optflags}"

%install
rm -rf %{buildroot}
make DESTDIR="%{buildroot}" PREFIX="/usr" install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING
%{_bindir}/%{name}
%{_mandir}/man8/*

%changelog
* Fri Nov 19 2010 Jan Friesse <jfriesse@redhat.com> - 0.0.1-1
- Initial package for Fedora
