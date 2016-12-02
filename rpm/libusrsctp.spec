Name: libusrsctp
Version: 1.0.0~td105
Release: 1
Summary: Portable SCTP Userland Stack
License: BSD
Group: Applications/Internet
URL: https://github.com/sctplib/usrsctp
Source: %{name}-%{version}.tar.gz

AutoReqProv: on
BuildRequires: cmake
BuildRoot: %{_tmppath}/%{name}-%{version}-build

%description
This is a userland SCTP stack supporting FreeBSD, Linux, Mac OS X and Windows.


%package devel
Summary: Portable SCTP Userland Stack (Development Files)
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
 This is a userland SCTP stack supporting FreeBSD, Linux, Mac OS X and Windows.
 This package contains the shared library for the Portable SCTP Userland Stack.


%package examples
Summary: Portable SCTP Userland Stack (Examples)
Group: Applications/Internet
Requires: %{name} = %{version}-%{release}
Requires: %{name}-docs
Requires: chrpath

%description examples
 This is a userland SCTP stack supporting FreeBSD, Linux, Mac OS X and Windows.
 This package contains the examples for the Portable SCTP Userland Stack.


%prep
%setup -q

%build
%cmake -DCMAKE_INSTALL_PREFIX=/usr .
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

#%clean
#rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(-,root,root,-)
/usr/lib/libusrsctp.so*

%files devel
/usr/include/usrsctp.h
/usr/lib//libusrsctp*.a
/usr/lib/libusrsctp*.so

%files examples
/usr/bin/client
/usr/bin/datachan_serv
/usr/bin/daytime_server
/usr/bin/discard_server
/usr/bin/echo_server
/usr/bin/ekr_client
/usr/bin/ekr_loop
/usr/bin/ekr_peer
/usr/bin/ekr_server
/usr/bin/http_client
/usr/bin/rtcweb
/usr/bin/test_libmgmt
/usr/bin/tsctp

%changelog
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 1.0.0
- Initial RPM release
