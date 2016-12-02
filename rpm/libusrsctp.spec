Name: libusrsctp
Version: 1.0.0~td107
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
/usr/lib/libusrsctp/client
/usr/lib/libusrsctp/datachan_serv
/usr/lib/libusrsctp/daytime_server
/usr/lib/libusrsctp/discard_server
/usr/lib/libusrsctp/echo_server
/usr/lib/libusrsctp/ekr_client
/usr/lib/libusrsctp/ekr_loop
/usr/lib/libusrsctp/ekr_peer
/usr/lib/libusrsctp/ekr_server
/usr/lib/libusrsctp/http_client
/usr/lib/libusrsctp/rtcweb
/usr/lib/libusrsctp/test_libmgmt
/usr/lib/libusrsctp/tsctp

%changelog
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 1.0.0
- Initial RPM release
