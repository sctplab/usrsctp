Name: libusrsctp
Version: 1.0.0~td109
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


%files
%defattr(-,root,root,-)
%{_libdir}/libusrsctp.so*

%files devel
%{_includedir}/usrsctp.h
%{_libdir}/libusrsctp*.a
%{_libdir}/libusrsctp*.so

%files examples
${_bindir}/libusrsctp/client
${_bindir}/libusrsctp/daytime_server
${_bindir}/libusrsctp/discard_server
${_bindir}/libusrsctp/echo_server
${_bindir}/libusrsctp/ekr_client
${_bindir}/libusrsctp/ekr_loop
${_bindir}/libusrsctp/ekr_peer
${_bindir}/libusrsctp/ekr_server
${_bindir}/libusrsctp/http_client
${_bindir}/libusrsctp/rtcweb
${_bindir}/libusrsctp/test_libmgmt
${_bindir}/libusrsctp/tsctp


%changelog
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 1.0.0
- Initial RPM release
