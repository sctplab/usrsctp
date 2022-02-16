Name: libusrsctp
Version: 1.0.0~td133
Release: 1
Summary: Portable SCTP Userland Stack
License: BSD
Group: Applications/Internet
URL: https://github.com/sctplab/usrsctp
Source: %{name}-%{version}.tar.gz

AutoReqProv: on
BuildRequires: cmake
BuildRequires: gcc-c++
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
%{_libdir}/libusrsctp.so*

%files devel
%{_includedir}/usrsctp.h
%{_libdir}/libusrsctp*.a
%{_libdir}/libusrsctp*.so

%files examples
%{_bindir}/chargen_server_upcall
%{_bindir}/client
%{_bindir}/client_upcall
%{_bindir}/daytime_server
%{_bindir}/daytime_server_upcall
%{_bindir}/discard_server
%{_bindir}/discard_server_upcall
%{_bindir}/echo_server
%{_bindir}/echo_server_upcall
%{_bindir}/ekr_client
%{_bindir}/ekr_loop
%{_bindir}/ekr_loop_offload
%{_bindir}/ekr_loop_upcall
%{_bindir}/ekr_peer
%{_bindir}/ekr_server
%{_bindir}/http_client
%{_bindir}/http_client_upcall
%{_bindir}/rtcweb
%{_bindir}/st_client
%{_bindir}/test_libmgmt
%{_bindir}/test_timer
%{_bindir}/tsctp
%{_bindir}/tsctp_upcall


%changelog
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 1.0.0
- Initial RPM release
