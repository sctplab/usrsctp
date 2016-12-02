Name: libusrsctp
Version: 1.0.0~td105
Release: 1
Summary: Portable SCTP Userland Stack
License: BSD
Group: Applications/Internet
URL: https://github.com/sctplib/usrsctp
Source: https://github.com/sctplib/usrsctp

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
cmake -DCMAKE_INSTALL_PREFIX=/usr .

%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%clean
rm -rf "$RPM_BUILD_ROOT"

%files
%defattr(-,root,root,-)
%{_libdir}/libusrsctp.so*

%files devel
%{_includedir}/usrsctp.h
%{_libdir}/libusrsctp*.a
%{_libdir}/libusrsctp*.la
%{_libdir}/libusrsctp*.so

%files examples
%{_bindir}/cspmonitor
%{_bindir}/hsdump
%{_bindir}/rspserver
%{_bindir}/rspterminal


%changelog
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 1.0.0
- Initial RPM release
