Summary: File system backend VMOD for Varnish
Name: vmod-fsbackend
Version: 0.1
Release: 1%{?dist}
License: BSD
Group: System Environment/Daemons
Source0: libvmod-fsbackend.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: varnish >= 4.1.0
BuildRequires: make
BuildRequires: python-docutils
BuildRequires: varnish >= 4.1.0
BuildRequires: varnish-libs-devel >= 4.1.0

%description
File system backend vmod for Varnish

%prep
%setup -n libvmod-fsbackend-trunk

%build
%configure --prefix=/usr/
%{__make} %{?_smp_mflags}
%{__make} %{?_smp_mflags} check

%install
[ %{buildroot} != "/" ] && %{__rm} -rf %{buildroot}
%{__make} install DESTDIR=%{buildroot}

%clean
[ %{buildroot} != "/" ] && %{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/varnis*/vmods/
%doc /usr/share/doc/lib%{name}/*
%{_mandir}/man?/*

%changelog
* Sun Apr 19 2015 Martin Blix Grydeland <martin@varnish-software.com> - 0.1-0.20150729
- Initial version
