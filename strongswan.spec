Name: strongswan-bf
Version: 5.9
Release: 1%{?dist}
Summary: BlueField Strongswan Package

License: BSD and GPLv2+ and MIT and Expat
Url: https://github.com/Mellanox/strongswan.git
Source: %{name}-%{version}.tgz

BuildRequires: binutils
BuildRequires: openssl-devel
BuildRequires: gmp-devel
BuildRequires: gettext-devel
BuildRequires: pkgconfig
BuildRequires: perl
BuildRequires: gperf
BuildRequires: bison
BuildRequires: flex
BuildRequires: libtool
BuildRequires: gcc >= 3

%description
The strongSwan IPsec implementation supports both IKEv1 IKEv2 key
exchange protocols in conjunction with the native NETKEY IPsec stack of the
Linux Kernel.

%prep
%setup

%build
%configure \
	--enable-openssl \
	--disable-random \
	--prefix=%{_prefix} \
	--sysconfdir=%{_sysconfdir}
%make_build

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls
%if 0%{?rhel} == 7
	cp openssl-conf/CentOS7/openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf.mlnx
%endif
%if 0%{?rhel} == 8
	cp openssl-conf/CentOS8/openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf.mlnx
%endif

%preun
cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.mlnx
cp /etc/pki/tls/openssl.cnf.orig /etc/pki/tls/openssl.cnf

%post
cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.orig
cp /etc/pki/tls/openssl.cnf.mlnx /etc/pki/tls/openssl.cnf

%files
%defattr(-, root, root)
/usr/lib64/ipsec
/usr/bin/dh_speed
/usr/bin/pubkey_speed
/usr/bin/pki
/usr/sbin/swanctl
/usr/sbin/ipsec
/usr/libexec/ipsec
%{_sysconfdir}/
%{_datadir}/
/usr/lib/systemd/system/strongswan-starter.service

%doc COPYING TODO NEWS INSTALL HACKING README
%license LICENSE
