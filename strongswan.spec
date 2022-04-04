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

Obsoletes: libreswan

%package -n strongswan-swanctl
Summary: Placeholder package for strongswan-swanctl for dependency resolution
%description -n strongswan-swanctl
This package contains the swanctl interface, used to configure a running
charon daemon

%description
The strongSwan IPsec implementation supports both IKEv1 IKEv2 key
exchange protocols in conjunction with the native NETKEY IPsec stack of the
Linux Kernel.

%files -n strongswan-swanctl

%prep
%setup
cp -f systemd-conf/strongswan-starter.service.in.centos init/systemd-starter/strongswan-starter.service.in

%build
%configure \
	--enable-openssl \
	--disable-random \
	--prefix=%{_prefix} \
	--sysconfdir=%{_sysconfdir} \
	--enable-systemd
%make_build

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls
%if 0%{?rhel} == 7
	cp -f openssl-conf/CentOS7/openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf.mlnx
%endif
%if 0%{?rhel} == 8
	cp -f openssl-conf/CentOS8/openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf.mlnx
%endif
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/etc/swanctl/conf.d
cp -f mlnx-conf/BFL.swanctl.conf $RPM_BUILD_ROOT%{_sysconfdir}/swanctl/conf.d
cp -f mlnx-conf/BFR.swanctl.conf $RPM_BUILD_ROOT%{_sysconfdir}/swanctl/conf.d

%preun
cp -f /etc/pki/tls/openssl.cnf.orig /etc/pki/tls/openssl.cnf
systemctl disable strongswan-starter.service

%post
cp -f /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.orig
systemctl enable strongswan-starter.service

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
/usr/lib/systemd/system/strongswan.service
/usr/sbin/charon-systemd

%doc COPYING TODO NEWS INSTALL HACKING README
%license LICENSE
