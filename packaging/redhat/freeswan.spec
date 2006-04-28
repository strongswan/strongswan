Summary: FreeS/WAN IPSEC implementation
Name: freeswan
Version: 2.04
%define defkv %(rpm -q --qf='%{Version}-%{Release}\\n' kernel-source|tail -1)
# The default kernel version to build for is the latest of
# the installed kernel-source RPMs.
# This can be overridden by "--define 'kversion x.x.x-y.y.y'"
%{!?kversion: %{expand: %%define kversion %defkv}}
%define	krelver		%(echo %{kversion} | tr -s '-' '_')
# FreeS/WAN -pre/-rc nomenclature has to co-exist with hyphen paranoia
%define srcpkgver	%(echo %{version} | tr -s '_' '-')
%define our_release 1fs
%define debug_package %{nil}
Release: %{our_release}
License: GPL
Url: http://www.freeswan.org/
Source: freeswan-%{srcpkgver}.tar.gz
Group: System Environment/Daemons
BuildRoot: /var/tmp/%{name}-%{PACKAGE_VERSION}-root
%define __spec_install_post /usr/lib/rpm/brp-compress || :
BuildRequires: kernel-source = %{kversion}

%package userland
Summary: FreeS/WAN IPSEC usermod tools
Group: System Environment/Daemons
Provides: ipsec-userland
Obsoletes: freeswan
Requires: ipsec-kernel
Release: %{our_release}

%package doc
Summary: FreeS/WAN IPSEC full documentation
Group: System Environment/Daemons
Release: %{our_release}

%package module
Summary: FreeS/Wan kernel module
Group:  System Environment/Kernel
Release: %{krelver}_%{our_release}
Provides: ipsec-kernel
Requires: kernel = %{kversion}
# do not make the dependancy circular for now.
#Requires: ipsec-userland

%description userland
FreeS/WAN is a free implementation of IPSEC & IKE for Linux.  IPSEC is 
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and 
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
FreeS/WAN on a freeswan enabled kernel.

%description module
This package contains only the ipsec module for the RedHat series of kernels.

%description doc
This package contains extensive documentation of the FreeeS/WAN IPSEC
system.

%description
A dummy package that installs userland and kernel pieces.

%prep
%setup -q -n freeswan-%{srcpkgver}

%build
%{__make} \
  USERCOMPILE="-g %{optflags}" \
  INC_USRLOCAL=%{_prefix} \
  MANTREE=%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  programs
FS=$(pwd)
mkdir -p BUILD.%{_target_cpu}
mkdir -p BUILD.%{_target_cpu}-smp

cd packaging/redhat
for smp in -smp ""
do
%{__make} -C $FS MODBUILDDIR=$FS/BUILD.%{_target_cpu}$smp \
    FREESWANSRCDIR=$FS \
    KERNELSRC=/usr/src/linux-%{kversion} \
    ARCH=%{_arch} \
    SUBARCH=%{_arch} \
    MODULE_DEF_INCLUDE=$FS/packaging/redhat/config-%{_target_cpu}$smp.h \
    module
done

%install
%{__make} \
  DESTDIR=%{buildroot} \
  INC_USRLOCAL=%{_prefix} \
  MANTREE=%{buildroot}%{_mandir} \
  INC_RCDEFAULT=%{_initrddir} \
  install
install -d -m700 %{buildroot}%{_localstatedir}/run/pluto
install -d %{buildroot}%{_sbindir}

mkdir -p %{buildroot}/lib/modules/%{kversion}/kernel/net/ipsec
cp BUILD.%{_target_cpu}/ipsec.o \
 %{buildroot}/lib/modules/%{kversion}/kernel/net/ipsec

mkdir -p %{buildroot}/lib/modules/%{kversion}smp/kernel/net/ipsec
cp BUILD.%{_target_cpu}-smp/ipsec.o \
 %{buildroot}/lib/modules/%{kversion}smp/kernel/net/ipsec

%clean
rm -rf ${RPM_BUILD_ROOT}

%files doc
%defattr(-,root,root)
%doc doc
%doc %{_defaultdocdir}/freeswan/ipsec.conf-sample

%files userland
%defattr(-,root,root)
%doc BUGS CHANGES COPYING
%doc CREDITS INSTALL README
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%config(noreplace) %{_initrddir}/ipsec
%{_libdir}/ipsec
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%doc %{_mandir}/*/*
%{_localstatedir}/run/pluto

%files module
%defattr (-,root,root)
/lib/modules/%{kversion}/kernel/net/ipsec
/lib/modules/%{kversion}smp/kernel/net/ipsec

%pre userland
%preun userland
if [ $1 = 0 ]; then
    /sbin/service ipsec stop || :
    /sbin/chkconfig --del ipsec
fi

%postun userland
if [ $1 -ge 1 ] ; then
  /sbin/service ipsec stop 2>&1 > /dev/null && /sbin/service ipsec start  2>&1 > /dev/null || :
fi

%postun module
%post module

%post userland
chkconfig --add ipsec

%changelog
* Fri Aug 22 2003 Sam Sgro <sam@freeswan.org>
- Juggling release/source package names to allow for 
  -pre/-rc releases to build.

* Thu Aug 14 2003 Sam Sgro <sam@freeswan.org>
- Reverting back to pre-x.509 version, cosmetic changes.

* Tue May 20 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-x509_1.3.2_2es
- Add "Obsoletes: freeswan" to userland RPM.

* Fri May 16 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-x509_1.3.2_1es
- Add version 1.3.2 of the x509 patch.
- Add missing /usr/libexec/ipsec dir and files.
- Minor tidy up of spec file.

* Thu May 15 2003 Charlie Brady <charlieb@e-smith.com> 2.0.0-1es
- Based on work by Paul Lahaie of Steamballoon, Michael
  Richardson of freeS/WAN team and Tuomo Soini <tis@foobar.fi>.
- Build freeswan RPMs from a single source RPM, for RedHat, but
  should work on any RPM based system.
