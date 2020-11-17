%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: fido2luks
Summary: Decrypt your LUKS partition using a FIDO2 compatible authenticator
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License:                     Mozilla Public License Version 2.0
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://github.com/shimunn/fido2luks

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}
pwd
echo %{_topdir}
echo %{_specdir}
install -Dm 755 -d %{_topdir}/../../../dracut/96luks-2fa %{buildroot}/%{_prefix}/lib/dracut/modules.d/96luks-2fa
install -Dm 755 %{_topdir}/../../../dracut/dracut.conf.d/luks-2fa.conf %{buildroot}/%{_sysconfdir}/dracut.conf.d/luks-2fa.conf
install -Dm 644 %{_topdir}/../../../initramfs-tools/fido2luks.conf %{buildroot}/%{_sysconfdir}/fido2luks.conf

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_prefix}/*
%config(noreplace) %{_sysconfdir}/*
