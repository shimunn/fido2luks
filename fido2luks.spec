%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: fido2luks
Summary: Decrypt your LUKS partition using a FIDO2 compatible authenticator
# Version: @@VERSION@@
# Release: @@RELEASE@@%{?dist}
Version: 0.2.15
Release: 1%{?dist}
License:                     Mozilla Public License Version 2.0
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://github.com/shimunn/fido2luks
Requires: dracut, cryptsetup >= 2.2.0, cryptsetup-libs >= 2.2.0
BuildRequires: cargo, clang-devel, cryptsetup >= 2.2.0, cryptsetup-devel >= 2.2.0, cryptsetup-libs >= 2.2.0

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

%build
source $HOME/.cargo/env
make -f .copr/Makefile

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
make -f .copr/Makefile install root=%{buildroot}
install -Dm 755 -d dracut/96luks-2fa %{buildroot}/%{_prefix}/lib/dracut/modules.d/96luks-2fa
cp -r dracut/96luks-2fa %{buildroot}/%{_prefix}/lib/dracut/modules.d/96luks-2fa
install -Dm 755 dracut/dracut.conf.d/luks-2fa.conf %{buildroot}/%{_sysconfdir}/dracut.conf.d/luks-2fa.conf
install -Dm 644 dracut/dracut.conf.d/luks-2fa.conf %{buildroot}/%{_prefix}/lib/dracut/dracut.conf.d/luks-2fa.conf
install -Dm 644 initramfs-tools/fido2luks.conf %{buildroot}/%{_sysconfdir}/fido2luks.conf

%clean
rm -rf %{buildroot}

%files
%attr(0775, root, root) "%{_bindir}/fido2luks"
%attr(0775, root, root) "%{_prefix}/lib/dracut/modules.d/96luks-2fa"
%attr(0775, root, root) "%{_prefix}/lib/dracut/modules.d/96luks-2fa/luks-2fa-generator.sh"
%attr(0775, root, root) "%{_prefix}/lib/dracut/modules.d/96luks-2fa/luks-2fa.target"
%attr(0775, root, root) "%{_prefix}/lib/dracut/modules.d/96luks-2fa/module-setup.sh"
%attr(0775, root, root) "%{_prefix}/lib/dracut/dracut.conf.d/luks-2fa.conf"
%config(noreplace) "%{_sysconfdir}/dracut.conf.d/luks-2fa.conf"
%config(noreplace) "%{_sysconfdir}/fido2luks.conf"
%doc README.md
