# Maintainer: shimunn <shimun@shimun.net>

pkgname=fido2luks-git
pkgver=0.2.16.7e6b33a
pkgrel=1
makedepends=('rust' 'cargo' 'cryptsetup' 'clang' 'git')
depends=('cryptsetup')
arch=('i686' 'x86_64' 'armv6h' 'armv7h')
pkgdesc="Decrypt your LUKS partition using a FIDO2 compatible authenticator"
url="https://github.com/shimunn/fido2luks"
license=('MPL-2.0')
source=('git+https://github.com/shimunn/fido2luks')
sha512sums=('SKIP')

pkgver() {
    cd fido2luks

    # Use tag version if possible otherwise concat project version and git ref
    git describe --exact-match --tags HEAD 2>/dev/null ||
        echo "$(cargo pkgid | cut -d'#' -f2).$(git describe --always)"
}

build() {
    cd fido2luks
    cargo build --release --locked --all-features --target-dir=target
}

package() {
    cd fido2luks

    install -Dm 755 target/release/fido2luks -t "${pkgdir}/usr/bin"
    install -Dm 755 pam_mount/fido2luksmounthelper.sh -t "${pkgdir}/usr/bin"
    install -Dm 644 initcpio/hooks/fido2luks -t "${pkgdir}/usr/lib/initcpio/hooks"
    install -Dm 644 initcpio/install/fido2luks -t "${pkgdir}/usr/lib/initcpio/install"
    install -Dm 644 fido2luks.bash "${pkgdir}/usr/share/bash-completion/completions/fido2luks"
    install -Dm 644 fido2luks.fish -t "${pkgdir}/usr/share/fish/vendor_completions.d"
}
