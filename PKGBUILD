# Maintainer: shimunn <shimun@shimun.net>
pkgname=fido2luks
pkgver=0.2.12
pkgrel=1
makedepends=('rust' 'cargo' 'cryptsetup' 'clang')
depends=('cryptsetup')
arch=('i686' 'x86_64' 'armv6h' 'armv7h')
pkgdesc="Decrypt your LUKS partition using a FIDO2 compatible authenticator"
url="https://github.com/shimunn/fido2luks"
license=('MPL-2.0')

pkgver() {
	# Use tag version if possible otherwise concat project version and git ref
	git describe --exact-match --tags HEAD 2> /dev/null || \
		echo "$(cargo pkgid | cut -d'#' -f2).$(git describe --always)"
}

build() {
    cargo build --release --locked --all-features --target-dir=target
}

package() {
    install -Dm 755 target/release/${pkgname} -t "${pkgdir}/usr/bin"
    install -Dm 644 fido2luks.bash "${pkgdir}/usr/share/bash-completion/completions/fido2luks"
}
