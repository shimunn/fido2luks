# Maintainer: shimunn <shimun@shimun.net>
pkgname=fido2luks
pkgver=0.2.12
pkgrel=1
makedepends=('rust' 'cargo')
arch=('i686' 'x86_64' 'armv6h' 'armv7h')
pkgdesc="Decrypt your LUKS partition using a FIDO2 compatible authenticator"
url="https://github.com/shimunn/fido2luks"
license=('MPL-2.0')

build() {
    return 0
}

package() {
    cd $srcdir
    cargo install --no-track --locked --all-features --root="$pkgdir/usr/" --git=https://github.com/shimunn/fido2luks
}
