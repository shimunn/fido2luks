srpm:
	dnf install -y cargo
	cargo install cargo-rpm
	cargo rpm build --verbose
	cp -r target/release/rpmbuild/SRPMS/* $(outdir)/
