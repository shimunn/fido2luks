srpm:
	dnf install -y cargo
	cargo install cargo-rpm
	cargo rpm build --verbose
	find .
	cp -r target/release/rpmbuild/SRPMS/* $(outdir)/
