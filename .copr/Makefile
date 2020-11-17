srpm:
	dnf install -y cargo
	cargo install cargo-rpm
	cargo rpm build --verbose
	ls -lart target/release/rpmbuild/SRPMS/*
	echo $(outdir)
	cp -r target/release/rpmbuild/SRPMS/* $(outdir)/
