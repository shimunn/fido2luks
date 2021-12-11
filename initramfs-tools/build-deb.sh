#!/usr/bin/env bash

set -ex

docker build . -t fido2luks-deb

mkdir -p debs

docker run -ti -v "$(pwd)/..:/code:ro" -v "$(pwd)/debs:/out" fido2luks-deb
