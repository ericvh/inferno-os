#!/bin/sh
# put the test fixtures where the kernel's baked root will pick them up
set -e
cd "$(dirname "$0")/../.."
obj=${OBJTYPE:-$(uname -m | sed 's/x86_64/amd64/')}
mkdir -p lib/hybtest
cp tests/hybrid/run.sh tests/hybrid/hysrv tests/hybrid/hyalice tests/hybrid/mallory tests/hybrid/hysigner \
	tests/hybrid/secret tests/hybrid/user.seed tests/hybrid/user.pub tests/hybrid/hygood tests/hybrid/hysigners lib/hybtest/
Linux/$obj/bin/limbo -Imodule -o dis/logincli.dis tests/hybrid/logincli.b
