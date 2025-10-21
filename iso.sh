#!/bin/sh
set -e
. ./build.sh

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub

cp sysroot/boot/adhDOS.kernel isodir/boot/adhDOS.kernel
cat > isodir/boot/grub/grub.cfg << EOF
menuentry "adhdos" {
	multiboot /boot/adhDOS.kernel
}
EOF
grub-mkrescue -o adhDOS.iso isodir
