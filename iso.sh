#!/bin/sh
set -e
. ./build.sh

mkdir -p isodir
mkdir -p isodir/boot
mkdir -p isodir/boot/grub

nasm -f bin -o user/hello.bin user/hello.asm

cp sysroot/boot/adhDOS.kernel isodir/boot/adhDOS.kernel
cp user/hello.bin isodir/boot/hello.bin
cat > isodir/boot/grub/grub.cfg << EOF
menuentry "adhdos" {
	multiboot /boot/adhDOS.kernel
	module /boot/hello.bin
}
EOF
grub-mkrescue -o adhDOS.iso isodir
