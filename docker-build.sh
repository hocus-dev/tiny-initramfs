#!/bin/sh

docker build --progress=plain -t hocus-initramfs .
id=$(docker create hocus-initramfs /)
docker cp $id:/initrd.img - | tar x -O > initrd.img
docker rm -v $id
