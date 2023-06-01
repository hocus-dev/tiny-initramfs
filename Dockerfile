FROM gcc:13.1-bookworm AS builder

RUN apt-get update && apt-get install dietlibc-dev cpio
WORKDIR /build
COPY . .
RUN ./autogen.sh \
    #&& ./configure --enable-debug CC="diet gcc" \
    && ./configure CC="diet gcc" \
    && make \
    && mkdir initramfs \
    && cp tiny_initramfs initramfs/init \
    && strip initramfs/init \
    && mkdir initramfs/dev initramfs/proc initramfs/sys initramfs/target \
    && cd initramfs ; find . | cpio -o --quiet -R 0:0 -H newc > ../initrd.img

FROM scratch AS result
COPY --from=builder /build/initrd.img /initrd.img
