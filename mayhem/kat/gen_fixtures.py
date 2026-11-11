#!/usr/bin/env python3
"""Regenerates the committed KAT fixtures and fuzz seeds (not run by the build)."""
import hashlib
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
MAYHEM = os.path.dirname(HERE)


def put(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def bcm4908(pad, jffs_blocks=1, vendor=False):
    cfe = b""
    if vendor:
        hdr = bytearray(0x100)
        hdr[0:4] = struct.pack(">I", 0x2a23245e)
        hdr[4:8] = struct.pack(">I", 0x100)
        cfe = bytes(hdr)
    body = bytearray()
    body += b"\x85\x19" + b"\x00" * 30 + b"bootfs data"
    body += b"\xff" * (0x20000 * jffs_blocks - len(body))
    if pad:
        body += b"\xff" * 0x20000
    body += b"UBI#\x01" + b"\x00" * 27 + b"rootfs data"
    if not pad:
        body += b"\x00" * 256  # the unpadded layout reads 256 bytes at each rootfs candidate
    tail_crc = zlib.crc32(bytes(body)) ^ 0xFFFFFFFF
    tail = struct.pack("<5I", tail_crc, 0x5732, 0x4908, 3, 2)
    return cfe + bytes(body) + tail


def safeloader(parts):
    vendor = bytearray(0x1000)
    vendor[0:16] = b"vendor info here"
    table = b""
    for name, base, content in parts:
        table += b"fwup-ptn %s base 0x%x size 0x%x\t\r\n" % (name.encode(), base, len(content))
    # partition table sits right behind the 0x1000 vendor info, data offsets are relative to it
    body = bytearray(0x1000 + 0x1000 + 0x2000)
    body[0:0x1000] = vendor
    body[0x1000:0x1000 + len(table)] = table
    for name, base, content in parts:
        body[0x1000 + base:0x1000 + base + len(content)] = content
    salt = bytes([0x7a, 0x2b, 0x15, 0xed, 0x9b, 0x98, 0x59, 0x6d, 0xe5, 0x04, 0xab, 0x44, 0xac, 0x2a, 0x9f, 0x4e])
    md5 = hashlib.md5(salt + bytes(body)).digest()
    return struct.pack(">I", len(body)) + md5 + bytes(body)


def nvram(vars_, total, magic_off=0, bad_len=False):
    img = bytearray(b"\xff" * total)
    data = b"".join(b"%s=%s\x00" % (k.encode(), v.encode()) for k, v in vars_) + b"\x00\x00"
    ln = 20 + len(data)
    hdr = struct.pack("<5I", 0x48534C46, 0xfffffff0 if bad_len else ln, (0x1000 << 16) | 0x100 | 0xa5, 0x0100 | (0x0200 << 16), 0)
    img[magic_off:magic_off + 20] = hdr
    img[magic_off + 20:magic_off + 20 + len(data)] = data
    return bytes(img)


def ead(typ, payload=b"", nid=0xffff, sid=0x1000):
    return struct.pack(">IIIHHI", 0xdadacafe, len(payload), typ, nid, sid, 0x01010101) + payload


def main():
    salt = bytes(range(1, 9)) + b"\x00" * 24
    ext = b"extsalt1" + b"\x00" * 24
    put(os.path.join(MAYHEM, "fuzz_ead_client/testsuite/pong.ead"), ead(1, struct.pack(">H", 0) + b"mayhem-ap\x00"))
    put(os.path.join(MAYHEM, "fuzz_ead_client/testsuite/pong-md5.ead"), ead(1, struct.pack(">H", 1) + b"router2\x00"))
    put(os.path.join(MAYHEM, "fuzz_ead_client/testsuite/ack-username.ead"), ead(3))
    put(os.path.join(MAYHEM, "fuzz_ead_client/testsuite/prime.ead"), ead(5, bytes([0, 8]) + salt + ext))
    put(os.path.join(MAYHEM, "fuzz_ead_client/testsuite/send-b.ead"), ead(7, b"\x00" + bytes(range(2, 130))))
    put(os.path.join(MAYHEM, "fuzz_ead_client/testsuite/done-auth.ead"), ead(9, bytes(range(20))))

    put(os.path.join(HERE, "bcm4908.img"), bcm4908(pad=True))
    put(os.path.join(MAYHEM, "bcm4908img_info/testsuite/padded.img"), bcm4908(pad=True))
    put(os.path.join(MAYHEM, "bcm4908img_info/testsuite/plain.img"), bcm4908(pad=False))
    put(os.path.join(MAYHEM, "bcm4908img_info/testsuite/vendor.img"), bcm4908(pad=False, vendor=True))

    parts = [("os-image", 0x400, b"kernel" * 40), ("file-system", 0x800, b"squashfs" * 100)]
    put(os.path.join(HERE, "safeloader.bin"), safeloader(parts))
    put(os.path.join(MAYHEM, "osafeloader_extract/testsuite/two-parts.bin"), safeloader(parts))
    put(os.path.join(MAYHEM, "osafeloader_extract/testsuite/one-part.bin"), safeloader([("file-system", 0x100, b"x" * 64)]))

    v = [("boardtype", "0x0472"), ("boardnum", "42"), ("et0macaddr", "00:11:22:33:44:55"), ("sdram_init", "0x0009"), ("sdram_ncdl", "0x0")]
    put(os.path.join(MAYHEM, "fuzz_nvram/testsuite/small.nvram"), nvram(v, 0x400))
    put(os.path.join(MAYHEM, "fuzz_nvram/testsuite/offset.nvram"), nvram(v, 0x8100, magic_off=0x40))
    put(os.path.join(MAYHEM, "fuzz_nvram/testsuite/badlen.nvram"), nvram(v, 0x200, bad_len=True))


if __name__ == "__main__":
    main()
