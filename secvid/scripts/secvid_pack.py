#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# secvid_pack.py h264 <in.h264> <out prefix>
# secvid_pack.py raw <in.yuv> <frame size> <out prefix>
#
# Packs a stream for secvidsrc: <prefix>.enc holds each unit (an H.264
# access unit, split at its access unit delimiter, or a raw frame)
# encrypted on its own with the secvid TA's demo key (AES-128-CTR from the
# start of the key stream, as the TA decrypts one unit at a time),
# <prefix>.idx the unit sizes, one per line, and <prefix>.x the plaintext
# XORed with 0xa5 for clear reference runs (secvidsrc mode=clear). Needs
# the openssl command.
import subprocess
import sys

# The demo key and IV built into ta/secvid_ta.c. Not a secret: a real
# player gets its content key from a key system, never from the host.
KEY = "5daa822d6c0eecd9e580ab8b95ab3f80"
IV = "1b782ad1e45f0b5df4ff9fdeaa6a09df"


def encrypt(data):
    out = subprocess.run(["openssl", "enc", "-aes-128-ctr", "-K", KEY, "-iv", IV],
                         input=data, stdout=subprocess.PIPE, check=True).stdout
    assert len(out) == len(data)
    return out


def access_units(stream):
    starts = []
    i = 0
    while True:
        i = stream.find(b"\x00\x00\x01\x09", i)
        if i < 0:
            break
        starts.append(i - 1 if i > 0 and stream[i - 1] == 0 else i)
        i += 4
    if not starts or starts[0] != 0:
        sys.exit("the stream must start with an access unit delimiter "
                 "(ffmpeg -bsf:v h264_metadata=aud=insert)")
    return [stream[a:b] for a, b in zip(starts, starts[1:] + [len(stream)])]


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "h264":
        units = access_units(open(sys.argv[2], "rb").read())
        prefix = sys.argv[3]
    elif len(sys.argv) == 5 and sys.argv[1] == "raw":
        data = open(sys.argv[2], "rb").read()
        size = int(sys.argv[3])
        if not size or len(data) % size:
            sys.exit("%s is not a whole number of %d-byte frames" % (sys.argv[2], size))
        units = [data[i:i + size] for i in range(0, len(data), size)]
        prefix = sys.argv[4]
    else:
        sys.exit("usage: %s h264 <in.h264> <prefix> | raw <in.yuv> <frame size> <prefix>"
                 % sys.argv[0])
    with open(prefix + ".enc", "wb") as f:
        for u in units:
            f.write(encrypt(u))
    with open(prefix + ".idx", "w") as f:
        f.write("".join("%d\n" % len(u) for u in units))
    with open(prefix + ".x", "wb") as f:
        f.write(bytes(b ^ 0xa5 for u in units for b in u))
    print("%d units, %d bytes" % (len(units), sum(len(u) for u in units)))


if __name__ == "__main__":
    main()
