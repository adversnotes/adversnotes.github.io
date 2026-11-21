#!/usr/bin/env python3
"""
GTA6Cloud chain static unpacker (2026-11-21).

Usage:  python3 -I gta6cloud_unpack.py loadperf.dll OUTDIR

Purely static: re-implements the decryption routines; never executes sample code.
  stage1 loadperf.dll  --(BLXO overlay: deinterleave 2/3 + inverse-subst/chain + RC4 + XOR32)-->  stage2 PhotoCache.exe
  stage2 PHOTO resource --(same scheme w/ other keys + 3 rolling-XOR passes)--> OXSE header + stage3 PE
  OXSE config           --(ChaCha20-Poly1305, key = SHA256(const8 || blob[0x3e1] || "ox-seal-v1"))--> C2 config
Requires: pefile, cryptography
Key/table addresses are specific to the analysed build; other builds may move them.
"""
import sys, os, struct, hashlib
import pefile
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def tables(pe, subst, ksub, krc4, kxor):
    base = pe.OPTIONAL_HEADER.ImageBase
    rd = lambda va, n: pe.get_data(va - base, n)
    return rd(subst, 256), rd(ksub, 16), rd(krc4, 16), rd(kxor, 32)


def core_decrypt(buf, SUBST, K_SUB, K_RC4, K_XOR):
    inv = [0] * 256
    for i, b in enumerate(SUBST):
        inv[b] = i
    prev = 0
    for i in range(len(buf)):
        c = buf[i]
        buf[i] = inv[c] ^ K_SUB[i & 0xf] ^ prev
        prev = c
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + K_RC4[i & 0xf]) & 0xff
        S[i], S[j] = S[j], S[i]
    x = y = 0
    for i in range(len(buf)):
        x = (x + 1) & 0xff
        y = (y + S[x]) & 0xff
        S[x], S[y] = S[y], S[x]
        buf[i] ^= S[(S[x] + S[y]) & 0xff]
    for i in range(len(buf)):
        buf[i] ^= K_XOR[i & 0x1f]
    return buf


def stage1(path):
    pe = pefile.PE(path)
    data = open(path, 'rb').read()
    assert data[-12:-8] == b'BLXO'
    plen = struct.unpack('<I', data[-8:-4])[0]
    blob = data[-12 - plen:-12]
    out = bytearray(); i = 0
    while i < len(blob) and len(out) < 0x367802:
        out.append(blob[i]); i += 1
        if len(out) & 1 == 0:
            i += 1
    return bytes(core_decrypt(out, *tables(pe, 0x180004070, 0x180004060, 0x180004050, 0x180004030)))


def stage2(path):
    pe = pefile.PE(path)
    res = None
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if t.struct.Id == 10:
            for n in t.directory.entries:
                if n.name and str(n.name) == 'PHOTO':
                    e = n.directory.entries[0]
                    res = pe.get_data(e.data.struct.OffsetToData, e.data.struct.Size)
    assert res
    size, key, magic = struct.unpack('<III', res[-12:])
    assert magic == 0x601453c9
    buf = core_decrypt(bytearray(res[:size]), *tables(pe, 0x140025f90, 0x140025f78, 0x140025f68, 0x140025f48))
    kb = struct.pack('<I', key)
    for k in (kb[2], kb[1], kb[0]):
        for i in range(len(buf)):
            buf[i] ^= k
            k = (k + buf[i]) & 0xff
    cfg = None
    if buf[:4] == b'OXSE':
        hl = struct.unpack_from('<I', buf, 0x12)[0] + 0x26
        cfg, buf = bytes(buf[:hl]), buf[hl:]
    base = pe.OPTIONAL_HEADER.ImageBase
    blob = pe.get_data(0x140025b60 - base, 0x3e1)
    seal_key = hashlib.sha256(struct.pack('<II', 0x39fcadd1, 0x6aff07e2) + blob + b'ox-seal-v1').digest()
    return bytes(buf), cfg, seal_key


def open_oxse(cfg, key):
    n = struct.unpack_from('<I', cfg, 0x12)[0]
    return ChaCha20Poly1305(key).decrypt(cfg[6:18], cfg[0x16:0x16 + n + 16], None)


if __name__ == '__main__':
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    s2 = stage1(src)
    p2 = os.path.join(outdir, 'stage2_PhotoCache.bin'); open(p2, 'wb').write(s2)
    print('stage2', hashlib.sha256(s2).hexdigest())
    s3, cfg, key = stage2(p2)
    p3 = os.path.join(outdir, 'stage3_stealer.bin'); open(p3, 'wb').write(s3)
    print('stage3', hashlib.sha256(s3).hexdigest())
    if cfg:
        pt = open_oxse(cfg, key)
        open(os.path.join(outdir, 'oxse_config.bin'), 'wb').write(pt)
        bid = struct.unpack_from('<Q', pt, 0)[0]
        strs, off = [], 8
        while off + 2 <= len(pt):  # u16 byte-length + UTF-16LE string (NUL-terminated)
            ln = struct.unpack_from('<H', pt, off)[0]; off += 2
            strs.append(pt[off:off + ln].decode('utf-16le').rstrip('\x00')); off += ln
        print('config bid', bid)
        print('config strings', strs)
