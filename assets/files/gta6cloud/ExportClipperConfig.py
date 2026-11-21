# -*- coding: utf-8 -*-
# Export the oxcollector clipper config (GTA6Cloud stage 3) from Ghidra.
#
# FUN_14004beac copies 0x5bbaa bytes from DAT_14027afc8 and XORs each one with 0xA0
# (loop at 14004bf16..14004bf33). The result is a JSON document:
#   {"coins": {"btc": [...], "eth": [...], ...}, "prefix_chars": 2, "shot_min_interval_secs": 30}
# This script does the same decode and writes:
#   clipper_config.json      - the decoded JSON, pretty-printed
#   clipper_addresses.tsv    - one line per address: coin <TAB> address
# It also labels the blob and comments the decode loop.
#
# Works with Ghidra's Jython (2.7) and PyGhidra. The decoding logic was tested
# against the sample; the script itself was not run inside Ghidra.
#
#@category Malware.oxcollector
#@menupath Tools.oxcollector.Export clipper addresses

import json
import os
import io
import jarray
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

BLOB_VA = 0x14027afc8
BLOB_LEN = 0x5bbaa      # 375,722 bytes, taken from "mov edx, 0x5bbaa" / "cmp rax, 0x5bbaa"
LOOP_VA = 0x14004bf16
KEY = 0xA0


def decode_config(raw):
    text = bytearray([b ^ KEY for b in raw]).decode('utf-8')
    return json.loads(text)


def to_rows(cfg):
    rows = []
    for coin in sorted(cfg['coins']):
        for addr in cfg['coins'][coin]:
            rows.append((coin, addr))
    return rows


addr = toAddr(BLOB_VA)
buf = jarray.zeros(BLOB_LEN, 'b')
currentProgram.getMemory().getBytes(addr, buf)
cfg = decode_config([b & 0xff for b in buf])
rows = to_rows(cfg)

def write_outputs(out_dir):
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    js = json.dumps(cfg, indent=1)
    if str is bytes:          # Jython 2.7: json.dumps returns a byte str
        js = js.decode('ascii')
    with io.open(os.path.join(out_dir, 'clipper_config.json'), 'w', encoding='utf-8') as f:
        f.write(js)
    with io.open(os.path.join(out_dir, 'clipper_addresses.tsv'), 'w', encoding='utf-8') as f:
        f.write(u'coin\taddress\n')
        for coin, a in rows:
            f.write(u'%s\t%s\n' % (coin, a))


out_dir = askDirectory("Folder for clipper_config.json and clipper_addresses.tsv", "Save").getAbsolutePath()
try:
    write_outputs(out_dir)
except (IOError, OSError) as e:
    # Typical on Windows: Defender "Controlled folder access" blocks Ghidra (java.exe)
    # from writing to Desktop/Documents, or the target file is open in another program.
    print("Could not write to %s: %s" % (out_dir, e))
    out_dir = os.path.join(os.path.expanduser('~'), 'oxcollector_export')
    print("Falling back to " + out_dir)
    write_outputs(out_dir)

createLabel(addr, "ox_clipper_config_xor_a0", True, SourceType.USER_DEFINED)
listing = currentProgram.getListing()
listing.setComment(addr, CodeUnit.PLATE_COMMENT,
                   "oxcollector clipper config: %d bytes, XOR 0xA0, JSON with %d addresses" % (BLOB_LEN, len(rows)))
listing.setComment(toAddr(LOOP_VA), CodeUnit.EOL_COMMENT, "decode clipper config: byte ^ 0xA0, 0x5bbaa bytes")

counts = {}
for coin, _ in rows:
    counts[coin] = counts.get(coin, 0) + 1
for coin in sorted(counts):
    print("%-5s %5d" % (coin, counts[coin]))
print("Total: %d addresses, prefix_chars=%s, shot_min_interval_secs=%s" %
      (len(rows), cfg.get('prefix_chars'), cfg.get('shot_min_interval_secs')))
print("Written to " + out_dir)
