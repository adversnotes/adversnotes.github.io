# -*- coding: utf-8 -*-
# Decode the XOR-0xA0 hidden strings of the oxcollector stealer (GTA6Cloud stage 3)
# and annotate them in the Ghidra listing.
#
# - Scans the .rdata block for runs of bytes >= 0x80 (the obfuscated strings).
# - Decodes each run with XOR 0xA0 (UTF-8, falls back to latin-1).
# - Puts the decoded text as an EOL comment on the string itself, and on every
#   instruction that references it (Rust passes string slices, so references
#   often point into the middle of a run).
# - Adds a bookmark "oxcollector" on each decoded string and prints a summary.
#
# Works with Ghidra's Jython (2.7) and PyGhidra. The decoding logic was tested
# against the sample; the script itself was not run inside Ghidra.
#
#@category Malware.oxcollector
#@menupath Tools.oxcollector.Decode hidden strings

import jarray
from ghidra.program.model.listing import CodeUnit

KEY = 0xA0
MIN_LEN = 6            # shortest obfuscated run to consider
MAX_REF_SCAN = 4096    # bytes per run scanned for incoming references (big JSON blobs)
REF_TEXT_LEN = 100     # characters shown at a referencing instruction
STR_TEXT_LEN = 240     # characters shown at the string itself


def decode(seq):
    raw = bytearray([c ^ KEY for c in seq])
    try:
        return raw.decode('utf-8')
    except Exception:
        return raw.decode('latin-1')


def looks_like_text(s):
    if not s:
        return False
    printable = sum(1 for ch in s if (32 <= ord(ch) < 127) or ord(ch) >= 0x400 or ch in u'\t\r\n')
    letters = sum(1 for ch in s if ch.isalpha())
    return printable >= 0.9 * len(s) and letters >= 0.3 * len(s)


def one_line(s, n):
    s = s.replace(u'\r', u' ').replace(u'\n', u' ').replace(u'\t', u' ')
    return s[:n] + (u'...' if len(s) > n else u'')


mem = currentProgram.getMemory()
listing = currentProgram.getListing()
refman = currentProgram.getReferenceManager()
block = mem.getBlock(".rdata")

if block is None:
    popup("No .rdata block found. Is stage3_stealer.bin the active program?")
else:
    start = block.getStart()
    size = int(block.getSize())
    buf = jarray.zeros(size, 'b')
    mem.getBytes(start, buf)
    data = [b & 0xff for b in buf]

    n_strings = 0
    n_refs = 0
    i = 0
    monitor.initialize(size)
    monitor.setMessage("Decoding oxcollector strings...")
    while i < size:
        monitor.checkCanceled()
        if data[i] < 0x80:
            i += 1
            continue
        j = i
        while j < size and data[j] >= 0x80:
            j += 1
        if j - i >= MIN_LEN:
            text = decode(data[i:j])
            if looks_like_text(text):
                addr = start.add(i)
                listing.setComment(addr, CodeUnit.EOL_COMMENT, u'XOR A0: ' + one_line(text, STR_TEXT_LEN))
                createBookmark(addr, "oxcollector", one_line(text, 120))
                n_strings += 1
                for k in range(i, min(j, i + MAX_REF_SCAN)):
                    a = start.add(k)
                    for ref in refman.getReferencesTo(a):
                        frm = ref.getFromAddress()
                        piece = one_line(decode(data[k:min(j, k + REF_TEXT_LEN * 2)]), REF_TEXT_LEN)
                        new = u'XOR A0 -> "%s"' % piece
                        old = listing.getComment(CodeUnit.EOL_COMMENT, frm)
                        if old:
                            # Already annotated (e.g. second run): leave it alone
                            if new in old:
                                continue
                            new = old + u' | ' + new
                        listing.setComment(frm, CodeUnit.EOL_COMMENT, new)
                        n_refs += 1
                print(u'%s  %s' % (addr, one_line(text, 160)))
        monitor.setProgress(j)
        i = j

    print(u'Decoded %d hidden strings, annotated %d references. '
          u'See Window > Bookmarks (category oxcollector).' % (n_strings, n_refs))
