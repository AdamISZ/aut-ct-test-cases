#! /usr/bin/env python
"""
To prepare data for input to this tool:

1. Query the bitcoind RPC:

```
bitcoin-cli dumptxoutset "yourabsolutepathfilename"
```

(which can take a long while; it's a full utxo snapshot).

2. Run this tool:

https://github.com/theStack/utxo_dump_tools/blob/master/utxo_to_sqlite/utxo_to_sqlite.go

.. with appropriate input (the above) and output file names. The output file can then be used as input to this querying tool.

Note also that the output file produced here is in the format taken by https://github.com/AdamISZ/aut-ct for usage tokens from a pubkey set.

TODO:
There are pros and cons to allowing repeated pubkeys here, depending on the usage scenario. For now, duplicates are allowed, so a post-processing step like list(set(x)) may be needed.
"""

import sys
from sqlite3 import connect, Cursor, Row
from utils import hextobin, bintohex
from peddleq import get_pt_from_ark_hex, convert_to_ark_compressed,pointadd, pointmult

def setup_db(fn):
    source = connect(fn)
    return source.cursor()

def select_the_scripts(db, low_filter, height=None):
    if height is None:
        qrystring = "SELECT scriptpubkey, value FROM 'utxos' WHERE value >= ? \
        AND scriptpubkey LIKE '5120%';"
        tpl = (low_filter,)
    else:
        qrystring = "SELECT scriptpubkey, value FROM 'utxos' WHERE value >= ? \
        AND height >= ? AND scriptpubkey LIKE '5120%';"
        tpl = (low_filter, height)
    spks = db.execute(qrystring, tpl).fetchall()
    if audit:
        return [(x[0], x[1]) for x in spks]

if __name__ == "__main__":
    print("Using sat value filter: {}, input file: {}\
    , and output file: {}".format(*sys.argv[1:4]))
    c = setup_db(sys.argv[2])
    audit = True if len(sys.argv) > 4 and sys.argv[4] == "audit" else False
    height = None if len(sys.argv) > 6 else int(sys.argv[5])
    spks = select_the_scripts(c, sys.argv[1], height)
    print("Retrieved this many taproot pubkeys: ", len(spks))
    if not audit:
        with open(sys.argv[3], "wb") as f:
            f.write((" ".join([x[0][4:] for x in spks])).encode())
    else:
        # we need to add the value as an additive tweak,
        # with the generator J; see the aut-ct repo for how J is generated.
        Jhex = "c208099c7e3d51e60f29d835bd108c50fe5e6b1c2fe59cf2bb2b111b9a12f2c480"
        J = get_pt_from_ark_hex(Jhex)
        pubkeysvalueslist = [(x[0][4:], x[1]) for x in spks]
        with open(sys.argv[3], "w") as f:
            Cs = []
            lenp = len(pubkeysvalueslist)
            for (pub, val) in pubkeysvalueslist:
                try:
                    Cs.append(convert_to_ark_compressed(
                        pointadd([pointmult(val.to_bytes(
                        32, byteorder="big"), J),
                        hextobin("02"+pub)]))) # 02 is always correct here; bip340 from chain
                except ValueError:
                    print("Invalid hex detected, ignoring")

            f.write(" ".join([bintohex(y) for y in Cs]))


